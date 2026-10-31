import csv,gc,gzip,hashlib,json,re,time
from collections import Counter
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
import pandas as pd

PRIOR=Path('/kaggle/working/CLOSING_E0D_SOURCE_REPRODUCTION_20261015T060927061897Z')
CAP_PER_CLASS=10000
CHUNK_ROWS=50000
HASH_KEY='0123456789abcdef'
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
EXTRA=['id.resp_p','service','conn_state','history']
ALLOWED_SOURCES={f'CTU-IoT-Malware-Capture-{n}-1' for n in [1,3,8]}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(8*1024**2),b''):h.update(block)
    return h.hexdigest()

def small_pointer(path):
    p=Path(path);seen=set()
    for _ in range(5):
        if str(p) in seen:raise ValueError('Pointer cycle')
        seen.add(str(p))
        if not p.is_file():raise FileNotFoundError(p)
        if p.stat().st_size>4096:return p
        raw=p.read_bytes()
        if raw[:2]==b'\x1f\x8b':return p
        try:text=raw.decode('utf-8-sig').strip()
        except UnicodeDecodeError:return p
        if '\n' not in text and '\r' not in text and text.startswith('/kaggle/'):
            if not text.startswith('/kaggle/input/'):
                raise ValueError('Pointer names an old non-input path; explicit relocation required')
            p=Path(text);continue
        return p
    raise ValueError('Pointer depth exceeded')

def open_text(path):
    path=small_pointer(path)
    with path.open('rb') as f:compressed=f.read(2)==b'\x1f\x8b'
    return gzip.open(path,'rt',encoding='utf-8-sig',newline='') if compressed else path.open('r',encoding='utf-8-sig',newline='')

def log_rows(path):
    fields=None
    with open_text(path) as f:
        for number,line in enumerate(f,1):
            if line.startswith('#fields'):
                fields=line.strip().split()[1:]
                if len(fields)!=len(set(fields)):raise ValueError('Duplicate Zeek header fields')
                continue
            if line.startswith('#') or not line.strip():continue
            if fields is None:raise ValueError('Missing Zeek #fields')
            values=line.strip().split()
            if len(values)!=len(fields):raise ValueError(f'Field count mismatch at physical line {number}: {len(values)} vs {len(fields)}')
            row=dict(zip(fields,values));row['_physical_line']=number
            yield row

def key(row):
    micro=int((Decimal(row['ts'])*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
    return json.dumps([micro,row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()],separators=(',',':'))

def label_value(value):
    value=str(value).strip().lower()
    if value=='benign':return 0
    if value=='malicious':return 1
    return None

def equal_core(column,left,right):
    if column=='proto':return str(left).lower()==str(right).lower()
    a=str(left);b=str(right)
    if a=='-' or b=='-':return a==b
    return Decimal(a)==Decimal(b)

def priority(ids):
    return pd.util.hash_pandas_object(pd.Series(ids,dtype='string'),index=False,hash_key=HASH_KEY).to_numpy(dtype=np.uint64)

def take_capped(frame):
    parts=[]
    for value in [0,1]:
        part=frame[frame.y.eq(value)]
        if len(part):parts.append(part.sort_values(['sample_priority','record_id'],kind='stable').head(CAP_PER_CLASS))
    return pd.concat(parts,ignore_index=True) if parts else frame.iloc[:0].copy()

def main():
    started=time.monotonic()
    prior=json.loads((PRIOR/'receipt.json').read_text())
    if prior['status']!='SOURCE_NUMERICAL_REPRODUCTION_PASSED':raise RuntimeError('Source reproduction must pass first')
    recovery=Path(prior['recovery_registry']).parent
    registry=json.loads((recovery/'artifact_registry.json').read_text())
    inventory=Path(registry['inventory_directory'])
    files=pd.read_csv(inventory/'file_inventory.csv',dtype=str,keep_default_na=False)
    metadata=json.loads((PRIOR/'historical_source_train_metadata.json').read_text())
    if not isinstance(metadata,list) or {m['scenario'] for m in metadata}!=ALLOWED_SOURCES:
        raise ValueError('Historical source roster is not exactly 1,3,8')
    out=Path('/kaggle/working')/('CLOSING_E1A_SOURCE_PANEL_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(exist_ok=False)
    assets=[];diagnostics=[];errors=[];outputs=[];content_hash_cache={}
    def resolved_hash(path):
        actual=small_pointer(path)
        if str(actual) not in content_hash_cache:content_hash_cache[str(actual)]=sha(actual)
        return actual,content_hash_cache[str(actual)]
    def locate_recorded(meta):
        old=Path(meta['source_path']);parts=old.parts
        markers=[j for j,p in enumerate(parts) if p.startswith('TRACE_')]
        if not markers:raise ValueError('Cannot form a recorded source suffix')
        suffix='/'.join(parts[markers[0]:])
        direct=files[files.path.str.endswith('/'+suffix)]
        if direct.empty and meta['scenario'].endswith('-8-1'):
            marker=parts[markers[0]]
            direct=files[files.path.str.contains(marker,regex=False)&files.path.map(lambda p:Path(p).name in ['conn.log','clean_replay_conn.log'])]
        candidates=sorted(direct.path.unique(),key=lambda p:('PRIVATE_' in p,len(Path(p).parts),len(p),p))
        attempts=[]
        for text in candidates:
            try:
                actual,digest=resolved_hash(text)
                if digest==meta['source_sha256']:
                    assets.append({'scenario':meta['scenario'],'role':'historical_source','path':str(actual),'sha256':digest,'selection':'RECORDED_SHA256_MATCH'})
                    return actual
                attempts.append('hash mismatch: '+text)
            except Exception as e:attempts.append(str(e))
        raise ValueError('Recorded source not resolved: '+meta['scenario']+'; '+str(attempts[:3]))
    for meta in metadata:
        scenario=meta['scenario']
        print('BUILDING SOURCE PANEL:',scenario,flush=True)
        try:
            source=locate_recorded(meta)
            if meta['source_kind']=='linked_records':
                sample=pd.DataFrame();counts=Counter();total=0
                with open_text(source) as handle:
                    for chunk in pd.read_csv(handle,dtype=str,keep_default_na=False,chunksize=CHUNK_ROWS):
                        required=set(F+['published_label','reference_line','generated_line','source_scenario'])
                        if not required.issubset(chunk.columns):raise ValueError('Linked CSV schema mismatch')
                        if not chunk.source_scenario.eq(scenario).all():raise ValueError('Mixed source scenario')
                        total+=len(chunk)
                        mapped=chunk.published_label.map(label_value)
                        counts.update(mapped.fillna(-1).astype(int).tolist())
                        chunk=chunk.loc[mapped.notna()].copy();chunk['y']=mapped.loc[chunk.index].astype(int)
                        chunk['generated_line']=pd.to_numeric(chunk.generated_line,errors='raise').astype(np.int64)
                        chunk['record_id']=scenario+'|'+meta['source_sha256'][:16]+'|gline:'+chunk.generated_line.astype(str)
                        chunk['sample_priority']=priority(chunk.record_id.tolist())
                        sample=take_capped(pd.concat([sample,chunk],ignore_index=True))
                if total!=int(meta['raw_rows']):raise ValueError('Linked-source row count differs from metadata')
                if counts[-1]:raise ValueError('Unsupported source labels; do not silently relabel')
                if counts[0]!=int(meta['benign_raw']) or counts[1]!=int(meta['malicious_raw']):raise ValueError('Historical source class counts differ')
                if sample.generated_line.duplicated().any():raise ValueError('Duplicate selected generated-line IDs')
                replay=small_pointer(source.parent/'replay'/'conn.log')
                digest=sha(replay)
                assets.append({'scenario':scenario,'role':'generated_source_log','path':str(replay),'sha256':digest,'selection':'Sibling replay; selected rows independently core-checked'})
                requested={int(row['generated_line']):row for row in sample.to_dict('records')}
                reconstructed=[]
                for row in log_rows(replay):
                    number=row['_physical_line']
                    if number not in requested:continue
                    old=requested.pop(number)
                    if any(c not in row for c in F+EXTRA+['ts','id.orig_h','id.orig_p','id.resp_h']):raise ValueError('Expanded fields absent in generated source log')
                    mismatched=[c for c in F if not equal_core(c,old[c],row[c])]
                    if mismatched:raise ValueError(f'Physical-line core mismatch at {number}: {mismatched}')
                    for c in ['conn_state','history']:
                        if c in old and old[c]!=row[c]:raise ValueError('Linked/generated context mismatch: '+c)
                    reconstructed.append({**{c:row[c] for c in F+EXTRA},'ts':row['ts'],
                        'record_id':old['record_id'],'record_key':key(row),'y':int(old['y']),
                        'published_label':old['published_label'],'published_detailed_label':old.get('published_detailed_label',''),
                        'source_scenario':scenario,'reference_line':old['reference_line'],'generated_line':number})
                if requested:raise ValueError(f'{len(requested)} selected physical lines were not recovered')
                frame=pd.DataFrame(reconstructed)
            elif meta['source_kind']=='clean_replay_conn_log_plus_exact_label_mapping':
                candidates=files[files.root_label.eq('IoT_named_corpus_VERIFY_IDENTITY') & files.path.map(lambda p:scenario in Path(p).parts and Path(p).name=='conn.log.labeled')]
                if len(candidates)!=1:raise ValueError('Source-8 published reference must resolve uniquely')
                reference=small_pointer(Path(candidates.iloc[0].path))
                assets.append({'scenario':scenario,'role':'published_source_labels','path':str(reference),'sha256':sha(reference),'selection':'Unique source-8 published reference'})
                lookup={}
                for row in log_rows(reference):
                    k=key(row)
                    if k in lookup:raise ValueError('Ambiguous published source-8 key')
                    if 'label' not in row:raise ValueError('Published label column not parsed')
                    lookup[k]=row
                reconstructed=[];seen=set();counts=Counter();total=0
                for row in log_rows(source):
                    total+=1;k=key(row)
                    if k in seen:raise ValueError('Duplicate generated source-8 key')
                    seen.add(k)
                    if k not in lookup:raise ValueError('Unmatched generated source-8 key')
                    old=lookup[k];label=label_value(old['label'])
                    if label is None:raise ValueError('Unsupported published source-8 label')
                    if any(c not in row for c in F+EXTRA):raise ValueError('Expanded fields missing in source-8 replay')
                    mismatched=[c for c in F if not equal_core(c,old[c],row[c])]
                    if mismatched:raise ValueError('Source-8 reference/replay core mismatch: '+str(mismatched))
                    counts[label]+=1
                    reconstructed.append({**{c:row[c] for c in F+EXTRA},'ts':row['ts'],
                        'record_id':scenario+'|'+meta['source_sha256'][:16]+'|gline:'+str(row['_physical_line']),
                        'record_key':k,'y':label,'published_label':old['label'],
                        'published_detailed_label':old.get('detailed-label',''),'source_scenario':scenario,
                        'reference_line':old['_physical_line'],'generated_line':row['_physical_line']})
                if total!=int(meta['raw_rows']) or counts[0]!=int(meta['benign_raw']) or counts[1]!=int(meta['malicious_raw']):raise ValueError('Source-8 counts differ from historical metadata')
                frame=pd.DataFrame(reconstructed);frame['sample_priority']=priority(frame.record_id.tolist())
                frame=take_capped(frame).drop(columns='sample_priority')
            else:raise ValueError('Unsupported historical source kind')
            if frame.empty or frame.record_key.duplicated().any() or frame.record_id.duplicated().any():raise ValueError('Empty or ambiguous selected source panel')
            for c in F:
                if c=='proto':frame[c]=frame[c].astype(str).str.lower();continue
                values=pd.to_numeric(frame[c].replace('-',np.nan),errors='raise')
                if np.isinf(values.to_numpy(float)).any():raise ValueError('Infinite source predictor')
                frame[c]=values.fillna(0).clip(lower=0)
            frame['id.resp_p']=pd.to_numeric(frame['id.resp_p'],errors='raise').astype(int)
            if not frame['id.resp_p'].between(0,65535).all():raise ValueError('Invalid destination port')
            frame['ts']=pd.to_numeric(frame.ts,errors='raise')
            frame=frame.sort_values(['ts','record_id'],kind='stable').reset_index(drop=True)
            destination=out/(scenario+'_source_panel.parquet')
            frame.to_parquet(destination,index=False)
            info={'scenario':scenario,'status':'SOURCE_PANEL_BUILT','records':len(frame),
                'benign':int(frame.y.eq(0).sum()),'malicious':int(frame.y.eq(1).sum()),
                'path':str(destination),'sha256':sha(destination),
                'scope':'Class-capped source/design panel; NOT natural-prevalence held-out validation',
                'join_validation':'All selected rows exact core comparison; keys unique',
                'historical_reference_training_disjointness_proved':False}
            outputs.append(info);diagnostics.append(info)
            print(json.dumps({k:info[k] for k in ['scenario','status','records','benign','malicious']}),flush=True)
            del frame;gc.collect()
        except Exception as e:
            errors.append({'scenario':scenario,'error':f'{type(e).__name__}: {e}'})
            diagnostics.append({'scenario':scenario,'status':'BLOCKED','records':0,'benign':0,'malicious':0,'path':'','sha256':'','scope':str(e),'join_validation':'NOT_APPROVED','historical_reference_training_disjointness_proved':False})
            print('BLOCKED:',scenario,type(e).__name__,str(e),flush=True)
    pd.DataFrame(diagnostics).to_csv(out/'source_panel_status.csv',index=False)
    pd.DataFrame(assets).to_csv(out/'source_asset_provenance.csv',index=False)
    pd.DataFrame(errors,columns=['scenario','error']).to_csv(out/'errors.csv',index=False)
    contract={'status':'SOURCE_PANEL_READY_FOR_ALLOCATION' if len(outputs)==3 else 'SOURCE_PANEL_INCOMPLETE',
        'sources':sorted(ALLOWED_SOURCES),'panels':outputs,'cap_per_class_per_capture':CAP_PER_CLASS,
        'selection':'Stable hashed record-ID priority within each class; no predictions used',
        'sampling_hash_key':HASH_KEY,'line_numbers':'One-based physical file lines including header lines',
        'historical_labels_preserved':True,'schema_candidates':['existing_core9','core9_plus_port_service_state_history'],
        'expanded_fields':EXTRA,'metadata_not_predictors':['ts','record_id','record_key','source_scenario','reference_line','generated_line','published_label','published_detailed_label'],
        'holdout_records_read':False,'models_trained':False,'source_training_allocations_frozen':False,
        'new_monitor_formula_frozen':False,'expanded_context_efficacy_established':False,
        'limitations':['Only uniquely linked selected source records','Class caps alter class prevalence','No application-functionality validation','Source competence does not guarantee target competence']}
    (out/'source_panel_contract.json').write_text(json.dumps(contract,indent=2))
    receipt={'stage':'E1-A: source data and parser closure','status':contract['status'],
        'output_directory':str(out),'elapsed_seconds':round(time.monotonic()-started,2),
        'source_panels_completed':len(outputs),'source_panels_expected':3,'errors':len(errors),
        'training_performed':False,'predictions_computed':False,'target_records_read':False,
        'pcap_replays':0,'raw_pcaps_read':False,'published_labels_replaced':False,
        'scientific_efficacy_claims_established':False,
        'next_step':'Freeze disjoint source allocations and begin source-only folds E2/E3' if len(outputs)==3 else 'Resolve only the documented source/pointer/parser blockers; do not run training'}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\n=== E1-A RECEIPT ===\n'+json.dumps(receipt,indent=2))
    print('\n=== SOURCE PANEL STATUS ===\n'+pd.DataFrame(diagnostics).to_string(index=False))
    print('\n=== SOURCE ASSETS ===\n'+pd.DataFrame(assets).to_string(index=False))
    print('\n=== ERRORS ===\n'+pd.DataFrame(errors,columns=['scenario','error']).to_string(index=False))
    return str(out)

E1A_OUTPUT_DIRECTORY=main()
