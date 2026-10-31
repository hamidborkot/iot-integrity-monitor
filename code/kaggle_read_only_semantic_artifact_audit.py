# Read-only semantic artifact audit. Paste this entire script into one Kaggle cell.
import ast
import csv
import gzip
import hashlib
import io
import json
import os
import re
import struct
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

DATASETS = {
    'CICIoMT2024':'/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024',
    'CICIoT2023':'/kaggle/input/datasets/himadri07/ciciot2023',
    'IoT23_named_mount':'/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full',
    'TONIoT':'/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network',
    'NFToNIoTv2':'/kaggle/input/datasets/dhoogla/nftoniotv2',
    'CSE':'/kaggle/input/datasets/dhoogla/csecicids2018',
    'NSL':'/kaggle/input/datasets/shamstahzib/nsl-kdd-dataset',
}
NAMES = ['all-kaggle-work','complete-backup','full-backup','last-day-backup',
         'one-last','ran-files','the-last-update','whole-in-one','the-last-days-backup',
         'pcaps-of-ciciot-23-and-24','research-closing-code','research-experiment-suite','githubnids']
ROOTS = {**DATASETS,**{n:'/kaggle/input/datasets/mdhamidborkottulla/'+n for n in NAMES},
         'current_working':'/kaggle/working'}
EXPECTED_CURRENT_CONFIG = '48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea'
DERIVED = ('CLOSING_FINISH_','CLOSING_REUSE_ANALYSIS_','CLOSING_TRACE_PAIR_CLOSURE_',
           'READ_ONLY_EXISTING_EVIDENCE_AUDIT_')
MAX_FILES = 150000
MAX_METADATA_SECONDS = 180
MAX_CONTENT_SECONDS = 180
MAX_ARCHIVES = 32
MAX_TOTAL_ARCHIVE_MEMBERS = 200000
MAX_SMALL_FILE_BYTES = 256*1024
MAX_CONTENT_BYTES = 48*1024**2
MAX_JSON_FILES = 1500
MAX_CSV_HEADERS = 2500
MAX_CODE_FILES = 150
MAX_NPZ_HEADERS = 80
MAX_OUTPUT_BYTES = 6*1024**2
HEADER_LIMIT = 16384

TASK_RULES = {
 'historical_tabular_estimation':r'estimator|estimation|target.matched|full.?4|main.table|paper.table|neural.replay',
 'historical_unique_witness_comparison':r'unique.witness|witness|unique.window',
 'historical_profile_reproduction':r'profile.reproduction|aligned.profile|reference.mixture|profile.check',
 'historical_tabular_attack_validity':r'algebraic|constraint|validity|spsa|adaptive|verified.witness',
 'historical_trace_packet_controls':r'protocol.eligible|packet.(pacing|injection|harness)|compact.injection|pacing.*search|three.treatment',
 'historical_trace_pair_coverage':r'matched.coverage|paired.window|window.gate|full.gate',
 'historical_gate_reversals_oracle_search':r'gate.reversal|acceptance.reversal|gate.aware|oracle.*(delay|search)|selected.delays',
 'historical_MD3_baselines':r'md3|margin.density',
 'historical_host_resource_measurements':r'resource|pipeline.tim|latency|memory.measure|overhead',
 'historical_NF_boundary':r'nf.step|nf.boundary|boundary.result|nf.target|nf.calibrated',
 'exposure_protocol_and_provenance':r'exposure|roster|protocol|provenance|schema|split.manifest|claim.evidence',
 'new_source_panel_and_allocation':r'closing.e1a|source.panel|source.allocation|record.role.manifest|allocation.receipt',
 'new_source_fold_driver_and_results':r'closing.e2e3|closing.source.diagnostic|source.validation.cache|source.feasibility|source.fold',
 'new_source_window_prioritization':r'closing.window.prior|source.window.review|window.prioritization',
 'new_frozen_monitor_and_target_execution':r'closing.e[4567](?:[^0-9]|$)|closing.*held.?out|closing.*target.freeze',
}
TASK_RULES = {k:re.compile(v,re.I) for k,v in TASK_RULES.items()}


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return sha(json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode())
def loc(a): return a['path']+(' :: '+a['member'] if a.get('member') else '')
def tasks(text): return [k for k,p in TASK_RULES.items() if p.search(text)]
def derived(name): return any(part.startswith(DERIVED) for part in Path(name).parts)


def read_bytes(a,limit):
    if a['bytes']>limit: raise ValueError('SIZE_DEFERRED')
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z:
            with z.open(a['member']) as f: raw=f.read(limit+1)
    else:
        with Path(a['path']).open('rb') as f: raw=f.read(limit+1)
    if len(raw)>limit: raise ValueError('SIZE_DEFERRED')
    return raw


def prefix(a,limit=HEADER_LIMIT):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z:
            with z.open(a['member']) as f: raw=f.read(limit)
    else:
        with Path(a['path']).open('rb') as f: raw=f.read(limit)
    return raw


def csv_header(a):
    if a['name'].lower().endswith('.gz'):
        # Archive-contained gzip is explicitly deferred rather than fully read.
        if a.get('member'): raise ValueError('ARCHIVED_GZIP_HEADER_DEFERRED')
        with gzip.open(a['path'],'rb') as f: raw=f.readline(HEADER_LIMIT+1)
    else:
        raw=prefix(a)
        raw=raw.split(b'\n',1)[0]
    if len(raw)>=HEADER_LIMIT: raise ValueError('HEADER_LIMIT')
    text=raw.decode('utf-8-sig').strip()
    if text.startswith('/kaggle/') and '\t' not in text and ',' not in text:
        return [],text
    if text.startswith('#'): raise ValueError('COMMENTED_OR_ZEEK_HEADER_NOT_PARSED')
    delim='\t' if '\t' in text and ',' not in text else ','
    return next(csv.reader([text],delimiter=delim)),''


def schema_kind(cols):
    s=set(cols)
    if {'scenario','seed','window','clean_accuracy','attack_accuracy','clean_estimate','attack_estimate'}.issubset(s):
        return 'TRACE_PAIRED_METRICS'
    if {'dataset','view_seed','attack_seed','window','estimator','estimated_accuracy','true_accuracy'}.issubset(s):
        return 'TABULAR_WINDOW_ESTIMATOR_TRUE_ACCURACY'
    if {'estimator','estimated_accuracy','actual_accuracy','witness_sha256'}.issubset(s):
        return 'TABULAR_WITNESS_ESTIMATOR_ACTUAL_ACCURACY'
    if {'witness_sha256','accepted','accuracy'}.issubset(s): return 'TABULAR_WITNESS_WINDOW_COVERAGE'
    if {'record_id','source_scenario','role'}.issubset(s): return 'SOURCE_RECORD_ROLE_MANIFEST'
    if any(c in s for c in ['ms_per_1000_records','ms_per_1000_rows','median_ms_per_1000']): return 'SAVED_HOST_TIMING'
    if {'clean_acceptance','attack_acceptance'}.issubset(s): return 'SAVED_ACCEPTANCE_REVERSAL'
    if 'unlabeled_first_warning' in s or 'first_warning_row' in s: return 'SAVED_WARNING_RESULTS'
    if 'balanced_accuracy' in s and any(c in s for c in ['held_capture','held_out','heldout']): return 'SOURCE_FOLD_METRICS_CANDIDATE'
    return 'OTHER_SCHEMA_NO_INTERPRETATION'


def selected_fields(obj):
    out=[]
    pattern=re.compile(r'status|scope|version|sha256|hash|completed|confirmation|post.exposure|retrain|targets?.*(read|inspect|predict)|disjoint|eligib|threshold|model.fit|primary.evaluation|allocation.path|source.*path|output.directory|driver.version',re.I)
    def visit(v,path='',depth=0):
        if depth>5 or len(out)>=90:return
        if isinstance(v,dict):
            for k,x in v.items():
                q=path+'.'+str(k) if path else str(k)
                if isinstance(x,dict):visit(x,q,depth+1)
                elif pattern.search(q) and isinstance(x,(str,int,float,bool,type(None))):
                    out.append((q,str(x)[:200]))
    visit(obj)
    return dict(out)


def npz_headers(a):
    if a.get('member'):raise ValueError('NPZ_INSIDE_ARCHIVE_HEADERS_DEFERRED')
    rows=[]
    if zip_budget(Path(a['path']))>8*1024**2:raise ValueError('NPZ_DIRECTORY_LIMIT')
    with zipfile.ZipFile(a['path']) as z:
        infos=z.infolist()
        if len(infos)>256:raise ValueError('NPZ_ARRAY_COUNT_LIMIT')
        for info in infos:
            if not info.filename.endswith('.npy'):continue
            with z.open(info) as f:
                magic=f.read(8)
                if len(magic)!=8 or magic[:6]!=b'\x93NUMPY':raise ValueError('BAD_NPY_HEADER')
                ver=tuple(magic[6:8]); n=2 if ver==(1,0) else 4 if ver in [(2,0),(3,0)] else 0
                if not n:raise ValueError('NPY_VERSION_DEFERRED')
                length=struct.unpack('<H' if n==2 else '<I',f.read(n))[0]
                if length>HEADER_LIMIT:raise ValueError('NPY_HEADER_LIMIT')
                header=ast.literal_eval(f.read(length).decode('utf-8' if ver==(3,0) else 'latin1').strip())
            rows.append({'array':info.filename[:-4],'shape':str(header['shape']),'dtype':str(header['descr'])[:100]})
    return rows


def zip_budget(p):
    size=p.stat().st_size
    with p.open('rb') as f:
        f.seek(max(0,size-65557));tail=f.read(65557)
        pos=tail.rfind(b'PK\x05\x06')
        if pos<0 or pos+22>len(tail):raise ValueError('ZIP_EOCD_UNRESOLVED')
        v=struct.unpack_from('<4s4H2LH',tail,pos)
        if pos+22+v[-1]!=len(tail) or v[1] or v[2]:raise ValueError('ZIP_LAYOUT_DEFERRED')
        central=v[5]
        if central==0xffffffff or v[4]==65535 or v[6]==0xffffffff:
            absolute=max(0,size-65557)+pos
            if absolute<20:raise ValueError('ZIP64_LOCATOR_MISSING')
            f.seek(absolute-20);locator=struct.unpack('<4sLQL',f.read(20))
            if locator[0]!=b'PK\x06\x07' or locator[1]!=0 or locator[3]!=1:raise ValueError('ZIP64_LOCATOR_UNRESOLVED')
            f.seek(locator[2]);rec=struct.unpack('<4sQ2H2L4Q',f.read(56))
            if rec[0]!=b'PK\x06\x06':raise ValueError('ZIP64_EOCD_UNRESOLVED')
            central=rec[-2]
        if central>32*1024**2:raise ValueError('ZIP_CENTRAL_DIRECTORY_LIMIT')
    return central


def scan():
    start=time.monotonic();assets=[];archives=[];roots=[];issues=[]
    seen=0;limited=False
    for name,root in ROOTS.items():
        p=Path(root);group='raw' if name in DATASETS else 'working' if name=='current_working' else 'backup_or_support'
        row={'root':name,'group':group,'path':root,'exists':p.is_dir(),'files_seen':0,'scan_complete':False}
        roots.append(row)
        if not p.is_dir() or limited:continue
        def walk_error(e):issues.append({'stage':'walk','location':str(e.filename),'reason':str(e)})
        for directory,dirs,files in os.walk(p,followlinks=False,onerror=walk_error):
            dirs[:]=sorted(d for d in dirs if d not in ['.git','__pycache__'] and not d.startswith(DERIVED))
            for filename in sorted(files):
                if seen>=MAX_FILES or time.monotonic()-start>MAX_METADATA_SECONDS:limited=True;break
                seen+=1;row['files_seen']+=1;q=Path(directory)/filename
                try:
                    size=q.stat().st_size
                    if derived(str(q)):continue
                    a={'root':name,'group':group,'path':str(q),'member':'','name':filename,'bytes':size}
                    if filename.lower().endswith(('.zip','.tar','.tar.gz','.tgz','.7z')):
                        if group!='raw':archives.append(a)
                    elif group!='raw':assets.append(a)
                    elif filename.lower().endswith(('.pcap','.pcapng','.pcap.gz','conn.log.labeled','.parquet','.csv')):
                        # Raw datasets are inventoried by filenames and size only.
                        assets.append(a)
                except OSError as e:issues.append({'stage':'stat','location':str(q),'reason':str(e)})
            if limited:break
        row['scan_complete']=not limited
    total_members=0;indexed=0
    for a in archives:
        if not a['name'].lower().endswith('.zip'):
            issues.append({'stage':'archive','location':loc(a),'reason':'NON_ZIP_CONTENT_INDEX_DEFERRED_NO_EXTRACTION'});continue
        if indexed>=MAX_ARCHIVES or total_members>=MAX_TOTAL_ARCHIVE_MEMBERS or time.monotonic()-start>MAX_METADATA_SECONDS:
            issues.append({'stage':'archive','location':loc(a),'reason':'ARCHIVE_INDEX_BUDGET'});limited=True;continue
        try:
            zip_budget(Path(a['path']))
            with zipfile.ZipFile(a['path']) as z:
                infos=z.infolist()
                if len(infos)>MAX_TOTAL_ARCHIVE_MEMBERS-total_members:raise ValueError('ZIP_MEMBER_BUDGET')
                total_members+=len(infos);indexed+=1
                for info in infos:
                    if info.is_dir() or derived(info.filename):continue
                    assets.append({'root':a['root'],'group':'archive_member','path':a['path'],'member':info.filename,
                                   'name':Path(info.filename).name,'bytes':info.file_size})
        except Exception as e:issues.append({'stage':'archive','location':loc(a),'reason':str(e)});limited=True
    return assets,roots,issues,{'direct_files_seen':seen,'archive_members_indexed':total_members,
                               'archives_found':len(archives),'ZIP_archives_indexed':indexed,'metadata_budget_limited':limited}


def main():
    started=time.monotonic();work=Path('/kaggle/working')
    if not work.is_dir():raise RuntimeError('Run this self-contained cell in Kaggle.')
    out=work/('READ_ONLY_EXISTING_EVIDENCE_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
    assets,roots,issues,scan_info=scan()
    evidence=[];json_rows=[];schema_rows=[];array_rows=[];code_rows=[];exact=[];pointers=[]
    content_start=time.monotonic();content_bytes=0;limits=Counter();used=Counter()
    def record(a,kind,assigned,detail='',fingerprint='',declared=''):
        for task in sorted(set(assigned)):
            evidence.append({'task':task,'root':a['root'],'location':loc(a),'kind':kind,
                             'bytes':a['bytes'],'fingerprint':fingerprint,'declared_status':declared,'detail':detail[:900]})
    ordered=sorted(assets,key=lambda a:(a['group']=='raw',bool(a['member']),
            not any(t in loc(a).lower() for t in ['closing_e2e3','source_validation','source_diagnostic','configuration','receipt']),loc(a)))
    for a in ordered:
        name=a['name'].lower();assigned=tasks(loc(a))
        if a['group']=='raw':continue
        if assigned:record(a,'PATH_CANDIDATE_ONLY',assigned)
        if time.monotonic()-content_start>MAX_CONTENT_SECONDS or content_bytes>=MAX_CONTENT_BYTES:
            limits['content_time_or_bytes']+=1;continue
        if name.endswith('.ipynb'):
            limits['notebooks_not_loaded']+=1;continue
        if name.endswith('.json') and a['bytes']<=MAX_SMALL_FILE_BYTES:
            if used['json']>=MAX_JSON_FILES:limits['json_count']+=1;continue
            try:
                raw=read_bytes(a,MAX_SMALL_FILE_BYTES);content_bytes+=len(raw);used['json']+=1
                text=raw.decode('utf-8-sig').strip()
                if text.startswith('/kaggle/') and '\n' not in text:
                    pointers.append({'location':loc(a),'pointer':text,'target_currently_exists':Path(text).is_file()});continue
                obj=json.loads(text);fields=selected_fields(obj);h=sha(raw);ch=canonical(obj)
                kind='SMALL_JSON_METADATA'
                if isinstance(obj,dict) and obj.get('driver_version')=='closing-source-fold-driver-v2':
                    assigned.append('new_source_fold_driver_and_results');kind='SOURCE_DRIVER_CONFIG_BY_CONTENT'
                status=str(obj.get('status',''))[:160] if isinstance(obj,dict) else ''
                key_text=' '.join(fields.keys())+' '+' '.join(fields.values())
                assigned+=tasks(key_text)
                json_rows.append({'location':loc(a),'bytes':len(raw),'sha256':h,'canonical_json_sha256':ch,
                    'kind':kind,'declared_status':status,'selected_metadata':json.dumps(fields,sort_keys=True)[:9000]})
                if h==EXPECTED_CURRENT_CONFIG or ch==EXPECTED_CURRENT_CONFIG or kind=='SOURCE_DRIVER_CONFIG_BY_CONTENT':
                    exact.append({'location':loc(a),'raw_sha256':h,'canonical_json_sha256':ch,
                        'exact_recorded_config_match':h==EXPECTED_CURRENT_CONFIG or ch==EXPECTED_CURRENT_CONFIG,
                        'semantic_driver_version_match':kind=='SOURCE_DRIVER_CONFIG_BY_CONTENT',
                        'allocation_path':obj.get('allocation_path','') if isinstance(obj,dict) else '',
                        'allocation_sha256':obj.get('allocation_sha256','') if isinstance(obj,dict) else ''})
                record(a,kind,assigned,json.dumps(fields)[:900],h,status)
            except Exception as e:issues.append({'stage':'json','location':loc(a),'reason':str(e)[:250]})
        elif name.endswith(('.csv','.csv.gz','.tsv')):
            if used['csv']>=MAX_CSV_HEADERS:limits['csv_count']+=1;continue
            try:
                cols,pointer=csv_header(a);used['csv']+=1;content_bytes+=HEADER_LIMIT
                if pointer:
                    pointers.append({'location':loc(a),'pointer':pointer,'target_currently_exists':Path(pointer).is_file()});continue
                sk=schema_kind(cols)
                if sk.startswith('TABULAR_'):assigned.append('historical_tabular_estimation')
                elif sk=='TRACE_PAIRED_METRICS':assigned.append('historical_trace_pair_coverage')
                elif sk=='SAVED_HOST_TIMING':assigned.append('historical_host_resource_measurements')
                elif sk=='SAVED_ACCEPTANCE_REVERSAL':assigned.append('historical_gate_reversals_oracle_search')
                elif sk=='SOURCE_RECORD_ROLE_MANIFEST':assigned.append('new_source_panel_and_allocation')
                elif sk=='SOURCE_FOLD_METRICS_CANDIDATE':assigned.append('new_source_fold_driver_and_results')
                schema_rows.append({'location':loc(a),'name':a['name'],'schema_kind':sk,
                                    'schema_fingerprint':canonical(cols),'columns':json.dumps(cols)[:4000]})
                record(a,'CSV_HEADER_ONLY',assigned,sk+' '+','.join(cols)[:500],canonical(cols))
            except Exception as e:issues.append({'stage':'csv_header','location':loc(a),'reason':str(e)[:250]})
        elif name.endswith('.npz') and any(t in loc(a).lower() for t in ['source','predict','output','cache','validation']):
            if used['npz']>=MAX_NPZ_HEADERS:limits['npz_count']+=1;continue
            try:
                rows=npz_headers(a);used['npz']+=1;content_bytes+=len(rows)*HEADER_LIMIT
                for r in rows:array_rows.append({'location':loc(a),**r})
                names=' '.join(r['array'] for r in rows)
                if '__p_PRIMARY' in names and '__y' in names:assigned.append('new_source_fold_driver_and_results')
                record(a,'NPZ_ARRAY_HEADERS_ONLY',assigned,names[:800],canonical(rows))
            except Exception as e:issues.append({'stage':'npz_header','location':loc(a),'reason':str(e)[:250]})
        elif name.endswith('.py') and a['bytes']<=MAX_SMALL_FILE_BYTES:
            if used['code']>=MAX_CODE_FILES:limits['code_count']+=1;continue
            try:
                raw=read_bytes(a,MAX_SMALL_FILE_BYTES);content_bytes+=len(raw);used['code']+=1
                tree=ast.parse(raw.decode('utf-8-sig'))
                funcs=[n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
                code_rows.append({'location':loc(a),'sha256':sha(raw),'function_names':'|'.join(funcs)[:1200],
                                  'scope':'STATIC_PARSE_ONLY_NOT_EXECUTED'})
                record(a,'STATIC_CODE_ONLY',assigned,'|'.join(funcs)[:600],sha(raw))
            except Exception as e:issues.append({'stage':'static_code','location':loc(a),'reason':str(e)[:250]})
    grouped=defaultdict(list)
    for r in evidence:grouped[r['task']].append(r)
    ledger=[]
    for task in TASK_RULES:
        rows=grouped[task];locations={r['location'] for r in rows}
        receipts=[r for r in rows if r['kind'] in ['SMALL_JSON_METADATA','SOURCE_DRIVER_CONFIG_BY_CONTENT']]
        complete=[r for r in receipts if re.search(r'complete|passed|verified|accepted',r['declared_status'],re.I)
                  and not re.search(r'incomplete|not.complete|failed|pending',r['declared_status'],re.I)]
        negative=[r for r in receipts if re.search(r'failed|infeasible|no.real.packet.damage|no.attackable',r['declared_status'],re.I)]
        state=('NEGATIVE_OUTCOME_DECLARED_VERIFY_SCOPE' if negative else 'EXECUTION_OR_VERIFICATION_DECLARED_VERIFY_SCOPE' if complete
               else 'ARTIFACTS_FOUND_COMPLETION_NOT_INFERRED' if locations else 'NOT_LOCATED_WITHIN_AUDIT_LIMITS')
        ledger.append({'task':task,'status':state,'candidate_locations':len(locations),'small_metadata_records':len(receipts),
            'declared_completion_or_verification_records':len(complete),'declared_negative_records':len(negative),
            'reuse_rule':'Do not rerun solely because renamed or absent from a generic adapter; check exact scientific scope',
            'example_location':sorted(locations)[0] if locations else ''})
    duplicates=defaultdict(list)
    for r in json_rows:duplicates[r['sha256']].append(r['location'])
    duplicate_rows=[{'sha256':h,'copies':len(set(v)),'examples':' | '.join(sorted(set(v))[:3])}
                    for h,v in duplicates.items() if len(set(v))>1]
    written=0;truncated=[]
    def save(name,rows,fields):
        nonlocal written
        p=out/name;kept=0
        with p.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader()
            for row in rows:
                s=io.StringIO();c=csv.DictWriter(s,fieldnames=fields,extrasaction='ignore');c.writerow(row)
                line=s.getvalue();size=len(line.encode())
                if written+size>MAX_OUTPUT_BYTES:truncated.append(name);break
                f.write(line);written+=size;kept+=1
        return kept
    save('task_evidence_ledger.csv',ledger,['task','status','candidate_locations','small_metadata_records','declared_completion_or_verification_records','declared_negative_records','reuse_rule','example_location'])
    save('current_source_configuration_candidates.csv',exact,['location','raw_sha256','canonical_json_sha256','exact_recorded_config_match','semantic_driver_version_match','allocation_path','allocation_sha256'])
    save('roots.csv',roots,['root','group','path','exists','files_seen','scan_complete'])
    save('small_metadata_evidence.csv',json_rows,['location','bytes','sha256','canonical_json_sha256','kind','declared_status','selected_metadata'])
    save('recognized_csv_schemas.csv',schema_rows,['location','name','schema_kind','schema_fingerprint','columns'])
    save('npz_array_headers.csv',array_rows,['location','array','shape','dtype'])
    save('static_code_index.csv',code_rows,['location','sha256','function_names','scope'])
    save('small_json_duplicate_groups.csv',duplicate_rows,['sha256','copies','examples'])
    save('backup_path_pointers.csv',pointers,['location','pointer','target_currently_exists'])
    save('audit_issues.csv',issues,['stage','location','reason'])
    save('artifact_evidence_index.csv',evidence,['task','root','location','kind','bytes','fingerprint','declared_status','detail'])
    receipt={'status':'BOUNDED_READ_ONLY_AUDIT_RECORDED','output_directory':str(out),
        **scan_info,'elapsed_seconds':round(time.monotonic()-started,2),
        'missing_roots':[r['path'] for r in roots if not r['exists']],
        'small_JSON_files_read':used['json'],'CSV_headers_read':used['csv'],'NPZ_headers_read':used['npz'],
        'Python_files_statically_parsed':used['code'],'source_driver_candidates_by_content':len(exact),
        'exact_recorded_source_config_matches':sum(r['exact_recorded_config_match'] for r in exact),
        'read_budget_accounted_bytes':content_bytes,'content_limit_counts':dict(limits),
        'report_files_truncated':sorted(set(truncated)),
        'report_bytes':sum(p.stat().st_size for p in out.iterdir() if p.is_file()),
        'inputs_modified':False,'backups_copied':False,'archives_extracted_to_disk':False,
        'archive_metadata_and_selected_small_members_read':True,
        'nested_archives_recursively_opened':False,'models_loaded':False,'models_trained':False,
        'numeric_prediction_arrays_loaded':False,'new_target_records_or_labels_read':False,
        'raw_PCAPPayloads_read':False,'notebooks_or_notebook_outputs_loaded':False,
        'saved_experiment_metrics_recomputed':False,'scientific_completion_automatically_inferred':False,
        'method_output_checksums_against_receipts_verified':False,
        'filename_absence_treated_as_unperformed_experiment':False,
        'scope':'Evidence existence, renamed-file schemas, small metadata declarations and configuration identities only',
        'limitations':['No blanket study-completion inference from receipt wording.',
                       'Compressed non-ZIP and nested archives are deferred, not declared empty.',
                       'Same CSV schema is not proof of identical results.',
                       'Same logical filename with different JSON hashes is not automatically a scientific conflict.',
                       'Historical post-exposure results cannot automatically satisfy a newer held-out protocol.']}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2))
    print('READ-ONLY AUDIT: no training, replay, metric reanalysis, notebook loading, or backup copying.')
    print('Roots present: %s/%s | Direct files seen: %s | ZIPs indexed: %s' %
          (sum(r['exists'] for r in roots),len(roots),scan_info['direct_files_seen'],scan_info['ZIP_archives_indexed']))
    print('\n=== TASK EVIDENCE SUMMARY ===')
    for r in ledger:print('%-44s %5d  %s' % (r['task'],r['candidate_locations'],r['status']))
    print('\n=== CURRENT SOURCE DRIVER ===')
    print('Exact recorded config matches: %s | Semantic driver candidates: %s' %
          (receipt['exact_recorded_source_config_matches'],sum(r['semantic_driver_version_match'] for r in exact)))
    for r in exact[:3]:print(('EXACT: ' if r['exact_recorded_config_match'] else 'CANDIDATE: ')+r['location'])
    print('\n=== AUDIT LIMITS ===')
    print('Read limits: '+json.dumps({k:v for k,v in limits.items() if k!='notebooks_not_loaded'},sort_keys=True))
    print('Recorded issues: %s | Truncated report files: %s | Reports: %.2f MiB' %
          (len(issues),len(set(truncated)),sum(p.stat().st_size for p in out.iterdir() if p.is_file())/1024**2))
    print('Reports directory: '+str(out))
    print('Detailed paths and scope are saved in CSVs; no full tables or notebook outputs printed.')
    return str(out)

READ_ONLY_AUDIT_DIRECTORY=main()
