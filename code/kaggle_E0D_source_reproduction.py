import csv, gc, gzip, hashlib, json, re, time
from pathlib import Path
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_auc_score
from threadpoolctl import threadpool_limits

RECOVERY = Path('/kaggle/working/CLOSING_E0B_C_20261015T060201309368Z')
F = ['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts',
     'orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
V = {'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],
     'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],
     'V_time_proto':['duration','proto']}
SEEDS = [8101,8102,8103]
ATOL = 1e-12
MAX_HEADER_BYTES = 65536


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(4*1024**2),b''): h.update(block)
    return h.hexdigest()


def save(rows, path, columns):
    pd.DataFrame(rows,columns=columns).to_csv(path,index=False)


def matrix(frame, columns):
    pieces = []
    numeric = [c for c in columns if c != 'proto']
    if numeric: pieces.append(np.log1p(frame[numeric].to_numpy(dtype=float)))
    if 'proto' in columns:
        pieces.append(np.column_stack([frame.proto.eq(p).to_numpy(dtype=float)
                                      for p in ['tcp','udp','icmp']]))
    values = np.hstack(pieces)
    if not np.isfinite(values).all(): raise ValueError('Nonfinite transformed input')
    return values


def metrics(y, decision, probability):
    tn,fp,fn,tp = confusion_matrix(y,decision,labels=[0,1]).ravel()
    recall = tp/(tp+fn) if tp+fn else None
    fpr = fp/(fp+tn) if fp+tn else None
    return {'rows':len(y),'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp),
            'accuracy':float(np.mean(y==decision)),
            'balanced_accuracy':(recall+1-fpr)/2 if recall is not None and fpr is not None else None,
            'malicious_recall':recall,'benign_FPR':fpr,
            'AUROC':float(roc_auc_score(y,probability)) if len(np.unique(y))==2 else None}


def header_only(path):
    with path.open('rb') as f: compressed = f.read(2)==b'\x1f\x8b'
    opener = gzip.open if compressed else open
    with opener(path,'rt',encoding='utf-8-sig',errors='strict',newline='') as f:
        first = f.readline(MAX_HEADER_BYTES+1)
        if len(first)>MAX_HEADER_BYTES: raise ValueError('Header read limit')
        if not first.startswith('#'):
            if not path.name.lower().endswith(('.csv','.csv.gz')):
                raise ValueError('Non-CSV file without a recognized Zeek header')
            return next(csv.reader([first]))
        separator='\t'; consumed=len(first)
        line=first
        while consumed<=MAX_HEADER_BYTES:
            if line.startswith('#separator '):
                separator=bytes(line.split(' ',1)[1].strip(),'utf-8').decode('unicode_escape')
            if line.startswith('#fields'):
                return line.rstrip('\r\n').split(separator)[1:]
            if not line or not line.startswith('#'): break
            line=f.readline(MAX_HEADER_BYTES-consumed+1);consumed+=len(line)
    raise ValueError('Zeek #fields not found within header limit')


def main():
    start=time.monotonic()
    registry=json.loads((RECOVERY/'artifact_registry.json').read_text())
    fingerprints=pd.read_csv(RECOVERY/'fingerprints.csv',dtype=str,keep_default_na=False)
    inventory=Path(registry['inventory_directory'])
    files=pd.read_csv(inventory/'file_inventory.csv',dtype=str,keep_default_na=False)
    paths=registry['resolved_paths']
    needed=['trace_source_model','source_reference','source_predictions','source_calibration_contract']
    if any(k not in paths for k in needed): raise RuntimeError('Recovery registry lacks required source roles')
    out=Path('/kaggle/working')/('CLOSING_E0D_SOURCE_REPRODUCTION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(exist_ok=False)
    checks=[];metric_rows=[];normalization=[];headers=[];errors=[];composition=[]
    metadata=[];all_match=False;new_outputs={}
    def check(name, passed, detail=''):
        checks.append({'check':name,'passed':bool(passed),'detail':str(detail)})
        if not passed: raise ValueError(name+': '+str(detail))
    try:
        for role in needed:
            p=Path(paths[role]); rows=fingerprints[(fingerprints.path==str(p)) & fingerprints.status.eq('HASHED')]
            expected=set(rows.sha256)
            check('fingerprint_'+role,len(expected)==1 and sha(p) in expected)
        check('historical_model_identity',sha(Path(paths['trace_source_model']))==registry['trace_model_expected_sha256'])
        contract=json.loads(Path(paths['source_calibration_contract']).read_text())
        check('feature_contract',contract.get('features')==F)
        check('view_contract',contract.get('views')==V)
        raw=pd.read_csv(paths['source_reference'],dtype={'ks':str,'source_scenario':str},keep_default_na=False)
        check('reference_columns',set(F+['ks','y','source_scenario']).issubset(raw.columns))
        check('reference_length',len(raw)==int(contract['reference_rows']))
        check('source_captures_only',set(raw.source_scenario)=={f'CTU-IoT-Malware-Capture-{n}-1' for n in [1,3,8]})
        yraw=pd.to_numeric(raw.y,errors='raise')
        check('binary_labels',yraw.isin([0,1]).all())
        y=yraw.to_numpy(dtype=int)
        check('reference_keys_unique',not raw.duplicated(['source_scenario','ks']).any())
        frame=raw[F].copy();frame['proto']=frame.proto.astype(str).str.lower()
        check('known_reference_protocols',frame.proto.isin(['tcp','udp','icmp']).all(),sorted(frame.proto.unique()))
        for c in F:
            if c=='proto': continue
            values=pd.to_numeric(frame[c].replace('-',np.nan),errors='coerce')
            normalization.append({'feature':c,'missing_or_coerced':int(values.isna().sum()),
                                  'negative_clipped':int(values.lt(0).sum()),
                                  'infinite':int(np.isinf(values.to_numpy(float)).sum())})
            frame[c]=values.fillna(0).clip(lower=0)
        for (scenario,label),group in raw.assign(y=y).groupby(['source_scenario','y']):
            composition.append({'scenario':scenario,'label':int(label),'rows':len(group)})
        bundle=joblib.load(paths['trace_source_model'])
        check('bundle_model_bank',isinstance(bundle,dict) and isinstance(bundle.get('models'),dict))
        check('model_seeds',set(map(int,bundle['models']))==set(SEEDS))
        metadata=bundle.get('source_train_metadata',[])
        (out/'historical_source_train_metadata.json').write_text(json.dumps(metadata,indent=2,default=str))
        (out/'historical_feature_schema.json').write_text(json.dumps(bundle.get('feature_schema'),indent=2,default=str))
        with np.load(paths['source_predictions'],allow_pickle=False) as saved, threadpool_limits(limits=2):
            check('saved_labels_match',np.array_equal(saved['labels'],y))
            for seed in SEEDS:
                bank=bundle['models'].get(seed,bundle['models'].get(str(seed)))
                check(f'seed_{seed}_bank',isinstance(bank,dict) and set(['PRIMARY']+list(V)).issubset(bank))
                primary=None;votes=[]
                for name,columns in [('PRIMARY',F)]+list(V.items()):
                    model=bank[name];X=matrix(frame,columns)
                    check(f'{seed}_{name}_dimension',X.shape[1]==model.n_features_in_)
                    check(f'{seed}_{name}_classes',np.array_equal(model.classes_,[0,1]))
                    probability=np.asarray(model.predict_proba(X)[:,1],dtype=float)
                    check(f'{seed}_{name}_probabilities',probability.shape==(len(frame),) and np.isfinite(probability).all()
                          and ((probability>=0)&(probability<=1)).all())
                    decision=(probability>=.5).astype(int) if name=='PRIMARY' else np.asarray(model.predict(X),dtype=int)
                    metric_rows.append({'seed':seed,'model':name,**metrics(y,decision,probability)})
                    if name=='PRIMARY': primary=probability
                    else: votes.append(decision)
                votes=np.vstack(votes)
                original=np.asarray(saved[f'seed_{seed}_primary_probability'],dtype=float)
                check(f'{seed}_saved_primary_shape',original.shape==primary.shape)
                maximum=float(np.max(np.abs(original-primary)))
                mismatches=int(np.sum((original>=.5)!=(primary>=.5)))
                check(f'{seed}_primary_reproduced',np.allclose(original,primary,atol=ATOL,rtol=0),f'max_abs_diff={maximum};decision_mismatches={mismatches}')
                old_votes=np.asarray(saved[f'seed_{seed}_view_prediction'])
                check(f'{seed}_saved_views_shape',old_votes.shape==votes.shape)
                check(f'{seed}_views_reproduced',np.array_equal(old_votes,votes),f'changed_entries={np.sum(old_votes!=votes)}')
                new_outputs[f'seed_{seed}_primary_probability']=primary
                new_outputs[f'seed_{seed}_view_prediction']=votes
                print(f'SOURCE REPRODUCTION seed {seed}: matched',flush=True)
            check('saved_source_scenario_not_unpickled',True,'Object array deliberately not loaded; numerical alignment verified, saved record-ID provenance not proved')
        np.savez_compressed(out/'reproduced_source_outputs.npz',labels=y,
                            source_scenario=raw.source_scenario.to_numpy(dtype=str),ks=raw.ks.to_numpy(dtype=str),**new_outputs)
        all_match=True
        del bundle;gc.collect()
    except Exception as e:
        errors.append({'stage':'source_reproduction','path':str(RECOVERY),'error':f'{type(e).__name__}: {e}'})
    for scenario in [f'CTU-IoT-Malware-Capture-{n}-1' for n in [1,3,8]]:
        subset=files[files.path.map(lambda p:scenario in Path(p).parts)]
        allowed=subset[subset.path.map(lambda p: Path(p).name in ['linked_records.csv','linked_records.csv.gz','conn.log','conn.log.gz','conn.log.labeled','conn.log.labeled.gz'])]
        ordered=sorted(allowed.path.unique(),key=lambda p:('PRIVATE_' in p,len(Path(p).parts),len(p),p))
        seen=set();count=0
        for text in ordered:
            path=Path(text)
            try:
                columns=header_only(path)
                signature=(path.name,tuple(columns))
                if signature in seen: continue
                seen.add(signature);count+=1
                context=['ts','id.resp_p','service','conn_state','history']
                headers.append({'scenario':scenario,'path':text,'columns':json.dumps(columns),
                    'available_context':','.join(c for c in context if c in columns),
                    'scope':'SOURCE HEADER ONLY; no fidelity, label mapping, or allocation approval'})
                if count>=3: break
            except Exception as e:
                errors.append({'stage':'source_header','path':text,'error':f'{type(e).__name__}: {e}'})
        if not count: headers.append({'scenario':scenario,'path':'','columns':'[]','available_context':'','scope':'NO_USABLE_SOURCE_HEADER_FOUND'})
    exact_full4=files[files.path.map(lambda p:bool(re.fullmatch(r'results_(main|blind)_full4_seed\d+\.csv(?:\.gz)?',Path(p).name,re.I)))]
    exact_full4.to_csv(out/'exact_full4_result_locations.csv',index=False)
    save(checks,out/'reproduction_checks.csv',['check','passed','detail'])
    save(metric_rows,out/'historical_reference_metrics.csv',['seed','model','rows','TN','FP','FN','TP','accuracy','balanced_accuracy','malicious_recall','benign_FPR','AUROC'])
    save(normalization,out/'normalization_audit.csv',['feature','missing_or_coerced','negative_clipped','infinite'])
    save(composition,out/'source_reference_composition.csv',['scenario','label','rows'])
    save(headers,out/'source_header_availability.csv',['scenario','path','columns','available_context','scope'])
    save(errors,out/'errors.csv',['stage','path','error'])
    receipt={'stage':'E0-D / source-reproduction component of E1',
        'status':'SOURCE_NUMERICAL_REPRODUCTION_PASSED' if all_match else 'SOURCE_NUMERICAL_REPRODUCTION_FAILED',
        'output_directory':str(out),'recovery_registry':str(RECOVERY/'artifact_registry.json'),
        'elapsed_seconds':round(time.monotonic()-start,2),'checks_recorded':len(checks),
        'failed_checks':sum(not r['passed'] for r in checks),'explicit_errors':len(errors),
        'all_three_primary_probabilities_reproduced':all_match,'all_three_view_matrices_reproduced':all_match,
        'prediction_tolerance':{'atol':ATOL,'rtol':0},'saved_object_arrays_unpickled':False,
        'source_reference_metrics_are_independent_test_metrics':False,
        'reference_training_disjointness_verified':False,'expanded_schema_approved':False,
        'heldout_targets_selected':False,'target_outcomes_inspected':False,
        'exact_full4_result_files_found':len(exact_full4),'models_retrained':False,
        'pcaps_replayed':0,'new_target_records_read':False,'source_headers_inspected':True,
        'inputs_modified':False,'scientific_efficacy_claims_established':False,
        'next_step':'Review source headers, training metadata and exposure contract; source-only feasibility comes next' if all_match
        else 'Diagnose source reproduction mismatch; do not recalibrate or train to hide it'}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\n=== E0-D RECEIPT ===\n'+json.dumps(receipt,indent=2))
    print('\n=== REPRODUCTION CHECKS ===\n'+pd.DataFrame(checks).to_string(index=False))
    print('\n=== HISTORICAL SOURCE-REFERENCE METRICS (not independent validation) ===\n'+pd.DataFrame(metric_rows).round(6).to_string(index=False))
    print('\n=== SOURCE REFERENCE COMPOSITION ===\n'+pd.DataFrame(composition).to_string(index=False))
    print('\n=== NORMALIZATION AUDIT ===\n'+pd.DataFrame(normalization).to_string(index=False))
    print('\n=== SOURCE TRAIN METADATA ===\n'+json.dumps(metadata,indent=2,default=str))
    print('\n=== SOURCE HEADER AVAILABILITY ===')
    for row in headers: print(json.dumps(row))
    print('\n=== EXACT FULL4 RESULT LOCATIONS ===')
    print(exact_full4[['root_label','path','bytes']].head(8).to_string(index=False) if len(exact_full4) else 'No exact filenames found; summaries are not a substitute for raw rows')
    print('\n=== ERRORS ===')
    for e in errors: print(json.dumps(e))
    if not errors: print('None recorded')
    return str(out)

E0D_OUTPUT_DIRECTORY=main()
