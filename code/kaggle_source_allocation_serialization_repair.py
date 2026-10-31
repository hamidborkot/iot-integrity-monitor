import hashlib,json,time
from collections import Counter
from datetime import datetime,timezone
from itertools import combinations
from pathlib import Path
import numpy as np
import pandas as pd
import pyarrow as pa

PANELS=Path('/kaggle/working/CLOSING_E1A_SOURCE_PANEL_20261015T061834828709Z')
OUT=Path('/kaggle/working/CLOSING_E2E3_SOURCE_FOLDS_v1')
ROLES=['train','competence_reference','profile_fit','cutoff_calibration','source_validation']
CATEGORICAL={'proto','service','conn_state','history'}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
    return h.hexdigest()

def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def group_id(scenario,record_key):
    fields=json.loads(record_key)
    if len(fields)!=6:raise ValueError('Unexpected recorded flow-key schema')
    return hashlib.sha256(json.dumps([scenario]+fields[1:],separators=(',',':')).encode()).hexdigest()

def allocation(group):
    bucket=int(hashlib.sha256(('closing-source-role-v1|'+group).encode()).hexdigest()[:16],16)%100
    return ROLES[0] if bucket<60 else ROLES[1+(bucket-60)//10]

def main():
    start=time.monotonic()
    config_path=OUT/'configuration.json'
    if not config_path.is_file():raise FileNotFoundError('The failed source-fold run must have saved configuration.json; no guessed configuration is created')
    frozen=json.loads(config_path.read_text());settings=frozen['settings'];ch=frozen['configuration_sha256']
    if canonical_hash(settings)!=ch:raise ValueError('Existing configuration checksum mismatch')
    if settings.get('grouping')!='Source capture plus directed five-tuple, excluding timestamp':raise ValueError('Unexpected grouping definition')
    if settings.get('role_salt')!='closing-source-role-v1' or settings.get('role_buckets')!=dict(zip(ROLES,[60,10,10,10,10])):raise ValueError('Unexpected role policy; refuse silent changes')
    data_path=OUT/'source_allocations.parquet';receipt_path=OUT/'allocation_receipt.json'
    if receipt_path.exists():
        accepted=json.loads(receipt_path.read_text())
        if accepted['configuration_sha256']!=ch or not data_path.is_file() or sha(data_path)!=accepted['allocations_sha256']:raise ValueError('Existing accepted allocation is inconsistent; do not overwrite')
        print('ALLOCATION ALREADY ACCEPTED. Nothing changed.')
        print(json.dumps(accepted,indent=2));return str(OUT)
    if any((OUT/'jobs').glob('*/completion.json')) or any((OUT/'jobs').glob('*/*_model_receipt.json')):
        raise RuntimeError('Model/completion receipts exist without an accepted allocation; inspect before repairing')
    contract=json.loads((PANELS/'source_panel_contract.json').read_text())
    if contract['status']!='SOURCE_PANEL_READY_FOR_ALLOCATION':raise ValueError('E1-A panels must be accepted')
    panel_by_scenario={p['scenario']:p for p in contract['panels']}
    frames=[];type_rows=[]
    for p in settings['panel_fingerprints']:
        accepted=panel_by_scenario.get(p['scenario'])
        if accepted is None or accepted['path']!=p['path'] or accepted['sha256']!=p['sha256'] or sha(p['path'])!=p['sha256']:
            raise ValueError('Panel fingerprint/contract mismatch: '+p['scenario'])
        frame=pd.read_parquet(p['path'])
        for column in ['reference_line','generated_line']:
            type_rows.append({'scenario':p['scenario'],'column':column,'dtype_before_concat':str(frame[column].dtype),
                              'python_types':json.dumps(dict(Counter(type(v).__name__ for v in frame[column])))})
        frames.append(frame)
    df=pd.concat(frames,ignore_index=True)
    if set(df.source_scenario)!=set(settings['sources']) or df.record_id.duplicated().any():raise ValueError('Source roster/IDs invalid')
    if not df.y.isin([0,1]).all():raise ValueError('Binary labels required')
    predictors=list(dict.fromkeys(c for cols in settings['schemas'].values() for c in cols))
    for c in predictors:
        if c in CATEGORICAL:df[c]=df[c].astype(str)
        else:
            df[c]=pd.to_numeric(df[c],errors='raise')
            if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise ValueError('Invalid numeric predictor: '+c)
    predictor_before=pd.util.hash_pandas_object(df[predictors],index=False).to_numpy(np.uint64)
    label_before=df.y.to_numpy(copy=True);ids_before=df.record_id.astype(str).to_numpy(copy=True)
    fixes=[]
    for column in ['reference_line','generated_line']:
        text=df[column].astype('string').str.strip()
        if text.isna().any() or not text.str.fullmatch(r'[1-9][0-9]*',na=False).all():
            raise ValueError('Non-positive/non-integer lineage metadata: '+column+'; no truncation or guessing permitted')
        numeric=np.asarray([int(v) for v in text],dtype=np.int64)
        fixes.append({'column':column,'dtype_before':str(df[column].dtype),'dtype_after':'int64','rows':len(df)})
        df[column]=numeric
    for column in ['record_id','record_key','source_scenario','published_label','published_detailed_label']:
        if column in df:
            if df[column].isna().any():raise ValueError('Unexpected missing string metadata: '+column)
            df[column]=df[column].astype('string')
    df['allocation_group']=[group_id(s,k) for s,k in zip(df.source_scenario,df.record_key)]
    role_map={g:allocation(g) for g in df.allocation_group.unique()}
    df['role']=df.allocation_group.map(role_map)
    if df.groupby('allocation_group').role.nunique().max()!=1:raise ValueError('Group split across allocations')
    predictor_after=pd.util.hash_pandas_object(df[predictors],index=False).to_numpy(np.uint64)
    if not np.array_equal(predictor_before,predictor_after) or not np.array_equal(label_before,df.y.to_numpy()) or not np.array_equal(ids_before,df.record_id.astype(str).to_numpy()):
        raise ValueError('Repair changed predictors, labels or record order')
    audit=[]
    for left,right in combinations(ROLES,2):
        a=df.role.eq(left).to_numpy();b=df.role.eq(right).to_numpy()
        audit.append({'left':left,'right':right,
            'shared_record_ids':len(set(df.loc[a,'record_id'])&set(df.loc[b,'record_id'])),
            'shared_five_tuple_groups':len(set(df.loc[a,'allocation_group'])&set(df.loc[b,'allocation_group'])),
            'shared_feature_patterns_diagnostic':len(set(predictor_after[a])&set(predictor_after[b]))})
    if any(r['shared_record_ids'] or r['shared_five_tuple_groups'] for r in audit):raise ValueError('Allocation overlap detected')
    pa.Table.from_pandas(df,preserve_index=False,safe=True)
    run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    temporary=OUT/('source_allocations.typed_'+run_id+'.partial.parquet')
    df.to_parquet(temporary,index=False)
    reread=pd.read_parquet(temporary)
    if len(reread)!=len(df) or not np.array_equal(pd.util.hash_pandas_object(reread[predictors],index=False).to_numpy(np.uint64),predictor_before):
        raise ValueError('Parquet round-trip changed predictor data')
    for c in ['record_id','role','allocation_group']:
        if reread[c].astype(str).tolist()!=df[c].astype(str).tolist():raise ValueError('Round-trip identity/role mismatch: '+c)
    if not np.array_equal(reread.y.to_numpy(),label_before):raise ValueError('Round-trip label mismatch')
    for c in ['reference_line','generated_line']:
        if not np.array_equal(reread[c].to_numpy(),df[c].to_numpy()):raise ValueError('Round-trip lineage mismatch')
    preserved_partial=None
    if data_path.exists():
        preserved_partial=OUT/('source_allocations.UNACCEPTED_'+run_id+'.parquet')
        data_path.replace(preserved_partial)
    temporary.replace(data_path)
    df.groupby(['source_scenario','role','y']).size().rename('records').reset_index().to_csv(OUT/'allocation_counts.csv',index=False)
    df[['record_id','source_scenario','allocation_group','role']].to_csv(OUT/'record_role_manifest.csv',index=False)
    pd.DataFrame(audit).to_csv(OUT/'allocation_overlap_audit.csv',index=False)
    pd.DataFrame(type_rows).to_csv(OUT/'metadata_type_diagnosis.csv',index=False)
    pd.DataFrame(fixes).to_csv(OUT/'metadata_serialization_fixes.csv',index=False)
    accepted={'configuration_sha256':ch,'allocations_sha256':sha(data_path),
        'record_disjointness_verified':True,'directed_five_tuple_groups_disjoint':True,
        'feature_patterns_may_repeat':True,'physical_device_independence_certified':False,
        'historical_model_training_disjointness_proved':False,'new_target_records_read':False,
        'metadata_line_columns_explicit_int64':True,'predictors_labels_order_unchanged':True,
        'parquet_roundtrip_verified':True}
    receipt_temp=OUT/('allocation_receipt.'+run_id+'.tmp')
    receipt_temp.write_text(json.dumps(accepted,indent=2));receipt_temp.replace(receipt_path)
    repair={'status':'ALLOCATION_SERIALIZATION_REPAIRED','output_directory':str(OUT),'records':len(df),
        'elapsed_seconds':round(time.monotonic()-start,2),'configuration_unchanged':True,
        'predictors_labels_and_record_order_unchanged':True,'roles_use_original_hash_policy':True,
        'old_unaccepted_file_preserved_as':str(preserved_partial) if preserved_partial else None,
        'models_trained':False,'predictions_computed':False,'target_records_read':False,'files_deleted':False,
        'next_step':'Rerun ONLY the self-contained E2/E3 source-fold cell unchanged; accepted allocation will be reused'}
    (OUT/('serialization_repair_receipt_'+run_id+'.json')).write_text(json.dumps(repair,indent=2))
    print('\n=== METADATA TYPE DIAGNOSIS ===\n'+pd.DataFrame(type_rows).to_string(index=False))
    print('\n=== SERIALIZATION REPAIR RECEIPT ===\n'+json.dumps(repair,indent=2))
    print('\n=== ALLOCATION RECEIPT ===\n'+json.dumps(accepted,indent=2))
    print('\n=== ALLOCATION COUNTS ===\n'+pd.read_csv(OUT/'allocation_counts.csv').to_string(index=False))
    print('\n=== OVERLAP AUDIT ===\n'+pd.DataFrame(audit).to_string(index=False))
    return str(OUT)

REPAIRED_ALLOCATION_DIRECTORY=main()
