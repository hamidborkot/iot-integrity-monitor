import hashlib,json,time
from pathlib import Path
from datetime import datetime,timezone
from itertools import combinations
import numpy as np
import pandas as pd

ROOT=Path('/kaggle/working/CLOSING_E2E3_SOURCE_FOLDS_v1')
EXPECTED_ALLOCATION='11c7e79d283ced769a7be8c13dd9f06952b604c411eb51eff714d9a81c20dd55'
SOURCES=[f'CTU-IoT-Malware-Capture-{n}-1' for n in [1,3,8]]
ROLES=['train','competence_reference','profile_fit','cutoff_calibration','source_validation']
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
EXTRA=['id.resp_p','service','conn_state','history']
CATEGORICAL={'proto','service','conn_state','history'}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(8*1024**2),b''):h.update(block)
    return h.hexdigest()

def group_id(scenario,record_key):
    fields=json.loads(str(record_key))
    if not isinstance(fields,list) or len(fields)!=6:raise ValueError('Unexpected record_key')
    return hashlib.sha256(json.dumps([str(scenario)]+fields[1:],separators=(',',':')).encode()).hexdigest()

def role_for(group):
    b=int(hashlib.sha256(('closing-source-role-v1|'+group).encode()).hexdigest()[:16],16)%100
    return ROLES[0] if b<60 else ROLES[1+(b-60)//10]

def audit(df):
    if len(df)!=44939 or set(df.source_scenario)!=set(SOURCES):raise ValueError('Source membership/count mismatch')
    if df.record_id.duplicated().any() or not df.y.isin([0,1]).all():raise ValueError('Invalid IDs/labels')
    required=set(F+EXTRA+['record_key','allocation_group','role','reference_line','generated_line'])
    if not required.issubset(df.columns):raise ValueError('Allocation lacks required columns')
    expected_groups=[group_id(s,k) for s,k in zip(df.source_scenario,df.record_key)]
    if df.allocation_group.astype(str).tolist()!=expected_groups:raise ValueError('Group policy changed')
    if df.role.astype(str).tolist()!=[role_for(g) for g in expected_groups]:raise ValueError('Role policy changed')
    if set(df.role)!=set(ROLES):raise ValueError('Role set mismatch')
    if df.groupby('allocation_group').role.nunique().gt(1).any():raise ValueError('Group crosses roles')
    return [{'left':a,'right':b,
        'shared_record_ids':len(set(df.loc[df.role.eq(a),'record_id'])&set(df.loc[df.role.eq(b),'record_id'])),
        'shared_five_tuple_groups':len(set(df.loc[df.role.eq(a),'allocation_group'])&set(df.loc[df.role.eq(b),'allocation_group']))}
        for a,b in combinations(ROLES,2)]

def reconstruct(contract):
    if contract.get('status')!='SOURCE_PANEL_READY_FOR_ALLOCATION':raise ValueError('Source panels not accepted')
    items=contract.get('panels',[])
    if len(items)!=3 or [p['scenario'] for p in items]!=SOURCES:
        raise ValueError('Original source-panel order must be 1,3,8')
    frames=[]
    for p in items:
        path=Path(p['path'])
        if not path.is_file() or sha(path)!=p['sha256']:raise ValueError('Panel fingerprint mismatch: '+str(path))
        frames.append(pd.read_parquet(path))
    df=pd.concat(frames,ignore_index=True)
    predictors=F+EXTRA
    for c in predictors:
        if c in CATEGORICAL:df[c]=df[c].astype(str)
        else:
            df[c]=pd.to_numeric(df[c],errors='raise')
            if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise ValueError('Invalid predictor '+c)
    before=pd.util.hash_pandas_object(df[predictors],index=False).to_numpy(np.uint64)
    y=df.y.to_numpy(copy=True);ids=df.record_id.astype(str).tolist()
    for c in ['reference_line','generated_line']:
        vals=df[c].astype('string').str.strip()
        if vals.isna().any() or not vals.str.fullmatch(r'[1-9][0-9]*',na=False).all():raise ValueError('Invalid physical line number: '+c)
        df[c]=np.asarray([int(v) for v in vals],dtype=np.int64)
    for c in ['record_id','record_key','source_scenario','published_label','published_detailed_label']:
        if c in df:
            if df[c].isna().any():raise ValueError('Missing metadata '+c)
            df[c]=df[c].astype('string')
    df['allocation_group']=[group_id(s,k) for s,k in zip(df.source_scenario,df.record_key)]
    role_map={g:role_for(g) for g in df.allocation_group.unique()}
    df['role']=df.allocation_group.map(role_map)
    if not np.array_equal(before,pd.util.hash_pandas_object(df[predictors],index=False).to_numpy(np.uint64)):
        raise ValueError('Reconstruction changed predictor values')
    if not np.array_equal(y,df.y.to_numpy()) or ids!=df.record_id.astype(str).tolist():raise ValueError('Reconstruction changed labels/order')
    audit(df)
    return df

def main():
    start=time.monotonic();ROOT.mkdir(parents=True,exist_ok=True)
    path=ROOT/'source_allocations.parquet'
    errors=[];contract_used=None;mode=None
    if path.exists():
        if sha(path)!=EXPECTED_ALLOCATION:
            raise RuntimeError('Existing allocation has a different hash. It is preserved; do not overwrite.')
        df=pd.read_parquet(path);mode='EXISTING_ACCEPTED_BYTES_REUSED'
    else:
        contracts=sorted(Path('/kaggle/working').glob('CLOSING_E1A_SOURCE_PANEL_*/source_panel_contract.json'))
        if not contracts:raise FileNotFoundError('No E1-A source-panel contract. Do not rerun E0; supply the current E1-A output location.')
        df=None
        for p in contracts:
            try:
                candidate=reconstruct(json.loads(p.read_text()))
                temporary=ROOT/('reconstruction_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.parquet')
                candidate.to_parquet(temporary,index=False)
                observed=sha(temporary)
                if observed!=EXPECTED_ALLOCATION:
                    errors.append({'contract':str(p),'error':'Byte hash differs; preserved candidate at '+str(temporary),'observed_sha256':observed})
                    continue
                temporary.replace(path);df=candidate;contract_used=str(p);mode='HISTORICAL_ALLOCATION_RECONSTRUCTED_BYTE_IDENTICALLY';break
            except Exception as e:errors.append({'contract':str(p),'error':f'{type(e).__name__}: {e}'})
        if df is None:
            failure={'status':'EXACT_ALLOCATION_RECOVERY_BLOCKED','expected_sha256':EXPECTED_ALLOCATION,'attempts':errors,
                     'training_authorized':False,'reason':'No hash bypass or invented original configuration is permitted'}
            (ROOT/'allocation_recovery_failure.json').write_text(json.dumps(failure,indent=2))
            print(json.dumps(failure,indent=2));raise RuntimeError('Allocation not byte-identically recovered; return this report')
    overlaps=audit(df)
    if any(r['shared_record_ids'] or r['shared_five_tuple_groups'] for r in overlaps):raise ValueError('Role overlap')
    actual=sha(path)
    if actual!=EXPECTED_ALLOCATION:raise ValueError('Final allocation checksum mismatch')
    counts=df.groupby(['source_scenario','role','y']).size().rename('records').reset_index()
    counts.to_csv(ROOT/'allocation_counts_recovery_verified.csv',index=False)
    pd.DataFrame(overlaps).to_csv(ROOT/'allocation_overlap_recovery_verified.csv',index=False)
    receipt={'status':'HISTORICAL_ALLOCATION_RECOVERY_VERIFIED','mode':mode,'allocation_path':str(path),
        'allocation_sha256':actual,'expected_allocation_sha256':EXPECTED_ALLOCATION,'records':len(df),
        'panel_contract_used':contract_used,'elapsed_seconds':round(time.monotonic()-start,2),
        'original_configuration_9974_recovered':False,'original_configuration_not_fabricated':True,
        'record_and_group_roles_recomputed_and_matched':True,'metadata_line_types':[str(df[c].dtype) for c in ['reference_line','generated_line']],
        'models_trained':False,'predictions_computed':False,'target_records_read':False,
        'historical_source_feasibility_outcome':'FAILED; recovery does not change that result',
        'next_step':'Run replacement Code 6 to recover the exact v2 driver configuration'}
    (ROOT/'allocation_recovery_verified.json').write_text(json.dumps(receipt,indent=2))
    print('\n=== REPLACEMENT CODE 5 RECEIPT ===\n'+json.dumps(receipt,indent=2))
    print('\n=== ALLOCATION COUNTS ===\n'+counts.to_string(index=False))
    print('\n=== OVERLAP CHECK ===\n'+pd.DataFrame(overlaps).to_string(index=False))
    return str(ROOT)

RECOVERED_SOURCE_ALLOCATION=main()
