import json,hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

ROOT=Path('/kaggle/working/CLOSING_E2E3_SOURCE_FOLDS_v1')
EXPECTED_DRIVER='48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea'
recovery_candidates=[]
for candidate in Path('/kaggle/working').glob('CLOSING_E0B_C_*/artifact_registry.json'):
    try:
        r=json.loads(candidate.read_text())
        p=Path(r['resolved_paths']['trace_source_model'])
        if p.is_file() and r.get('trace_model_expected_sha256')=='b340bb3289e95996007f4b7b31d6d379cfa79e03ece7f09860f82680c80a7774':
            recovery_candidates.append(candidate.parent)
    except (KeyError,ValueError,TypeError):
        continue
if not recovery_candidates:raise RuntimeError('No current recovery registry resolves the documented source-model identity')
RECOVERY=sorted(recovery_candidates,key=str)[-1]
EXPECTED_ALLOCATION='11c7e79d283ced769a7be8c13dd9f06952b604c411eb51eff714d9a81c20dd55'
OLD_CONFIG='9974c0f34eb1fefe344720f0ffb385a95d14d2a351e7b825f7df20ce9b2939d5'
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
EXTRA=['id.resp_p','service','conn_state','history']
SOURCES=[f'CTU-IoT-Malware-Capture-{n}-1' for n in [1,3,8]]
SEEDS=[8101,8102,8103]

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()

def canonical(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()
def json_ready(obj):
 if isinstance(obj,np.generic):return obj.item()
 if isinstance(obj,np.ndarray):return obj.tolist()
 if isinstance(obj,dict):return {str(k):json_ready(v) for k,v in obj.items()}
 if isinstance(obj,(list,tuple)):return [json_ready(v) for v in obj]
 return obj

if not ROOT.is_dir():raise FileNotFoundError(ROOT)
matches=[]
for p in sorted(ROOT.rglob('*.parquet')):
 if p.stat().st_size<=256*1024**2 and sha(p)==EXPECTED_ALLOCATION:matches.append(p)
if len(matches)!=1:raise RuntimeError(f'Expected one accepted allocation file with recorded hash; found {len(matches)}. No training performed.')
allocation=matches[0]
df=pd.read_parquet(allocation)
role_candidates=[c for c in ['role','allocation_role','allocation'] if c in df.columns]
if len(role_candidates)!=1:raise ValueError(f'Role column unresolved: {list(df.columns)}')
role_col=role_candidates[0]
required=set(F+EXTRA+['source_scenario','y','record_id','record_key',role_col])
if not required.issubset(df.columns):raise ValueError(f'Missing columns: {sorted(required-set(df.columns))}')
if len(df)!=44939 or df.record_id.duplicated().any():raise ValueError('Allocation size/record identity mismatch')
if set(df.source_scenario)!=set(SOURCES) or not df.y.isin([0,1]).all():raise ValueError('Source/label mismatch')
roles=['train','competence_reference','profile_fit','cutoff_calibration','source_validation']
if set(df[role_col])!=set(roles):raise ValueError('Role set differs from accepted allocation')
def group_key(k):
 p=json.loads(str(k))
 if not isinstance(p,list) or len(p)!=6:raise ValueError('Unsupported record_key representation')
 return json.dumps([str(v) for v in p[1:]],separators=(',',':'))
groups=df.record_key.map(group_key)
allocation_groups=df.source_scenario.astype(str)+'|'+groups
if pd.DataFrame({'g':allocation_groups,'r':df[role_col]}).groupby('g').r.nunique().gt(1).any():raise ValueError('Within-capture directed five-tuple group crosses roles')
global_tuple_role_conflicts=int(pd.DataFrame({'g':groups,'r':df[role_col]}).groupby('g').r.nunique().gt(1).sum())
for c in F:
 if c!='proto' and (not np.isfinite(pd.to_numeric(df[c],errors='raise')).all() or (df[c]<0).any()):raise ValueError('Invalid nonnegative numeric field: '+c)
registry=json.loads((RECOVERY/'artifact_registry.json').read_text())
model_path=Path(registry['resolved_paths']['trace_source_model'])
if sha(model_path)!=registry['trace_model_expected_sha256']:raise ValueError('Historical template hash mismatch')
old=joblib.load(model_path)
params={}
for seed in SEEDS:
 bank=old['models'].get(seed,old['models'].get(str(seed)))
 if not isinstance(bank,dict):raise ValueError('Missing source template seed')
 params[str(seed)]={name:json_ready(bank[name].get_params(deep=False)) for name in ['PRIMARY','V_orig','V_resp','V_time_proto']}
 if any(type(bank[name]).__name__!='HistGradientBoostingClassifier' for name in params[str(seed)]):raise ValueError('Unexpected template model type')
schemas={'core9':F,'expanded13':F+EXTRA}
views={'core9':{'originator':['orig_pkts','orig_bytes','orig_ip_bytes'],
'responder':['resp_pkts','resp_bytes','resp_ip_bytes'],'timing':['duration'],'context':['proto','missed_bytes']},
'expanded13':{'originator':['orig_pkts','orig_bytes','orig_ip_bytes'],
'responder':['resp_pkts','resp_bytes','resp_ip_bytes'],'timing':['duration'],'context':['proto','missed_bytes']+EXTRA}}
config={'driver_version':'closing-source-fold-driver-v2','allocation_path':str(allocation),'allocation_sha256':EXPECTED_ALLOCATION,
'prior_driver_configuration_sha256':OLD_CONFIG,'prior_driver_equivalence_claimed':False,'role_column':role_col,
'sources':SOURCES,'seeds':SEEDS,'schemas':schemas,'views':views,'historical_template_path':str(model_path),
'historical_template_sha256':registry['trace_model_expected_sha256'],'hgb_parameters':params,
'preprocessing':{'numeric':'log1p nonnegative inputs','protocol_categories':['tcp','udp','icmp'],
'context_categories':['id.resp_p','service','conn_state','history'],'context_min_frequency':10,'context_max_categories':64,'unknown_categories':'ignore'},
'classification_threshold':0.5,'primary_evaluation':'held-out capture source_validation role only',
'secondary_evaluation':'all records of held-out capture; not used for schema selection',
'model_fit':'train role of the other two captures only','thread_limit':2,
'eligibility':{'primary_min_fold_mean_bacc':0.8,'view_mean_fold_bacc':0.7,'view_each_fold_mean_bacc_strictly_above':0.5,'minimum_views':2},
'scope':'Source-only development; no new target selection or outcomes; no calibration or abstention implementation in these folds',
'group_audit':'Within-capture directed tuple grouping asserted; cross-capture equal tuples reported as diagnostics',
'cross_capture_tuple_role_conflicts_diagnostic':global_tuple_role_conflicts}
config_hash=canonical(config)
if config_hash!=EXPECTED_DRIVER:
    diagnostic=ROOT/'driver_reconstruction_difference.json'
    diagnostic.write_text(json.dumps({'status':'DRIVER_RECONSTRUCTION_MISMATCH','expected_sha256':EXPECTED_DRIVER,
        'actual_sha256':config_hash,'candidate_configuration':config,'training_authorized':False},indent=2,default=str))
    raise RuntimeError('Reconstructed driver differs from the recorded v2 configuration. No training performed. Return '+str(diagnostic))
out=Path('/kaggle/working')/('CLOSING_E2E3_DRIVER_v2_'+config_hash[:12]);out.mkdir(exist_ok=True)
config_path=out/'configuration.json'
if config_path.exists() and json.loads(config_path.read_text())!=json.loads(json.dumps(config,default=str)):raise RuntimeError('Existing driver configuration conflicts')
if not config_path.exists():config_path.write_text(json.dumps(config,indent=2,default=str))
context={'run_directory':str(out),'configuration_path':str(config_path),'configuration_sha256':config_hash}
Path('/kaggle/working/CLOSING_CURRENT_SOURCE_DRIVER.json').write_text(json.dumps(context,indent=2))
pd.DataFrame({'record_id':df.record_id,'source_scenario':df.source_scenario,'role':df[role_col],'directed_group':groups,'allocation_group':allocation_groups}).to_parquet(out/'identity_audit.parquet',index=False)
print('=== SOURCE DRIVER PREPARATION ===')
print(json.dumps({**context,'accepted_allocation_reused':True,'records':len(df),'new_source_model_fits_planned':90,
'shortcut_fits_planned':9,'metadata_only_repair_preserved':True,'old_v1_files_overwritten':False,
'new_targets_read':False,'training_started':False},indent=2))
print('\n=== SOURCE VALIDATION COUNTS ===')
print(df[df[role_col].eq('source_validation')].groupby(['source_scenario','y']).size().rename('records').to_string())
preparation_receipt={**context,'status':'EXACT_HISTORICAL_V2_PREPARATION_RECOVERED',
'allocation_sha256':EXPECTED_ALLOCATION,'historical_template_sha256':registry['trace_model_expected_sha256'],
'original_v2_configuration_reproduced':True,'training_started':False,'new_targets_read':False,
'prior_source_feasibility_passed':False,'next_step':'Resume the ORIGINAL v2 execution/report cells; no E4 or target evaluation'}
(out/'recovery_preparation_receipt.json').write_text(json.dumps(preparation_receipt,indent=2))
print('\n=== REPLACEMENT CODE 6 RECEIPT ===\n'+json.dumps(preparation_receipt,indent=2))
