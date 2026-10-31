"""NF Step 4 v2: explicit pre-outcome allocation amendment.
Global eligibility excludes actual source predictor groups instead of an arbitrary 10% hash bucket.
Models, thresholds, profiles, window size, attack settings, family order and sample caps remain unchanged.
No target inference or attack is executed.
"""
import gc,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pyarrow.dataset as ds

OLD=Path('/kaggle/working/nf_step4_target_contract_v1')
OUT=Path('/kaggle/working/nf_step4_target_contract_v2');OUT.mkdir(parents=True,exist_ok=True)
INPUT=Path('/kaggle/working/nf_step3_calibration_v1/NF_calibrated_source_bundle.joblib')
SPEC=Path('/kaggle/working/nf_boundary_spec_v1/NF_boundary_feature_specification.json')
EXPECTED_OLD='85e0e300a34cf8472a7be55ae522e058ca533e717c18e64930ad1425123ab8ad'
EXPECTED_MODEL='888e9783643a06792283f128403eda2e88309c6f162f0037e61dc6c907a39268'
SOURCE_KEYS=['train_df','primary_calibration_df','view_threshold_df','normal_profile_fit_df',
 'normal_profile_calibration_df','known_reference_df','known_profile_calibration_df','source_test_df']

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def object_hash(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def write_json(path,value):
 tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2),encoding='utf-8');tmp.replace(path)
def save_joblib(path,value):
 tmp=path.with_suffix('.tmp');joblib.dump(value,tmp,compress=3);tmp.replace(path)

old=json.loads((OLD/'boundary_contract.json').read_text())
if old['contract_sha256']!=EXPECTED_OLD or object_hash(old['contract'])!=EXPECTED_OLD:
 raise RuntimeError('Original contract does not match the reported failed allocation.')
if not INPUT.is_file() or sha(INPUT)!=EXPECTED_MODEL:raise RuntimeError('Source model checksum changed.')
bundle=joblib.load(INPUT);spec=json.loads(SPEC.read_text())['specification']
DATA=Path(spec['data_file'])
if sha(DATA)!=old['contract']['data_sha256']:raise RuntimeError('NF input bytes changed.')
features=list(bundle['primary_features'])
FAMILIES=list(old['contract']['heldout_attack_families'])
WINDOW_SIZE=int(old['contract']['window_size'])
CAP=int(old['contract']['cap_per_class_per_family'])
POOL_SEED=int(old['contract']['sampling_seed'])
protected=set()
for key in SOURCE_KEYS:protected.update(int(x) for x in bundle[key]['_feature_group_hash'])
write_json(OUT/'preserved_v1_contract.json',old)

# Preserve failed scan buffers if running in the same notebook kernel.
v1_pools=globals().get('pools')
if isinstance(v1_pools,dict) and v1_pools and all(
 isinstance(value,pd.DataFrame) and {'_panel_family','_feature_group_hash','label'}.issubset(value)
 for value in v1_pools.values()):
 path=OLD/'failed_scan_pools_checkpoint.joblib'
 if not path.exists():save_joblib(path,v1_pools)
 rows=[]
 for family in FAMILIES:
  for label in [0,1]:
   frame=v1_pools.get((family,label))
   rows.append({'family':family,'label':label,'retained_v1_records':len(frame) if frame is not None else 0})
 pd.DataFrame(rows).to_csv(OUT/'preserved_v1_availability.csv',index=False)

contract=json.loads(json.dumps(old['contract']))
contract['version']='NF-record-report-boundary-v2'
contract['eligible_predictor_group_rule']='Normalized predictor-equivalence hash absent from ALL actual source allocations'
contract['pre_outcome_allocation_amendment']={
 'supersedes_contract_sha256':EXPECTED_OLD,
 'reason':'Ransomware had fewer than 128 eligible records under the arbitrary reserved hash bucket.',
 'changed':'Eligibility only: actual unused predictor groups, applied equally to all attack families and normal panels.',
 'unchanged':['models','classifier thresholds','reference profiles','window size','attack fields',
  'attack budgets','baseline','boundary prediction','family order','sampling seed','sample caps'],
 'target_model_outcomes_used':False,'physical_source_independence_claim_added':False}
for key,value in old['contract'].items():
 if key not in {'version','eligible_predictor_group_rule'} and contract[key]!=value:
  raise AssertionError('Unexpected design change: '+key)
contract_hash=object_hash(contract);contract_path=OUT/'boundary_contract.json'
if contract_path.exists():
 if json.loads(contract_path.read_text())['contract_sha256']!=contract_hash:raise RuntimeError('Existing v2 contract differs; no overwrite.')
else:write_json(contract_path,{'contract':contract,'contract_sha256':contract_hash,
 'amended_before_target_inference_utc':datetime.now(timezone.utc).isoformat()})
print('V1 CONTRACT PRESERVED:',EXPECTED_OLD,flush=True)
print('V2 ALLOCATION AMENDMENT LOCKED:',contract_hash,flush=True)

TARGET=OUT/'NF_target_panels.joblib';DONE=OUT/'target_allocation_receipt.json'
CHECKPOINT=OUT/'target_scan_pools_checkpoint.joblib'
if TARGET.exists() or DONE.exists():
 if not (TARGET.exists() and DONE.exists()):raise RuntimeError('Incomplete earlier output. Preserve before retrying.')
 receipt=json.loads(DONE.read_text())
 if receipt['contract_sha256']!=contract_hash or sha(TARGET)!=receipt['target_panels_sha256']:raise RuntimeError('Completed v2 output mismatch.')
 print(json.dumps(receipt,indent=2));print('VERIFIED V2 TARGET ALLOCATION REUSED.')
else:
 if CHECKPOINT.exists():
  cached=joblib.load(CHECKPOINT)
  if cached['contract_sha256']!=contract_hash or cached['model_sha256']!=EXPECTED_MODEL:raise RuntimeError('Scan checkpoint mismatch.')
  pools=cached['pools'];eligible_counts=cached['eligible_counts'];returned=cached['returned'];nonfinite=cached['nonfinite']
  print('COMPLETE V2 SCAN CHECKPOINT REUSED',flush=True)
 else:
  aliases=set()
  for family in FAMILIES:aliases.update([family,family.upper(),family.title()])
  aliases.update(['MITM','XSS'])
  label_column=spec['label_column'];family_column=spec['family_column']
  scanner=ds.dataset(DATA,format='parquet').scanner(columns=features+[label_column,family_column],
   filter=(ds.field(label_column)==0)|ds.field(family_column).isin(sorted(aliases)),
   batch_size=50000,use_threads=False)
  rng=np.random.default_rng(POOL_SEED);pools={};eligible_counts={};returned=0;nonfinite=0
  for batch_number,batch in enumerate(scanner.to_batches(),start=1):
   raw=batch.to_pandas();labels=pd.to_numeric(raw[label_column],errors='raise')
   if labels.isna().any() or not set(labels.unique()).issubset({0,1}):raise ValueError('Invalid labels; no replacements generated.')
   names=raw[family_column].astype(str).str.strip().str.lower()
   if ((labels==1)&~names.isin(FAMILIES)).any():raise ValueError('Unexpected malicious family.')
   x=raw[features].apply(pd.to_numeric,errors='raise').astype('float64')
   nonfinite+=int(np.isinf(x.to_numpy()).sum());x=x.replace([np.inf,-np.inf],np.nan)
   h=pd.util.hash_pandas_object(x,index=False,hash_key='nf-boundary-v1!!').to_numpy(dtype=np.uint64)
   eligible=np.fromiter((int(value) not in protected for value in h),dtype=bool,count=len(h))
   normal_panel=((h//np.uint64(1000))%np.uint64(len(FAMILIES))).astype(int)
   panel=np.where(labels.to_numpy()==0,np.asarray(FAMILIES,dtype=object)[normal_panel],names.to_numpy())
   frame=x.copy();frame['label']=labels.to_numpy(dtype=int)
   frame['_family']=np.where(labels.to_numpy()==0,'__normal__',names.to_numpy())
   frame['_panel_family']=panel;frame['_feature_group_hash']=h
   frame['_row_id']=[contract['data_sha256'][:16]+':filtered_target:'+str(returned+i) for i in range(len(raw))]
   frame['_priority']=rng.integers(0,np.iinfo(np.int64).max,size=len(raw),dtype=np.int64)
   returned+=len(raw)
   for (family,label),part in frame.loc[eligible].groupby(['_panel_family','label'],sort=True):
    key=(family,int(label));eligible_counts[key]=eligible_counts.get(key,0)+len(part)
    previous=pools.get(key);merged=pd.concat([previous,part],ignore_index=True) if previous is not None else part
    pools[key]=merged.sort_values(['_priority','_row_id'],kind='stable').iloc[:CAP].copy()
   if batch_number%20==0:print('V2 ALLOCATION SCAN',batch_number,'batches;',returned,'returned rows; no predictions',flush=True)
   del raw,x,frame;gc.collect()
  save_joblib(CHECKPOINT,{'contract_sha256':contract_hash,'model_sha256':EXPECTED_MODEL,
   'pools':pools,'eligible_counts':eligible_counts,'returned':returned,'nonfinite':nonfinite})

 availability=[]
 for family in FAMILIES:
  normal=pools.get((family,0));attack=pools.get((family,1))
  n0=len(normal) if normal is not None else 0;n1=len(attack) if attack is not None else 0
  availability.append({'family':family,'retained_normal':n0,'retained_attack':n1,
   'eligible_normal_full_scan':eligible_counts.get((family,0),0),
   'eligible_attack_full_scan':eligible_counts.get((family,1),0),
   'balanced_rows_per_class':min(n0,n1)//WINDOW_SIZE*WINDOW_SIZE})
 table=pd.DataFrame(availability);table.to_csv(OUT/'target_availability_before_inference.csv',index=False)
 print('\nTARGET AVAILABILITY',flush=True);print(table.to_string(index=False),flush=True)
 insufficient=table[table.balanced_rows_per_class<WINDOW_SIZE]
 if not insufficient.empty:
  write_json(OUT/'allocation_blocker.json',{'contract_sha256':contract_hash,
   'insufficient_families':insufficient.family.tolist(),'scan_checkpoint_saved':True,
   'target_predictions_computed':False,'no_fake_records_created':True})
  raise RuntimeError('Still insufficient actual unused groups. Checkpoint and exact counts saved; no outcomes evaluated.')

 panels={};rows=[]
 for family in FAMILIES:
  normal=pools[(family,0)];attack=pools[(family,1)]
  per_class=min(len(normal),len(attack))//WINDOW_SIZE*WINDOW_SIZE
  frame=pd.concat([normal.iloc[:per_class],attack.iloc[:per_class]],ignore_index=True)
  frame=frame.sample(frac=1,random_state=1002).reset_index(drop=True).drop(columns='_priority')
  if frame['_row_id'].duplicated().any():raise AssertionError('Duplicate panel IDs.')
  if protected&set(int(x) for x in frame['_feature_group_hash']):raise AssertionError('Target/source predictor-group overlap.')
  panels[family]=frame
  rows.append({'family':family,'normal_rows':per_class,'attack_rows':per_class,
   'complete_windows':len(frame)//WINDOW_SIZE,'unique_predictor_groups':frame['_feature_group_hash'].nunique()})
 overlap_rows=[]
 for i,left in enumerate(FAMILIES):
  for right in FAMILIES[i+1:]:
   overlap_rows.append({'left_panel':left,'right_panel':right,
    'shared_predictor_groups':len(set(panels[left]['_feature_group_hash'])&set(panels[right]['_feature_group_hash']))})
 save_joblib(TARGET,{'panels':panels,'contract_sha256':contract_hash})
 pd.DataFrame(rows).to_csv(OUT/'target_allocations.csv',index=False)
 pd.DataFrame(overlap_rows).to_csv(OUT/'cross_panel_group_overlaps.csv',index=False)
 receipt={'output_directory':str(OUT),'contract_sha256':contract_hash,'superseded_v1_contract_sha256':EXPECTED_OLD,
  'allocation_amendment_recorded':True,'target_panels_path':str(TARGET),'target_panels_sha256':sha(TARGET),
  'family_panels_allocated':len(panels),'total_target_rows':sum(len(p) for p in panels.values()),
  'source_target_predictor_group_disjointness_verified':True,
  'physical_source_group_independence_verified':False,'independent_corpus_claim_allowed':False,
  'cross_panel_group_overlap_present':any(row['shared_predictor_groups']>0 for row in overlap_rows),
  'target_record_values_loaded':True,'target_labels_loaded_for_allocation':True,
  'target_model_predictions_computed':False,'target_outcomes_inspected':False,
  'models_retrained':False,'thresholds_changed':False,'window_size_changed':False,
  'attacks_executed':False,'boundary_experiment_completed':False,
  'completed_scan_checkpoint_saved':True,'packet_validity_established':False}
 write_json(DONE,receipt)
 print(json.dumps(receipt,indent=2));print('\nTARGET ALLOCATIONS');print(pd.DataFrame(rows).to_string(index=False))
 print('\nCROSS-PANEL OVERLAPS');print(pd.DataFrame(overlap_rows).to_string(index=False))
 print('\nNEXT: locked target evaluation; no model/threshold/attack-budget tuning.')
