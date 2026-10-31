"""NF Step 4: lock the representation-level test contract, then allocate targets.
No target predictions, attacks, retraining, or tuning.
Declared attack is post-extraction timing-report corruption, NOT valid traffic pacing.
"""
import gc,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pyarrow.dataset as ds

STEP1=Path('/kaggle/working/nf_boundary_spec_v1/NF_boundary_feature_specification.json')
STEP2=Path('/kaggle/working/nf_step2_source_training_v1')
INPUT=Path('/kaggle/working/nf_step3_calibration_v1/NF_calibrated_source_bundle.joblib')
OUT=Path('/kaggle/working/nf_step4_target_contract_v1');OUT.mkdir(parents=True,exist_ok=True)
EXPECTED_MODEL_SHA='888e9783643a06792283f128403eda2e88309c6f162f0037e61dc6c907a39268'
FAMILIES=['injection','xss','ransomware','backdoor','mitm']
WINDOW_SIZE=128
CAP_PER_CLASS=1280
POOL_SEED=2002
BATCH_SIZE=50000
REPORT_FIELDS=['FLOW_DURATION_MILLISECONDS','DURATION_IN','DURATION_OUT']

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def object_hash(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def write_json(path,value):
 temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2),encoding='utf-8');temp.replace(path)

if not INPUT.is_file() or sha(INPUT)!=EXPECTED_MODEL_SHA:raise RuntimeError('Calibrated source model differs from verified Step 3.')
spec=json.loads(STEP1.read_text())['specification']
training_settings=json.loads((STEP2/'source_training_settings.json').read_text())['settings']
DATA=Path(spec['data_file'])
if sha(DATA)!=training_settings['data_sha256']:raise RuntimeError('NF input bytes changed.')
bundle=joblib.load(INPUT)
features=list(bundle['primary_features'])
if any(field not in features for field in REPORT_FIELDS):raise ValueError('Declared timing-report fields are absent.')
for field in REPORT_FIELDS:
 if field not in bundle['semantic_views']['timing_rate']:raise ValueError('Declared channel membership mismatch.')

contract={
 'version':'NF-record-report-boundary-v1','feature_spec_sha256':bundle['feature_spec_sha256'],
 'calibrated_bundle_sha256':EXPECTED_MODEL_SHA,'data_sha256':training_settings['data_sha256'],
 'heldout_attack_families':FAMILIES,'cap_per_class_per_family':CAP_PER_CLASS,
 'minimum_complete_balanced_windows_per_family':2,'window_size':WINDOW_SIZE,
 'sampling_seed':POOL_SEED,'sampling':'lowest seeded random priorities; no score-based selection',
 'eligible_predictor_group_rule':'normalized float64 predictor hash modulo 1000 >=900',
 'normal_panel_rule':'(predictor_hash //1000) modulo 5, mapped to declared family order',
 'primary_baseline':'AC','primary_monitor':'ANCH_primary_agreement',
 'boundary_prediction_threshold':.80,
 'natural_view_accuracy_aggregation':'equal-weight average over declared family panels and four views',
 'differential_error_aggregation':'mean paired-window error within family, then equal family mean',
 'primary_attack':{'name':'linear_whitebox_timing_report_corruption','epsilon':.25,
  'sensitivity_epsilons':[.10,.50],'controlled_fields':REPORT_FIELDS,
  'budget_units':'epsilon times primary training StandardScaler scale per declared field',
  'box':'origin-anchored training .001/.999 quantile envelope intersected with coordinate budget',
  'integer_rule':'source-integer fields remain integer; choose feasible integer endpoint',
  'missing_origin_rule':'leave that coordinate unchanged','perturbed_rows':'malicious label 1 only',
  'objective':'minimize frozen primary detector logit in the declared independent-coordinate box',
  'labels_identifiers_other_predictors':'unchanged'},
 'attack_surface':'delivered post-extraction numeric reports; original network activity is not modified',
 'record_field_tampering_declared':True,
 'traffic_primitive_transformation_approved':False,
 'derived_cross_field_relationships_preserved':False,
 'NetFlow_semantic_validity_claim_allowed':False,'packet_validity_claim_allowed':False,
 'physical_source_group_independence_verified':False,'independent_corpus_claim_allowed':False,
 'lineage_scope':'same-parent representation and held-out-attack-family boundary',
 'family_panels_are_not_proven_independent_sampling_units':True,
 'statistics':'descriptive paired errors; no independent confirmation p-value or population guarantee',
 'fixed_operating_rules':{'classifier':'>','weighted_vote':'>.5','support_gate':'<=1'},
 'target_outcomes_used_to_select_settings':False,
 'shortage_rule':'stop without predictions; do not invent records or change eligibility to get favorable results'}
contract_hash=object_hash(contract);contract_path=OUT/'boundary_contract.json'
if contract_path.exists():
 if json.loads(contract_path.read_text())['contract_sha256']!=contract_hash:raise RuntimeError('An earlier contract differs; no overwrite.')
else:write_json(contract_path,{'contract':contract,'contract_sha256':contract_hash,
 'locked_before_target_scan_utc':datetime.now(timezone.utc).isoformat()})
print('LOCKED TARGET CONTRACT:',contract_hash,flush=True)

TARGET=OUT/'NF_target_panels.joblib';DONE=OUT/'target_allocation_receipt.json'
if TARGET.exists() or DONE.exists():
 if not (TARGET.exists() and DONE.exists()):raise RuntimeError('Incomplete earlier allocation artifacts; preserve and inspect.')
 receipt=json.loads(DONE.read_text())
 if receipt['contract_sha256']!=contract_hash or sha(TARGET)!=receipt['target_panels_sha256']:raise RuntimeError('Existing allocation mismatch.')
 print(json.dumps(receipt,indent=2));print('COMPLETED ALLOCATION REUSED; NOT RESCANNED.')
else:
 aliases=set()
 for family in FAMILIES:aliases.update([family,family.upper(),family.title()])
 aliases.update(['MITM','XSS'])
 dataset=ds.dataset(DATA,format='parquet')
 label_column=spec['label_column'];family_column=spec['family_column']
 scanner=dataset.scanner(columns=features+[label_column,family_column],
  filter=(ds.field(label_column)==0)|ds.field(family_column).isin(sorted(aliases)),
  batch_size=BATCH_SIZE,use_threads=False)
 rng=np.random.default_rng(POOL_SEED);pools={};returned=0;eligible_counts={};nonfinite=0
 for batch_number,batch in enumerate(scanner.to_batches(),start=1):
  raw=batch.to_pandas();labels=pd.to_numeric(raw[label_column],errors='raise')
  if labels.isna().any() or not set(labels.unique()).issubset({0,1}):raise ValueError('Invalid target labels; no replacement labels.')
  names=raw[family_column].astype(str).str.strip().str.lower()
  if ((labels==1)&~names.isin(FAMILIES)).any():raise ValueError('Unexpected malicious family returned.')
  x=raw[features].apply(pd.to_numeric,errors='raise').astype('float64')
  nonfinite+=int(np.isinf(x.to_numpy()).sum());x=x.replace([np.inf,-np.inf],np.nan)
  h=pd.util.hash_pandas_object(x,index=False,hash_key='nf-boundary-v1!!').to_numpy(dtype=np.uint64)
  eligible=h%np.uint64(1000)>=np.uint64(900)
  normal_panel=((h//np.uint64(1000))%np.uint64(5)).astype(int)
  panel=np.where(labels.to_numpy()==0,np.asarray(FAMILIES,dtype=object)[normal_panel],names.to_numpy())
  frame=x.copy();frame['label']=labels.to_numpy(dtype=int)
  frame['_family']=np.where(labels.to_numpy()==0,'__normal__',names.to_numpy())
  frame['_panel_family']=panel;frame['_feature_group_hash']=h
  frame['_row_id']=[training_settings['data_sha256'][:16]+':filtered_target:'+str(returned+i) for i in range(len(raw))]
  frame['_priority']=rng.integers(0,np.iinfo(np.int64).max,size=len(raw),dtype=np.int64)
  returned+=len(raw)
  for (family,label),part in frame.loc[eligible].groupby(['_panel_family','label'],sort=True):
   key=(family,int(label));eligible_counts[key]=eligible_counts.get(key,0)+len(part)
   previous=pools.get(key)
   merged=pd.concat([previous,part],ignore_index=True) if previous is not None else part
   pools[key]=merged.sort_values(['_priority','_row_id'],kind='stable').iloc[:CAP_PER_CLASS].copy()
  if batch_number%20==0:print('TARGET ALLOCATION SCAN',batch_number,'batches;',returned,'returned rows; no predictions',flush=True)
  del raw,x,frame;gc.collect()

 panels={};rows=[]
 source_groups=set()
 for key in ['train_df','primary_calibration_df','view_threshold_df','normal_profile_fit_df',
  'normal_profile_calibration_df','known_reference_df','known_profile_calibration_df','source_test_df']:
  source_groups.update(bundle[key]['_feature_group_hash'].tolist())
 for family in FAMILIES:
  normal=pools.get((family,0));attack=pools.get((family,1))
  if normal is None or attack is None:raise RuntimeError('Missing eligible class for '+family+'; no outcome evaluation performed.')
  per_class=min(len(normal),len(attack))//WINDOW_SIZE*WINDOW_SIZE
  if per_class<WINDOW_SIZE:raise RuntimeError('Insufficient eligible records for '+family+'; eligibility not retuned.')
  panel=pd.concat([normal.iloc[:per_class],attack.iloc[:per_class]],ignore_index=True)
  panel=panel.sample(frac=1,random_state=1002).reset_index(drop=True).drop(columns='_priority')
  if panel['_row_id'].duplicated().any():raise AssertionError('Duplicate panel row IDs.')
  if source_groups&set(panel['_feature_group_hash']):raise AssertionError('Target predictor-equivalence groups overlap source allocations.')
  panels[family]=panel
  rows.append({'family':family,'normal_rows':per_class,'attack_rows':per_class,
   'complete_windows':len(panel)//WINDOW_SIZE,
   'unique_predictor_groups':panel['_feature_group_hash'].nunique(),
   'eligible_normal_rows_in_full_scan':eligible_counts.get((family,0),0),
   'eligible_attack_rows_in_full_scan':eligible_counts.get((family,1),0)})
 overlap_rows=[]
 for i,left in enumerate(FAMILIES):
  for right in FAMILIES[i+1:]:
   overlap_rows.append({'left_panel':left,'right_panel':right,
    'shared_predictor_groups':len(set(panels[left]['_feature_group_hash'])&set(panels[right]['_feature_group_hash']))})
 temporary=TARGET.with_suffix('.tmp');joblib.dump({'panels':panels,'contract_sha256':contract_hash},temporary,compress=3);temporary.replace(TARGET)
 pd.DataFrame(rows).to_csv(OUT/'target_allocations.csv',index=False)
 pd.DataFrame(overlap_rows).to_csv(OUT/'cross_panel_group_overlaps.csv',index=False)
 receipt={'output_directory':str(OUT),'contract_sha256':contract_hash,
  'target_panels_path':str(TARGET),'target_panels_sha256':sha(TARGET),
  'family_panels_allocated':len(panels),'total_target_rows':sum(len(p) for p in panels.values()),
  'source_target_predictor_group_disjointness_verified':True,
  'physical_source_group_independence_verified':False,
  'cross_panel_group_overlap_present':any(row['shared_predictor_groups']>0 for row in overlap_rows),
  'target_record_values_loaded':True,'target_labels_loaded_for_allocation':True,
  'target_model_predictions_computed':False,'target_outcomes_inspected':False,
  'nonfinite_features_treated_as_missing':nonfinite,
  'models_retrained':False,'attacks_executed':False,'boundary_experiment_completed':False,
  'independent_corpus_claim_allowed':False,
  'attack_scope':'post-extraction report-field corruption, range/type constraints only',
  'NetFlow_semantic_validity_established':False,'packet_validity_established':False}
 write_json(DONE,receipt)
 print(json.dumps(receipt,indent=2));print('\nTARGET ALLOCATIONS');print(pd.DataFrame(rows).to_string(index=False))
 print('\nCROSS-PANEL GROUP OVERLAPS');print(pd.DataFrame(overlap_rows).to_string(index=False))
 print('\nNEXT: evaluate the locked clean and corrupted target panels without tuning.')
