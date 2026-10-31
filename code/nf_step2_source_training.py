"""NF Step 2: source-only allocation and training.
Locks settings before scanning. No held-out attack-family predictions or outcomes.
Predictor-equivalence grouping is NOT physical source-group independence.
"""
import gc,hashlib,json,warnings
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq
from sklearn.exceptions import ConvergenceWarning
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

SPEC_PATH=Path('/kaggle/working/nf_boundary_spec_v1/NF_boundary_feature_specification.json')
OUT=Path('/kaggle/working/nf_step2_source_training_v1')
OUT.mkdir(parents=True,exist_ok=True)
EXPECTED_SPEC='dcea984feb37322cbf055354e4b2aaa7569f45b5f8e877697dda4f50996cff9f'
SOURCE_FAMILIES=['scanning','dos','ddos','password']
HELDOUT_FAMILIES=['injection','xss','ransomware','backdoor','mitm']
NORMAL='__normal__'
MODEL_SEED=10
POOL_SEED=1
BATCH_SIZE=50000
MINIMUM_BUCKET_ROWS=128
CAPS={
 'train':{NORMAL:8000,'attack':2000},
 'primary_calibration_df':{NORMAL:1000,'attack':0},
 'view_threshold_df':{NORMAL:1000,'attack':0},
 'normal_profile_fit_df':{NORMAL:2000,'attack':0},
 'normal_profile_calibration_df':{NORMAL:2000,'attack':0},
 'known_reference_df':{NORMAL:2000,'attack':500},
 'known_profile_calibration_df':{NORMAL:2000,'attack':500},
 'source_test_df':{NORMAL:2000,'attack':500},
}
ROLE_BINS=[(0,400,'train'),(400,450,'primary_calibration_df'),
 (450,500,'view_threshold_df'),(500,550,'normal_profile_fit_df'),
 (550,600,'normal_profile_calibration_df'),(600,700,'known_reference_df'),
 (700,800,'known_profile_calibration_df'),(800,900,'source_test_df'),
 (900,1000,'boundary_reserved')]
CLASSIFIER_SETTINGS={'C':1.0,'solver':'lbfgs','max_iter':3000,
 'class_weight':'balanced','random_state':MODEL_SEED}

def canonical_hash(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def write_json(path,value):
 temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2),encoding='utf-8');temp.replace(path)
def source_model():
 return Pipeline([('imputer',SimpleImputer(strategy='median',keep_empty_features=True)),
  ('scaler',StandardScaler()),('classifier',LogisticRegression(**CLASSIFIER_SETTINGS))])
def fit_checked(columns,train):
 if not set(train.label.unique())=={0,1}:raise ValueError('Training needs both real label classes.')
 if train[columns].isna().all().any():raise ValueError('All-missing training predictor: '+str(train[columns].columns[train[columns].isna().all()].tolist()))
 model=source_model()
 with warnings.catch_warnings(record=True) as caught:
  warnings.simplefilter('always',ConvergenceWarning)
  with threadpool_limits(limits=4):model.fit(train[columns],train.label)
 if any(issubclass(item.category,ConvergenceWarning) for item in caught):
  raise RuntimeError('Classifier did not converge with frozen settings; no automatic retuning.')
 if list(model.classes_)!=[0,1]:raise ValueError('Unexpected binary class ordering.')
 return model

if not SPEC_PATH.is_file():raise FileNotFoundError(SPEC_PATH)
receipt=json.loads(SPEC_PATH.read_text());spec=receipt['specification']
if receipt['specification_sha256']!=EXPECTED_SPEC or canonical_hash(spec)!=EXPECTED_SPEC:
 raise RuntimeError('Step 1 specification differs from the verified receipt.')
DATA_PATH=Path(spec['data_file']);features=list(spec['predictors']);groups=spec['views']
if len(features)!=39 or sum(len(c) for c in groups.values())!=39:
 raise RuntimeError('Unexpected NF predictor/view coverage.')
if hashlib.sha256(str(pq.read_schema(DATA_PATH)).encode()).hexdigest()!=spec['schema_sha256']:
 raise RuntimeError('Parquet schema changed.')
settings={'version':'NF-source-training-v1','feature_spec_sha256':EXPECTED_SPEC,
 'data_file':str(DATA_PATH),'data_sha256':sha(DATA_PATH),
 'source_families':SOURCE_FAMILIES,'heldout_families':HELDOUT_FAMILIES,
 'model_seed':MODEL_SEED,'pool_seed':POOL_SEED,'caps':CAPS,'role_bins':ROLE_BINS,
 'minimum_rows_per_required_bucket':MINIMUM_BUCKET_ROWS,
 'classifier':CLASSIFIER_SETTINGS,'preprocessing':'float64; infinities to missing; training-only median imputation and scaling',
 'hash_key':'nf-boundary-v1!!','assignment_basis':'normalized predictor-equivalence hash modulo 1000',
 'classification_comparison':'>','normal_calibration_FPR_target':.05,
 'boundary_prediction_threshold':.80,
 'lineage_scope':'Same-parent representation boundary, not independent corpus',
 'attack_contract_approved':False,'target_outcome_tuning_allowed':False,
 'source_group_independence_verified':False,'packet_validity_established':False,
 'target_attack_family_records_requested':False}
settings_hash=canonical_hash(settings)
settings_path=OUT/'source_training_settings.json'
if settings_path.exists():
 old=json.loads(settings_path.read_text())
 if old['settings_sha256']!=settings_hash:raise RuntimeError('Frozen settings changed. Existing files not overwritten.')
else:write_json(settings_path,{'settings':settings,'settings_sha256':settings_hash,
 'frozen_before_source_scan_utc':datetime.now(timezone.utc).isoformat()})

bundle_path=OUT/'NF_source_bundle.joblib';completion_path=OUT/'source_training_receipt.json'
if bundle_path.exists() or completion_path.exists():
 if bundle_path.exists() and completion_path.exists():
  completed=json.loads(completion_path.read_text())
  if completed['settings_sha256']!=settings_hash or completed['bundle_sha256']!=sha(bundle_path):
   raise RuntimeError('Existing completed source-training artifact mismatch.')
  print(json.dumps(completed,indent=2));print('EXISTING VERIFIED SOURCE TRAINING REUSED; NOT RETRAINED.')
 else:raise RuntimeError('Incomplete earlier training artifacts found. Preserve them and inspect before retrying.')
else:
 dataset=ds.dataset(DATA_PATH,format='parquet')
 label_column=spec['label_column'];family_column=spec['family_column']
 label_type=dataset.schema.field(label_column).type
 if not (pa.types.is_integer(label_type) or pa.types.is_floating(label_type)):
  raise TypeError('Binary Label field is not numeric; no implicit label conversion.')
 aliases=set()
 for family in SOURCE_FAMILIES:aliases.update([family,family.upper(),family.title()])
 aliases.update(['DoS','DDoS'])
 source_filter=(ds.field(label_column)==0)|ds.field(family_column).isin(sorted(aliases))
 scanner=dataset.scanner(columns=features+[label_column,family_column],
  filter=source_filter,batch_size=BATCH_SIZE,use_threads=False)
 rng=np.random.default_rng(POOL_SEED);pools={};returned=0;reserved_normal=0;nonfinite=0
 for batch_number,batch in enumerate(scanner.to_batches(),start=1):
  raw=batch.to_pandas();n=len(raw)
  label=pd.to_numeric(raw[label_column],errors='raise')
  if label.isna().any() or not set(label.unique()).issubset({0,1}):raise ValueError('Invalid source labels; no replacement labels generated.')
  family=raw[family_column].astype(str).str.strip().str.lower()
  unexpected=(label==1)&~family.isin(SOURCE_FAMILIES)
  if unexpected.any():raise RuntimeError('Scanner returned a non-source attack family; boundary processing stopped.')
  x=raw[features].apply(pd.to_numeric,errors='raise').astype('float64')
  nonfinite+=int(np.isinf(x.to_numpy()).sum());x=x.replace([np.inf,-np.inf],np.nan)
  group_hash=pd.util.hash_pandas_object(x,index=False,hash_key='nf-boundary-v1!!').to_numpy(dtype=np.uint64)
  bins=(group_hash%np.uint64(1000)).astype(int)
  roles=np.empty(n,dtype=object)
  for lo,hi,role in ROLE_BINS:roles[(bins>=lo)&(bins<hi)]=role
  reserved_normal+=int(((roles=='boundary_reserved')&(label.to_numpy()==0)).sum())
  frame=x.copy();frame['label']=label.to_numpy(dtype=int)
  frame['_family']=np.where(label.to_numpy()==0,NORMAL,family.to_numpy())
  frame['_row_id']=[settings['data_sha256'][:16]+':filtered_source:'+str(returned+i) for i in range(n)]
  frame['_feature_group_hash']=group_hash
  frame['_priority']=rng.integers(0,np.iinfo(np.int64).max,size=n,dtype=np.int64)
  frame['_role']=roles;returned+=n
  for (role,fam),part in frame.groupby(['_role','_family'],sort=True):
   if role not in CAPS:continue
   cap=CAPS[role][NORMAL if fam==NORMAL else 'attack']
   if cap==0:continue
   key=(role,fam);part=part.drop(columns='_role')
   previous=pools.get(key)
   merged=pd.concat([previous,part],ignore_index=True) if previous is not None else part
   pools[key]=merged.sort_values(['_priority','_row_id'],kind='stable').iloc[:cap].copy()
  if batch_number%20==0:print('SOURCE SCAN',batch_number,'batches;',returned,'returned source/normal rows',flush=True)
  del raw,x,frame;gc.collect()

 frames={};allocation_rows=[]
 for role,caps in CAPS.items():
  required_families=[NORMAL]+(SOURCE_FAMILIES if caps['attack']>0 else [])
  parts=[]
  for fam in required_families:
   frame=pools.get((role,fam))
   if frame is None or len(frame)<MINIMUM_BUCKET_ROWS:
    raise ValueError(f'Insufficient source records for {role}/{fam}; no sample fabricated or allocation retuned.')
   parts.append(frame)
   allocation_rows.append({'role':role,'family':fam,'rows':len(frame),'label':int(frame.label.iloc[0])})
  frames[role]=pd.concat(parts,ignore_index=True).drop(columns='_priority')

 # Every normalized predictor-equivalence group stays within one allocation.
 allocated={role:set(frame['_feature_group_hash'].tolist()) for role,frame in frames.items()}
 roles=list(frames)
 for i,left in enumerate(roles):
  for right in roles[i+1:]:
   if allocated[left]&allocated[right]:raise AssertionError('Predictor-equivalence groups overlap allocations.')
 train=frames.pop('train')
 primary=fit_checked(features,train)
 view_models={}
 for view,columns in groups.items():
  view_models[view]=fit_checked(columns,train)
  print('TRAINED SOURCE VIEW:',view,'features:',len(columns),flush=True)

 bundle={'dataset':'NF-ToN-IoT-v2','run_kind':'source_only_boundary_preparation_v1',
  'primary_features':features,'semantic_views':groups,'train_df':train,
  'primary_model':primary,'view_models':view_models,**frames,
  'feature_spec_sha256':EXPECTED_SPEC,'source_training_settings_sha256':settings_hash,
  'primary_threshold':None,'view_thresholds':None,'profiles':None,
  'heldout_families':HELDOUT_FAMILIES,'source_group_independence_verified':False,
  'row_identifier_scope':'filtered-source scanner ordinal; not raw packet/capture identity',
  'evaluation_domains':{},'mutable_columns':[],
  'attack_contract_status':'PENDING_NO_ATTACK_VARIABLES_APPROVED'}
 temporary=bundle_path.with_suffix('.tmp')
 joblib.dump(bundle,temporary,compress=3);temporary.replace(bundle_path)
 pd.DataFrame(allocation_rows).to_csv(OUT/'source_allocations.csv',index=False)
 completed={'output_directory':str(OUT),'settings_sha256':settings_hash,
  'bundle_path':str(bundle_path),'bundle_sha256':sha(bundle_path),
  'source_records_returned_by_scanner':returned,'primary_training_rows':len(train),
  'source_view_count':len(view_models),'source_models_trained':1+len(view_models),
  'source_role_counts':{role:len(frame) for role,frame in frames.items()},
  'nonfinite_feature_values_treated_as_missing':nonfinite,
  'reserved_normal_rows_returned_by_scanner_but_not_allocated':reserved_normal,
  'heldout_attack_family_records_returned_by_scanner':0,
  'source_record_values_loaded':True,'source_label_values_loaded':True,
  'target_model_predictions_computed':False,'target_outcomes_inspected':False,
  'classifier_thresholds_calibrated':False,'attacks_executed':False,
  'boundary_experiment_completed':False,'independent_corpus_claim_allowed':False,
  'predictor_equivalence_group_disjointness_verified':True,
  'physical_source_group_independence_verified':False,
  'existing_development_artifacts_overwritten':False}
 write_json(completion_path,completed)
 print(json.dumps(completed,indent=2))
 print('\nSOURCE ALLOCATIONS')
 print(pd.DataFrame(allocation_rows).to_string(index=False))
 print('\nNEXT: calibrate these fixed models on the saved source-only reference allocations.')
