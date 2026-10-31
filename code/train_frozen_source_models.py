"""TRACE CONFIRMATORY STEP 1: source-only model fitting on frozen design scenarios 1-1, 3-1, 8-1.
Does NOT open E1 target PCAP slices, target logs, target labels, target rows, target models or attacks.
Models: HGB primary + three HGB views for seeds locked in TRACE_CONFIRMATORY_PROTOCOL_v1.
"""
import glob,hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score

WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';OUT=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1'
if not PROTO.is_file():raise FileNotFoundError('Frozen protocol missing.')
if OUT.exists():raise RuntimeError('Source model directory already exists; do not overwrite frozen source models.')
P=json.loads(PROTO.read_text());expected=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']
if P['design_scenarios_source_training_only']!=expected or P['models_trained'] or P['target_predictions_computed']:raise RuntimeError('Unexpected protocol state.')
FEATURES=P['source_detector']['primary_features'];VIEWS=P['monitor']['views'];SEEDS=P['source_detector']['random_seeds'];MAX_PER_CLASS_PER_SOURCE=40000

def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def find_largest(pattern):
 found=sorted(glob.glob(str(WORK/pattern)),key=lambda p:Path(p).stat().st_size,reverse=True)
 if not found:raise FileNotFoundError(pattern)
 return Path(found[0])
def numeric(df):
 for c in FEATURES:
  if c=='proto':df[c]=df[c].astype(str).str.lower()
  else:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0).clip(lower=0)
 return df
def onehot(df,cols):
 parts=[]
 for c in cols:
  if c=='proto':parts.append(np.column_stack([(df[c]=='tcp').to_numpy(float),(df[c]=='udp').to_numpy(float),(df[c]=='icmp').to_numpy(float)]))
  else:parts.append(np.log1p(df[[c]].to_numpy(float)))
 return np.hstack(parts)
def read_source(scenario):
 if scenario.endswith('1-1') or scenario.endswith('3-1'):
  path=find_largest(f'TRACE_LINKAGE_BATCH_v1/{scenario}/*/linked_records.csv')
  cols=FEATURES+['published_label'];raw=pd.read_csv(path,usecols=cols,dtype=str)
  raw=raw.rename(columns={'published_label':'label'})
 else:
  roots=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json')) if json.loads(Path(p).read_text()).get('scenario')==scenario]
  if len(roots)!=1:raise RuntimeError('Expected one clean-replay mapping for Capture-8-1.')
  path=roots[0]/'unique_exact_key_mapping.csv';hdr=pd.read_csv(path,nrows=0).columns.tolist()
  mapping={}
  for c in FEATURES:
   if c=='proto':
    choice=next((x for x in ['proto_generated','proto'] if x in hdr),None)
   else:choice=next((x for x in [c+'_generated',c] if x in hdr),None)
   if choice is None:raise RuntimeError('Missing source feature '+c+' in '+str(path))
   mapping[choice]=c
  label=next((x for x in ['published_label','label'] if x in hdr),None)
  if label is None:raise RuntimeError('Missing source label in '+str(path))
  raw=pd.read_csv(path,usecols=list(mapping)+[label],dtype=str).rename(columns={**mapping,label:'label'})
 raw['label']=raw.label.astype(str).str.lower();raw=raw[raw.label.isin(['benign','malicious'])].copy();raw=numeric(raw);raw['y']=(raw.label=='malicious').astype(int);raw['scenario']=scenario
 # Source-only balanced deterministic cap; no target data enter this selection.
 pieces=[]
 for y in (0,1):
  x=raw[raw.y==y];pieces.append(x.sample(min(MAX_PER_CLASS_PER_SOURCE,len(x)),random_state=abs(hash(scenario+str(y)))%2**31))
 return pd.concat(pieces,ignore_index=True),{'scenario':scenario,'source_path':str(path),'source_sha256':sha(path),'raw_rows':len(raw),'balanced_rows':sum(len(x)for x in pieces),'benign_raw':int((raw.y==0).sum()),'malicious_raw':int((raw.y==1).sum())}

frames=[];sources=[]
for s in expected:
 x,meta=read_source(s);frames.append(x);sources.append(meta)
source=pd.concat(frames,ignore_index=True)
# Deterministic source-only split: last 20% per scenario/class is held for source diagnostics, never targets.
train_parts=[];test_parts=[]
for s in expected:
 for y in (0,1):
  x=source[(source.scenario==s)&(source.y==y)].sample(frac=1,random_state=8100+expected.index(s)*10+y)
  n=max(1,int(.8*len(x)));train_parts.append(x.iloc[:n]);test_parts.append(x.iloc[n:])
train=pd.concat(train_parts,ignore_index=True);test=pd.concat(test_parts,ignore_index=True)
OUT.mkdir();joblib.dump({'protocol_sha256':sha(PROTO),'features':FEATURES,'views':VIEWS,'seeds':SEEDS,'source_metadata':sources,'train_rows':len(train),'test_rows':len(test)},OUT/'source_data_metadata.joblib')
models={};metrics=[]
for seed in SEEDS:
 bank={}
 for name,cols in {'PRIMARY':FEATURES,**VIEWS}.items():
  clf=HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,random_state=seed).fit(onehot(train,cols),train.y)
  bank[name]=clf
  p=clf.predict_proba(onehot(test,cols))[:,1];pred=(p>=.5).astype(int)
  metrics.append({'seed':seed,'model':name,'features':'|'.join(cols),'rows':len(test),'accuracy':accuracy_score(test.y,pred),'balanced_accuracy':balanced_accuracy_score(test.y,pred),'AUROC':roc_auc_score(test.y,p)})
 models[seed]=bank
joblib.dump({'protocol_sha256':sha(PROTO),'feature_schema':FEATURES,'views':VIEWS,'seeds':SEEDS,'models':models,'source_train_metadata':sources},OUT/'frozen_source_models.joblib')
pd.DataFrame(sources).to_csv(OUT/'source_data_manifest.csv',index=False);pd.DataFrame(metrics).to_csv(OUT/'source_model_diagnostics.csv',index=False)
receipt={'output_directory':str(OUT),'protocol_sha256':sha(PROTO),'source_scenarios':expected,'source_rows_train':len(train),'source_rows_test':len(test),'seeds':SEEDS,'models_trained':True,'target_pcap_or_log_opened':False,'target_predictions_computed':False,'target_outcomes_inspected':False,'attacks_executed':False,'NF_changed':False,'next_step':'Perform target-only transformability/PCAP mapping preflight. It must use frozen models only after transformation validity passes.'}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nSOURCE DATA MANIFEST');print(pd.DataFrame(sources).to_string(index=False));print('\nSOURCE MODEL DIAGNOSTICS');print(pd.DataFrame(metrics).round(4).to_string(index=False))
