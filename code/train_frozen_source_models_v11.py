"""TRACE CONFIRMATORY STEP 1.1: corrected source-only fitting. Fix: Capture-8-1 mapping CSV does not store all Zeek fields;
its clean replay conn.log is joined to the saved exact-key published labels. No E1 target PCAP/log/label/row/model outcome is read.
"""
import glob,hashlib,json
from datetime import datetime
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';OUT=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1'
if not PROTO.is_file():raise FileNotFoundError(PROTO)
if OUT.exists():raise RuntimeError('Corrected source directory already exists; do not overwrite.')
P=json.loads(PROTO.read_text());expected=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']
if P['design_scenarios_source_training_only']!=expected or P['models_trained'] or P['target_predictions_computed']:raise RuntimeError('Unexpected frozen protocol state.')
FEATURES=P['source_detector']['primary_features'];VIEWS=P['monitor']['views'];SEEDS=P['source_detector']['random_seeds'];MAX_PER_CLASS_PER_SOURCE=40000
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def find_largest(pattern):
 x=sorted(glob.glob(str(WORK/pattern)),key=lambda p:Path(p).stat().st_size,reverse=True)
 if not x:raise FileNotFoundError(pattern)
 return Path(x[0])
def zkey(ts,o,op,r,rp,pr):return (int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),o,str(op),r,str(rp),pr.lower())
def parse_zeek(path):
 fields=None;rows=[]
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   rows.append(dict(zip(fields,line.rstrip().split())))
 if fields is None:raise RuntimeError('No Zeek #fields in '+str(path))
 return pd.DataFrame(rows)
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
def cap(raw,scenario):
 raw['label']=raw.label.astype(str).str.lower();raw=raw[raw.label.isin(['benign','malicious'])].copy();raw=numeric(raw);raw['y']=(raw.label=='malicious').astype(int);raw['scenario']=scenario
 pieces=[]
 for y in (0,1):
  x=raw[raw.y==y];
  if x.empty:raise RuntimeError('Source '+scenario+' lacks class '+str(y))
  pieces.append(x.sample(min(MAX_PER_CLASS_PER_SOURCE,len(x)),random_state=abs(hash(scenario+str(y)))%2**31))
 return pd.concat(pieces,ignore_index=True),raw
def read_source(s):
 if s.endswith('1-1') or s.endswith('3-1'):
  path=find_largest(f'TRACE_LINKAGE_BATCH_v1/{s}/*/linked_records.csv');raw=pd.read_csv(path,usecols=FEATURES+['published_label'],dtype=str).rename(columns={'published_label':'label'});kind='linked_records'
 else:
  roots=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json')) if json.loads(Path(p).read_text()).get('scenario')==s]
  if len(roots)!=1:raise RuntimeError('Expected exactly one Capture-8-1 clean replay.')
  root=roots[0];conn=parse_zeek(root/'clean_replay/conn.log');mapping=pd.read_csv(root/'unique_exact_key_mapping.csv',dtype=str)
  labels={(int(a),b,c,e,f,g.lower()):l for a,b,c,e,f,g,l in zip(mapping.timestamp_microseconds,mapping.orig_h,mapping.orig_p,mapping.resp_h,mapping.resp_p,mapping.proto,mapping.published_label)}
  keys=[zkey(a,b,c,d,e,f) for a,b,c,d,e,f in zip(conn.ts,conn['id.orig_h'],conn['id.orig_p'],conn['id.resp_h'],conn['id.resp_p'],conn.proto)]
  conn['label']=[labels.get(k) for k in keys]
  if conn.label.isna().any():raise RuntimeError('Capture-8-1 clean replay has unmatched published-label keys.')
  missing=set(FEATURES)-set(conn.columns)
  if missing:raise RuntimeError('Capture-8-1 conn.log missing required stable fields: '+str(sorted(missing)))
  raw=conn[FEATURES+['label']].copy();path=root/'clean_replay/conn.log';kind='clean_replay_conn_log_plus_exact_label_mapping'
 balanced,full=cap(raw,s)
 return balanced,{'scenario':s,'source_path':str(path),'source_sha256':sha(path),'source_kind':kind,'raw_rows':len(full),'balanced_rows':len(balanced),'benign_raw':int((full.y==0).sum()),'malicious_raw':int((full.y==1).sum())}
frames=[];sources=[]
for s in expected:
 x,m=read_source(s);frames.append(x);sources.append(m)
source=pd.concat(frames,ignore_index=True);train_parts=[];test_parts=[]
for s in expected:
 for y in (0,1):
  x=source[(source.scenario==s)&(source.y==y)].sample(frac=1,random_state=8100+expected.index(s)*10+y);n=max(1,int(.8*len(x)));train_parts.append(x.iloc[:n]);test_parts.append(x.iloc[n:])
train=pd.concat(train_parts,ignore_index=True);test=pd.concat(test_parts,ignore_index=True)
OUT.mkdir();models={};metrics=[]
for seed in SEEDS:
 bank={}
 for name,cols in {'PRIMARY':FEATURES,**VIEWS}.items():
  clf=HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,random_state=seed).fit(onehot(train,cols),train.y);bank[name]=clf
  p=clf.predict_proba(onehot(test,cols))[:,1];pred=(p>=.5).astype(int);metrics.append({'seed':seed,'model':name,'features':'|'.join(cols),'rows':len(test),'accuracy':accuracy_score(test.y,pred),'balanced_accuracy':balanced_accuracy_score(test.y,pred),'AUROC':roc_auc_score(test.y,p)})
 models[seed]=bank
joblib.dump({'protocol_sha256':sha(PROTO),'feature_schema':FEATURES,'views':VIEWS,'seeds':SEEDS,'models':models,'source_train_metadata':sources},OUT/'frozen_source_models.joblib')
pd.DataFrame(sources).to_csv(OUT/'source_data_manifest.csv',index=False);pd.DataFrame(metrics).to_csv(OUT/'source_model_diagnostics.csv',index=False)
receipt={'output_directory':str(OUT),'supersedes_failed_source_script':True,'protocol_sha256':sha(PROTO),'source_scenarios':expected,'source_rows_train':len(train),'source_rows_test':len(test),'seeds':SEEDS,'models_trained':True,'target_pcap_or_log_opened':False,'target_predictions_computed':False,'target_outcomes_inspected':False,'attacks_executed':False,'NF_changed':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nSOURCE DATA MANIFEST');print(pd.DataFrame(sources).to_string(index=False));print('\nSOURCE MODEL DIAGNOSTICS');print(pd.DataFrame(metrics).round(4).to_string(index=False))
