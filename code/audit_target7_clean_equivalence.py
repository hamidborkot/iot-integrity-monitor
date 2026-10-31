"""Read-only Target 7 clean-feature equivalence audit. No attack, replay, model fitting or protocol change.
Compares the exact frozen 1,024-record target sample in E1 features.csv.gz with the matching existing clean conn.log.gz,
then replays frozen source models on BOTH representations. This diagnoses the clean=0.499 vs transformed=0.998 discrepancy.
"""
import gzip,hashlib,json
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import joblib,numpy as np,pandas as pd
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';ASSET=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1_2/target_asset_resolution.csv';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';OUT=WORK/'TRACE_TARGET7_CLEAN_EQUIVALENCE_AUDIT'
if OUT.exists():raise RuntimeError('Audit directory already exists; do not overwrite.')
P=json.loads(PROTO.read_text());a=pd.read_csv(ASSET);a=a[(a.scenario=='CTU-IoT-Malware-Capture-7-1')&(a.status=='RESOLVED')]
if len(a)!=1:raise RuntimeError('Frozen Target 7 assets unavailable.')
a=a.iloc[0];F=P['source_detector']['primary_features'];N=P['evaluation_sampling']['per_target_per_class_records']
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def k(ts,o,op,r,rp,pr):return (int((Decimal(str(ts))*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),str(o),str(op),str(r),str(rp),str(pr).lower())
def skey(x,sep='|'):return sep.join(map(str,x))
def sample():
 heaps={0:[],1:[]}
 import heapq
 for ch in pd.read_csv(a.features_path,compression='gzip',chunksize=250000):
  for r in ch.itertuples(index=False):
   d=r._asdict();y=int(d['y']);ks=str(d['ks']);hv=int(hashlib.sha256((str(P['version'])+ks).encode()).hexdigest(),16);item=(-hv,ks,d);h=heaps[y]
   if len(h)<N:heapq.heappush(h,item)
   elif item[0]>h[0][0]:heapq.heapreplace(h,item)
 out=[]
 for y in(0,1):out.extend(x[2]for x in heaps[y])
 df=pd.DataFrame(out);df['y']=df.y.astype(int);df['proto']=df.proto.astype(str).str.lower()
 for c in F:
  if c!='proto':df[c]=pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0)
 return df
def mat(df,cols):
 z=np.column_stack([np.log1p(pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0).to_numpy(float)) for c in cols if c!='proto'])
 if 'proto'in cols:z=np.hstack([z, np.column_stack([(df.proto.astype(str).str.lower()==p).to_numpy(float) for p in ['tcp','udp','icmp']])])
 return z
features=sample();wanted=set(features.ks.astype(str));rows=[];scores={'|':0,'::':0,',':0}
with gzip.open(a.conn_log_path,'rt',encoding='utf-8')as f:
 fields=None
 for line in f:
  if line.startswith('#fields'):fields=line.strip().split()[1:];continue
  if line.startswith('#')or not line.strip():continue
  r=dict(zip(fields,line.rstrip().split()));base=k(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto'])
  for sep in scores:scores[sep]+=skey(base,sep)in wanted
sep=max(scores,key=scores.get)
if scores[sep]==0:raise RuntimeError('Cannot resolve clean key encoding.')
with gzip.open(a.conn_log_path,'rt',encoding='utf-8')as f:
 fields=None
 for line in f:
  if line.startswith('#fields'):fields=line.strip().split()[1:];continue
  if line.startswith('#')or not line.strip():continue
  r=dict(zip(fields,line.rstrip().split()));ks=skey(k(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto']),sep)
  if ks in wanted:rows.append({**{c:r[c]for c in F},'ks':ks})
clean=pd.DataFrame(rows);clean['proto']=clean.proto.astype(str).str.lower()
for c in F:
 if c!='proto':clean[c]=pd.to_numeric(clean[c].replace('-',np.nan),errors='coerce').fillna(0).clip(lower=0)
merged=features.merge(clean,on='ks',suffixes=('_e1','_zeek'),how='outer',indicator=True)
comparison=[]
for c in F:
 if c=='proto':same=merged[f'{c}_e1'].fillna('__').eq(merged[f'{c}_zeek'].fillna('__'))
 else:same=np.isclose(pd.to_numeric(merged[f'{c}_e1'],errors='coerce').fillna(-999),pd.to_numeric(merged[f'{c}_zeek'],errors='coerce').fillna(-999))
 comparison.append({'field':c,'same_fraction':float(np.mean(same)),'different_rows':int((~same).sum())})
matched=merged[merged._merge.eq('both')].copy();zeek_df=matched[[f'{c}_zeek'for c in F]].copy();zeek_df.columns=F;zeek_df['y']=matched.y.to_numpy()
bundle=joblib.load(SOURCE);pred=[]
for seed,bank in bundle['models'].items():
 for rep,df in [('E1_features',features),('clean_conn_log',zeek_df)]:
  p=bank['PRIMARY'].predict(mat(df,F));pred.append({'seed':seed,'representation':rep,'accuracy':float((p==df.y.to_numpy()).mean()),'positive_fraction':float(p.mean()),'rows':len(df)})
OUT.mkdir();pd.DataFrame(comparison).to_csv(OUT/'field_equivalence.csv',index=False);pd.DataFrame(pred).to_csv(OUT/'source_model_clean_representation_accuracy.csv',index=False);merged.to_csv(OUT/'sample_key_join.csv',index=False)
receipt={'output_directory':str(OUT),'sample_rows_E1':len(features),'matched_clean_conn_rows':len(clean),'join_both':int((merged._merge=='both').sum()),'only_E1':int((merged._merge=='left_only').sum()),'only_clean_conn':int((merged._merge=='right_only').sum()),'key_separator':sep,'target_predictions_from_attack':False,'models_retrained':False,'attacks_executed':False,'NF_changed':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nFIELD EQUIVALENCE');print(pd.DataFrame(comparison).to_string(index=False));print('\nFROZEN SOURCE PRIMARY ON TWO CLEAN REPRESENTATIONS');print(pd.DataFrame(pred).round(4).to_string(index=False))
