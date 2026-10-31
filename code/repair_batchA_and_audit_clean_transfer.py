"""Confirmatory technical repair + clean target transfer audit. No PCAP modification, Zeek replay, attack or model fitting.
Repairs only the Batch-A attack-name metadata into NEW files; original receipts stay intact. Then evaluates frozen source models on each fixed clean target sample.
"""
import gzip,hashlib,json,heapq
from datetime import datetime,timezone
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.metrics import confusion_matrix,roc_auc_score
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';ASSETS=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1_2/target_asset_resolution.csv';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';BATCH=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1_1';OUT=WORK/'TRACE_CONFIRMATORY_REPAIR_AND_TRANSFER_v1'
if not PROTO.is_file()or not ASSETS.is_file()or not SOURCE.is_file()or not BATCH.is_dir():raise FileNotFoundError('Required frozen/Batch-A artifact missing.')
if OUT.exists():raise RuntimeError('Repair/audit output exists; do not overwrite.')
P=json.loads(PROTO.read_text());A=pd.read_csv(ASSETS);A=A[A.status.eq('RESOLVED')];F=P['source_detector']['primary_features'];N=P['evaluation_sampling']['per_target_per_class_records']
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def mat(df,cols):
 z=np.column_stack([np.log1p(pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0).to_numpy(float)) for c in cols if c!='proto'])
 if 'proto' in cols:z=np.hstack([z, np.column_stack([(df.proto.astype(str).str.lower()==q).to_numpy(float) for q in ['tcp','udp','icmp']])])
 return z
def sample(path):
 heaps={0:[],1:[]};salt=str(P['version'])
 for ch in pd.read_csv(path,compression='gzip',chunksize=250000):
  for r in ch.itertuples(index=False):
   d=r._asdict();y=int(d['y']);ks=str(d['ks']);hv=int(hashlib.sha256((salt+ks).encode()).hexdigest(),16);item=(-hv,ks,d);h=heaps[y]
   if len(h)<N:heapq.heappush(h,item)
   elif item[0]>h[0][0]:heapq.heapreplace(h,item)
 if any(len(heaps[y])<N for y in(0,1)):raise RuntimeError('Frozen sample unavailable.')
 df=pd.DataFrame([x[2]for y in(0,1)for x in heaps[y]]);df['y']=df.y.astype(int);df['proto']=df.proto.astype(str).str.lower()
 for c in F:
  if c!='proto':df[c]=pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0)
 return df
OUT.mkdir();repairs=[];batch_rows=[]
for job in sorted(BATCH.glob('CTU-*/*')):
 if not job.is_dir()or not(job/'receipt.json').is_file():continue
 old=json.loads((job/'receipt.json').read_text());attack_name=job.name
 # preserve original receipt; write a new repaired receipt and normalized compact rows.
 new=dict(old);new['attack']=attack_name;new['technical_metadata_repair']='Original attack field held a transformed-flow dictionary due to variable shadowing; corrected from immutable job directory name.'
 repaired=[]
 for row in old.get('rows',[]):
  x=dict(row);x['attack']=attack_name;repaired.append(x);batch_rows.extend(repaired)
 (OUT/f'{job.parent.name}_{attack_name}_receipt_repaired.json').write_text(json.dumps(new,indent=2))
 repairs.append({'scenario':job.parent.name,'attack':attack_name,'original_receipt_sha256':sha(job/'receipt.json'),'repaired_receipt_sha256':sha(OUT/f'{job.parent.name}_{attack_name}_receipt_repaired.json'),'rows_repaired':len(repaired)})
pd.DataFrame(repairs).to_csv(OUT/'batch_A_metadata_repair_manifest.csv',index=False);pd.DataFrame(batch_rows).to_csv(OUT/'batch_A_results_normalized.csv',index=False)
# Frozen-source target clean transfer: same protocol sample, no target transformation.
bundle=joblib.load(SOURCE);transfer=[];perseed=[]
for ar in A.itertuples(index=False):
 df=sample(ar.features_path)
 for seed,bank in bundle['models'].items():
  p=bank['PRIMARY'].predict_proba(mat(df,F))[:,1];pred=(p>=.5).astype(int);tn,fp,fn,tp=confusion_matrix(df.y,pred,labels=[0,1]).ravel()
  perseed.append({'scenario':ar.scenario,'seed':seed,'rows':len(df),'accuracy':float((pred==df.y.to_numpy()).mean()),'balanced_accuracy':float(((tn/(tn+fp))+(tp/(tp+fn)))/2),'AUROC':roc_auc_score(df.y,p),'positive_prediction_fraction':float(pred.mean()),'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp)})
ps=pd.DataFrame(perseed);ps.to_csv(OUT/'frozen_source_target_clean_transfer_per_seed.csv',index=False)
summary=ps.groupby('scenario').agg(rows=('rows','first'),accuracy_mean=('accuracy','mean'),accuracy_sd=('accuracy','std'),balanced_accuracy_mean=('balanced_accuracy','mean'),AUROC_mean=('AUROC','mean'),positive_prediction_fraction_mean=('positive_prediction_fraction','mean'),TP_mean=('TP','mean'),FN_mean=('FN','mean')).reset_index();summary.to_csv(OUT/'frozen_source_target_clean_transfer_summary.csv',index=False)
receipt={'output_directory':str(OUT),'batch_A_metadata_rows_repaired':len(batch_rows),'batch_A_original_receipts_preserved':True,'clean_targets_evaluated':len(summary),'models_retrained':False,'target_attacks_executed':False,'Zeek_rerun':False,'NF_changed':False,'next_step':'Use clean-transfer table to report natural shift. Continue only with corrected streaming target jobs, using job-directory attack metadata.'}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nREPAIRED BATCH-A METADATA');print(pd.DataFrame(repairs).to_string(index=False));print('\nFROZEN SOURCE → BLIND TARGET CLEAN TRANSFER');print(summary.round(4).to_string(index=False));print('\nTARGET 7 REPAIRED BATCH-A RESULTS');print(pd.DataFrame(batch_rows).round(4).to_string(index=False))
