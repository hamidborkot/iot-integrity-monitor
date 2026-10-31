"""MONITOR CASE STUDY on REAL-PACKET damage (Capture-1-1, DESIGN data; within-scenario HGB ALL9 primary detector, seed-7 split as before).
Declared before results: window=128 flows, 400 paired windows, drift gate z>3 (SD floor 0.01), views = originator counters | responder counters | timing+protocol.
Clean windows vs the SAME flows re-extracted after k REAL injected duplicate header-only packets: k=1 (real damage), k=3 (control: no damage to this detector).
Estimators: AC, DoC, ATC, output-agreement (3 views), drift-gated agreement (abstains when every view drifts). Not prospective confirmation; one scenario, one detector."""
import glob,hashlib,json,warnings
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');SEED=7;TRAIN_PER_CLASS=40000;WINDOW=128;N_WINDOWS=400;Z_GATE=3.0;SD_FLOOR=0.01;DAMAGE_FLAG=0.05
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'];PROTOS=['tcp','udp','icmp']
VIEWS={'V_orig':(['orig_pkts','orig_bytes','orig_ip_bytes'],False),'V_resp':(['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],False),'V_time_proto':(['duration'],True)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def zkey(ts,o,op,r,rp,pr):return (int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),o,str(op),r,str(rp),pr.lower())
def skey(k):return '|'.join(map(str,k))
def read_conn(path):
 fields=None;skip=0
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#'):
    skip+=1
    if line.startswith('#fields'):fields=line.rstrip('\n').split('\t')[1:]
   else:break
 if fields is None:raise ValueError('No #fields line in '+str(path))
 return pd.read_csv(path,sep='\t',comment='#',header=None,names=fields,dtype=str,keep_default_na=False),skip
def frame_from_conn(conn):
 keys=[skey(zkey(a,b,c,d,e,f)) for a,b,c,d,e,f in zip(conn['ts'],conn['id.orig_h'],conn['id.orig_p'],conn['id.resp_h'],conn['id.resp_p'],conn['proto'])]
 f=pd.DataFrame({c:pd.to_numeric(conn[c].replace('-',np.nan),errors='coerce').fillna(0.0).values for c in NUM});f['proto']=conn['proto'].str.lower().values;f['ks']=keys
 return f[~f.ks.duplicated(keep=False)].set_index('ks'),keys
def clean(df):
 df=df.copy();df['proto']=df['proto'].astype(str).str.lower();df['label']=df['published_label'].astype(str).str.lower()
 df=df[df.label.isin(['benign','malicious'])]
 for c in NUM:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 df['y']=(df.label=='malicious').astype(int);return df
def mat(df,cols,proto):
 parts=[df[cols].to_numpy(float)]
 if proto:parts.append(np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS]))
 return np.hstack(parts)
def train_idx(df):
 idx=[]
 for y in(0,1):
  part=df[df.y==y];idx.extend(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED).index.tolist())
 return idx
class Monitor:
 def __init__(self,train):
  self.primary=HGB(train,NUM,True);self.views={n:HGB(train,c,p) for n,(c,p) in VIEWS.items()}
 def outputs(self,df):
  probs=self.primary.proba(df,NUM,True);votes=np.column_stack([self.views[n].pred(df,*VIEWS[n]) for n in VIEWS]);return probs,votes
def HGB(train,cols,proto):
 return _M(HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(mat(train,cols,proto),train.y))
class _M:
 def __init__(self,clf):self.clf=clf
 def proba(self,df,cols,proto):return self.clf.predict_proba(mat(df,cols,proto))[:,1]
 def pred(self,df,cols,proto):return self.clf.predict(mat(df,cols,proto))
def windows(n,rng):return np.array([rng.choice(n,WINDOW,replace=False) for _ in range(N_WINDOWS)])
def reference(probs,votes,y):
 pred=(probs>=0.5).astype(int);conf=np.maximum(probs,1-probs);a_src=float((pred==y).mean());rng=np.random.default_rng(SEED+11);w=windows(len(y),rng)
 pr=np.array([votes[i].mean(axis=0) for i in w])
 return {'A_src':a_src,'conf_src':float(conf.mean()),'atc_t':float(np.quantile(conf,1-a_src)),'mu':pr.mean(axis=0),'sd':np.maximum(pr.std(axis=0),SD_FLOOR)}
def estimate(idx,probs,votes,y,ref):
 pred=(probs[idx]>=0.5).astype(int);conf=np.maximum(probs[idx],1-probs[idx]);v=votes[idx];yy=y[idx];acc=float((pred==yy).mean())
 z=np.abs(v.mean(axis=0)-ref['mu'])/ref['sd'];gated=z>Z_GATE;maj=(v.sum(axis=1)>=2).astype(int)
 est={'AC':float(conf.mean()),'DoC':float(conf.mean()-(ref['conf_src']-ref['A_src'])),'ATC':float((conf>ref['atc_t']).mean()),'AGREE':float((pred==maj).mean())}
 keep=~gated
 if keep.any():
  m=v[:,keep].mean(axis=1);vote=np.where(m>0.5,1,np.where(m<0.5,0,pred));est['GATED']=float((pred==vote).mean())
 else:est['GATED']=np.nan
 return acc,est,bool(gated.any()),bool(not keep.any())
def evaluate(clean_out,att_out,y,ref,w):
 rows=[];accs0=[];accs1=[];e0={};e1={};al0=[];al1=[];ab0=[];ab1=[]
 for idx in w:
  a0,s0,g0,b0=estimate(idx,*clean_out,y,ref);a1,s1,g1,b1=estimate(idx,*att_out,y,ref);accs0.append(a0);accs1.append(a1);al0.append(g0);al1.append(g1);ab0.append(b0);ab1.append(b1)
  for k in s0:e0.setdefault(k,[]).append(s0[k]);e1.setdefault(k,[]).append(s1[k])
 accs0=np.array(accs0);accs1=np.array(accs1);true_drop=accs0-accs1;flag=true_drop>=DAMAGE_FLAG;out=[]
 for k in e0:
  a0=np.array(e0[k]);a1=np.array(e1[k]);ok=~(np.isnan(a0)|np.isnan(a1));d=(a0-accs0)-(a1-accs1);est_drop=a0-a1
  auc=roc_auc_score(flag[ok],est_drop[ok]) if ok.sum()>5 and flag[ok].min()!=flag[ok].max() else np.nan
  out.append({'estimator':k,'windows_used':int(ok.sum()),'mean_true_accuracy_drop':float(true_drop.mean()),'mean_estimated_drop':float(est_drop[ok].mean()) if ok.any() else np.nan,
   'mean_differential_error':float(np.abs(d[ok]).mean()) if ok.any() else np.nan,'AUROC_detect_damage_ge_5pp':auc,
   'gate_alarm_rate_clean':float(np.mean(al0)) if k=='GATED' else np.nan,'gate_alarm_rate_attacked':float(np.mean(al1)) if k=='GATED' else np.nan,
   'abstain_rate_clean':float(np.mean(ab0)) if k=='GATED' else np.nan,'abstain_rate_attacked':float(np.mean(ab1)) if k=='GATED' else np.nan})
 return pd.DataFrame(out),float(accs0.mean()),float(accs1.mean())
def main():
 OUT=WORK/('TRACE_MONITOR_CASE_STUDY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
 receipts=[(p,json.loads(p.read_text())) for p in WORK.glob('TRACE_LINKAGE_BATCH_v1/CTU-IoT-Malware-Capture-1-1/*/candidate_receipt.json')]
 receipts=[(p,r) for p,r in receipts if r.get('status')=='FULL_LOG_LINKAGE_COMPUTED' and r.get('scenario')=='CTU-IoT-Malware-Capture-1-1']
 if len(receipts)!=1:raise RuntimeError('Expected exactly one completed Capture-1-1 receipt.')
 rpath,rec=receipts[0];conn_path=rpath.parent/'replay/conn.log';linked=Path(rec['linked_records_path'])
 if sha(linked)!=rec['linked_records_sha256'] or not conn_path.is_file() or sha(conn_path)!=rec['generated_log_sha256']:raise RuntimeError('Linked records or generated conn.log missing/changed.')
 inj_dirs=sorted(WORK.glob('TRACE_PACKET_INJECTION_1_1_*'))
 if not inj_dirs:raise RuntimeError('Run the real-packet injection experiment first.')
 inj=inj_dirs[-1];att_logs={k:inj/f'injection_{k}/conn.log' for k in (1,3)}
 for p in att_logs.values():
  if not p.is_file():raise FileNotFoundError(p)
 conn,skip=read_conn(conn_path);_,keys=frame_from_conn(conn);key_by_line={skip+1+r:keys[r] for r in range(len(keys))}
 lk=clean(pd.read_csv(linked,usecols=NUM+['proto','published_label','generated_line'],dtype=str))[NUM+['proto','y','generated_line']].reset_index(drop=True);lk['generated_line']=lk.generated_line.astype(int)
 lk['ks']=lk.generated_line.map(key_by_line)
 a,b=train_test_split(lk,test_size=0.5,stratify=lk.y,random_state=SEED);a=a.reset_index(drop=True);b=b.reset_index(drop=True)
 tidx=train_idx(a);train=a.loc[tidx].reset_index(drop=True);cal=a.drop(index=tidx).reset_index(drop=True)
 monitor=Monitor(train);cal_out=monitor.outputs(cal);ref=reference(*cal_out,cal.y.to_numpy())
 rows=[];summary=[]
 for k,path in att_logs.items():
  frame,_=frame_from_conn(read_conn(path)[0]);bb=b[b.ks.isin(frame.index)].reset_index(drop=True);dropped=len(b)-len(bb)
  att=frame.loc[bb.ks.tolist()].reset_index(drop=True);att['y']=bb.y.values
  clean_out=monitor.outputs(bb);att_out=monitor.outputs(att);w=windows(len(bb),np.random.default_rng(SEED+k))
  table,acc0,acc1=evaluate(clean_out,att_out,bb.y.to_numpy(),ref,w);table.insert(0,'injected_packets_per_flow',k);rows.append(table)
  summary.append({'injected_packets_per_flow':k,'heldout_flows_used':len(bb),'heldout_flows_dropped_unmatched':dropped,'mean_window_accuracy_clean':acc0,'mean_window_accuracy_attacked':acc1,'mean_true_accuracy_drop':acc0-acc1})
 res=pd.concat(rows,ignore_index=True);sm=pd.DataFrame(summary);res.to_csv(OUT/'monitor_case_study_results.csv',index=False);sm.to_csv(OUT/'window_accuracy_summary.csv',index=False)
 receipt={'output_directory':str(OUT),'declared':{'window':WINDOW,'windows':N_WINDOWS,'gate_z':Z_GATE,'sd_floor':SD_FLOOR,'views':{k:v[0] for k,v in VIEWS.items()}},'attacked_log_source':str(inj),
  'reference_accuracy_source_split':ref['A_src'],'prospective_confirmation':False,'independent_pairs':1,'significance_claim_allowed':False,'models_for_confirmatory_use_trained':False}
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 print('\nWINDOW ACCURACY (true)');print(sm.round(4).to_string(index=False))
 print('\nMONITOR CASE STUDY (k=1 real damage; k=3 control without damage to this detector)');print(res.round(4).to_string(index=False))
main()
