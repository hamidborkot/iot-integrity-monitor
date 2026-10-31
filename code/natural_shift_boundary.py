"""NATURAL-SHIFT BOUNDARY CHECK on the three design scenarios (1-1, 3-1, 8-1), leave-one-scenario-out, NO attack.
Same estimators/views/gate as the monitor case study (declared before results): window=128, 400 windows, gate z>3 (SD floor 0.01).
Boundary variable from the plan: mean semantic-view accuracy under natural shift (threshold 0.80). Descriptive only: 3 design scenarios, no significance claim."""
import glob,json,warnings
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');SEED=7;TRAIN_PER_CLASS=40000;WINDOW=128;N_WINDOWS=400;Z_GATE=3.0;SD_FLOOR=0.01;BOUNDARY=0.80
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'];PROTOS=['tcp','udp','icmp']
VIEWS={'V_orig':(['orig_pkts','orig_bytes','orig_ip_bytes'],False),'V_resp':(['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],False),'V_time_proto':(['duration'],True)}
DESIGN=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']
def clean(df):
 df=df.copy();df['proto']=df['proto'].astype(str).str.lower();df['label']=df['published_label'].astype(str).str.lower()
 df=df[df.label.isin(['benign','malicious'])]
 for c in NUM:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 df['y']=(df.label=='malicious').astype(int);return df[NUM+['proto','y']].reset_index(drop=True)
def load_linked(s):
 files=sorted(glob.glob(str(WORK/f'TRACE_LINKAGE_BATCH_v1/{s}/*/linked_records.csv')),key=lambda p:Path(p).stat().st_size,reverse=True)
 if not files:raise FileNotFoundError(s)
 return clean(pd.read_csv(files[0],usecols=NUM+['proto','published_label'],dtype=str))
def parse_zeek(path):
 fields=None;rows=[]
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   rows.append(dict(zip(fields,line.rstrip().split())))
 return pd.DataFrame(rows)
def load_8_1():
 dirs=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json')) if json.loads(Path(p).read_text()).get('scenario')=='CTU-IoT-Malware-Capture-8-1']
 if len(dirs)!=1:raise RuntimeError('Expected one Capture-8-1 clean replay.')
 d=dirs[0];gen=parse_zeek(d/'clean_replay/conn.log');mp=pd.read_csv(d/'unique_exact_key_mapping.csv',dtype=str)
 key=lambda ts:int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN))
 labels={(int(a),b,c,e,f,g.lower()):l for a,b,c,e,f,g,l in zip(mp.timestamp_microseconds,mp.orig_h,mp.orig_p,mp.resp_h,mp.resp_p,mp.proto,mp.published_label)}
 gen['published_label']=[labels.get((key(t),o,str(op),r,str(rp),pr.lower())) for t,o,op,r,rp,pr in zip(gen['ts'],gen['id.orig_h'],gen['id.orig_p'],gen['id.resp_h'],gen['id.resp_p'],gen['proto'])]
 if gen.published_label.isna().any():raise RuntimeError('Unlabeled replay row.')
 return clean(gen[NUM+['proto','published_label']])
def load_all():return {s:(load_8_1() if s.endswith('8-1') else load_linked(s)) for s in DESIGN}
def mat(df,cols,proto):
 parts=[df[cols].to_numpy(float)]
 if proto:parts.append(np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS]))
 return np.hstack(parts)
class M:
 def __init__(self,train,cols,proto):self.cols,self.proto=cols,proto;self.clf=HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(mat(train,cols,proto),train.y)
 def proba(self,df):return self.clf.predict_proba(mat(df,self.cols,self.proto))[:,1]
 def pred(self,df):return self.clf.predict(mat(df,self.cols,self.proto))
def outputs(primary,views,df):return primary.proba(df),np.column_stack([views[n].pred(df) for n in VIEWS])
def windows(n,rng):return np.array([rng.choice(n,WINDOW,replace=False) for _ in range(N_WINDOWS)])
def reference(probs,votes,y):
 pred=(probs>=0.5).astype(int);conf=np.maximum(probs,1-probs);a=float((pred==y).mean());w=windows(len(y),np.random.default_rng(SEED+11));pr=np.array([votes[i].mean(axis=0) for i in w])
 return {'A_src':a,'conf_src':float(conf.mean()),'atc_t':float(np.quantile(conf,1-a)),'mu':pr.mean(axis=0),'sd':np.maximum(pr.std(axis=0),SD_FLOOR)}
def estimate(idx,probs,votes,y,ref):
 pred=(probs[idx]>=0.5).astype(int);conf=np.maximum(probs[idx],1-probs[idx]);v=votes[idx];acc=float((pred==y[idx]).mean())
 z=np.abs(v.mean(axis=0)-ref['mu'])/ref['sd'];gated=z>Z_GATE;maj=(v.sum(axis=1)>=2).astype(int)
 est={'AC':float(conf.mean()),'DoC':float(conf.mean()-(ref['conf_src']-ref['A_src'])),'ATC':float((conf>ref['atc_t']).mean()),'AGREE':float((pred==maj).mean())}
 keep=~gated
 if keep.any():m=v[:,keep].mean(axis=1);vote=np.where(m>0.5,1,np.where(m<0.5,0,pred));est['GATED']=float((pred==vote).mean())
 else:est['GATED']=np.nan
 return acc,est,bool(gated.any()),bool(not keep.any())
def run_target(target,scenarios):
 sources=[k for k in scenarios if k!=target];pools=[];cals=[]
 for s in sources:
  pool,cal=train_test_split(scenarios[s],test_size=0.2,stratify=scenarios[s].y,random_state=SEED);pools.append(pool.reset_index(drop=True));cals.append(cal.reset_index(drop=True))
 parts=[]
 for df in pools:
  for y in(0,1):
   part=df[df.y==y];parts.append(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED))
 train=pd.concat(parts,ignore_index=True);cal=pd.concat(cals,ignore_index=True)
 primary=M(train,NUM,True);views={n:M(train,c,p) for n,(c,p) in VIEWS.items()}
 cp,cv=outputs(primary,views,cal);ref=reference(cp,cv,cal.y.to_numpy());test=scenarios[target];tp,tv=outputs(primary,views,test);y=test.y.to_numpy()
 view_acc={n:float((tv[:,i]==y).mean()) for i,n in enumerate(VIEWS)};primary_acc=float(((tp>=0.5).astype(int)==y).mean())
 w=windows(len(test),np.random.default_rng(SEED+3));errs={};bias={};alarms=[];aband=[]
 for idx in w:
  a,e,g,ab=estimate(idx,tp,tv,y,ref);alarms.append(g);aband.append(ab)
  for k,v in e.items():errs.setdefault(k,[]).append(v-a)
 rows=[]
 for k,d in errs.items():
  d=np.array(d);ok=~np.isnan(d);rows.append({'held_out_target':target,'estimator':k,'windows_used':int(ok.sum()),'mean_abs_error':float(np.abs(d[ok]).mean()) if ok.any() else np.nan,'mean_signed_error':float(d[ok].mean()) if ok.any() else np.nan,
   'gate_alarm_rate':float(np.mean(alarms)) if k=='GATED' else np.nan,'abstain_rate':float(np.mean(aband)) if k=='GATED' else np.nan})
 info={'held_out_target':target,'target_flows':len(test),'target_malicious_fraction':float(y.mean()),'primary_accuracy':primary_acc,**{n:v for n,v in view_acc.items()},'mean_view_accuracy':float(np.mean(list(view_acc.values()))),
  'boundary_met_mean_view_accuracy_ge_0.80':bool(np.mean(list(view_acc.values()))>=BOUNDARY),'source_reference_accuracy':ref['A_src']}
 return info,pd.DataFrame(rows)
def main():
 OUT=WORK/('TRACE_NATURAL_SHIFT_BOUNDARY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
 scenarios=load_all();infos=[];tables=[]
 for t in DESIGN:
  info,tab=run_target(t,scenarios);infos.append(info);tables.append(tab)
 info=pd.DataFrame(infos);res=pd.concat(tables,ignore_index=True)
 ac=res[res.estimator=='AC'].set_index('held_out_target').mean_abs_error;res['gain_vs_AC_mean_abs_error']=res.apply(lambda r:ac[r.held_out_target]-r.mean_abs_error,axis=1)
 info.to_csv(OUT/'target_level_boundary_variables.csv',index=False);res.to_csv(OUT/'natural_shift_estimator_errors.csv',index=False)
 receipt={'output_directory':str(OUT),'declared':{'window':WINDOW,'windows':N_WINDOWS,'gate_z':Z_GATE,'sd_floor':SD_FLOOR,'boundary_threshold':BOUNDARY},'design_scenarios':DESIGN,'attack_applied':False,
  'independent_pairs':1,'significance_claim_allowed':False,'prospective_confirmation':False}
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 print('\nTARGET-LEVEL BOUNDARY VARIABLES (leave-one-scenario-out)');print(info.round(4).to_string(index=False))
 print('\nESTIMATION ERROR UNDER NATURAL SHIFT (mean over 400 windows)');print(res.round(4).to_string(index=False))
main()
