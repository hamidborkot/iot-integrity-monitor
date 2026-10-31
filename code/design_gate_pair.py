"""DESIGN-ONLY gate on already-inspected scenarios {1-1, 3-1, 8-1}. These scenarios become DEVELOPMENT/DESIGN data and must not be
used later as blind confirmatory targets. No confirmatory outcome, no model selection from a target other than reporting.
Exp A: shortcut/competence audit (leave-one-scenario-out). Exp B: upper bound on damage reachable by feasible primitives.
"""
import glob,itertools,json,warnings
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score,recall_score
warnings.filterwarnings('ignore')

WORK=Path('/kaggle/working');SEED=7;TRAIN_PER_CLASS=40000;ATTACK_N=50000;MIN_DAMAGE=0.05
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes']
PROTOS=['tcp','udp','icmp'];DUR=[0.0,0.1,1.0,10.0];PAD=[0,100,500,1200];INJ=[0,1,3]
OUT=WORK/('TRACE_DESIGN_GATE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
DESIGN_ONLY=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']

def clean(df):
 df=df.copy();df['proto']=df['proto'].astype(str).str.lower();df['label']=df['published_label'].astype(str).str.lower()
 df=df[df.label.isin(['benign','malicious'])]
 for c in NUM:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 df['y']=(df.label=='malicious').astype(int);return df[NUM+['proto','y']].reset_index(drop=True)
def load_linked(scenario):
 files=sorted(glob.glob(str(WORK/f'TRACE_LINKAGE_BATCH_v1/{scenario}/*/linked_records.csv')),key=lambda p:Path(p).stat().st_size,reverse=True)
 if not files:raise FileNotFoundError(scenario)
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
 dirs=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json'))
  if json.loads(Path(p).read_text()).get('scenario')=='CTU-IoT-Malware-Capture-8-1']
 if len(dirs)!=1:raise RuntimeError('Expected exactly one Capture-8-1 clean replay directory.')
 d=dirs[0];gen=parse_zeek(d/'clean_replay/conn.log');mp=pd.read_csv(d/'unique_exact_key_mapping.csv',dtype=str)
 def key(ts):return int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN))
 gen['k']=list(zip(gen.ts.map(key),gen['id.orig_h'],gen['id.orig_p'],gen['id.resp_h'],gen['id.resp_p'],gen.proto.str.lower()))
 labels={(int(a),b,c,e,f,g.lower()):l for a,b,c,e,f,g,l in zip(mp.timestamp_microseconds,mp.orig_h,mp.orig_p,mp.resp_h,mp.resp_p,mp.proto,mp.published_label)}
 gen['published_label']=gen.k.map(labels)
 if gen.published_label.isna().any():raise RuntimeError('Replay rows without exact label key.')
 return clean(gen[NUM+['proto','published_label']])
def load_all():return {s:(load_8_1() if s.endswith('8-1') else load_linked(s)) for s in DESIGN_ONLY}

def matrix(df,fs,log=False):
 parts=[]
 if fs in('ALL9','NO_PROTO'):
  x=df[NUM].to_numpy(float);parts.append(np.log1p(x) if log else x)
 if fs in('ALL9','ONLY_PROTO'):parts.append(np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS]))
 return np.hstack(parts)
def sample_train(frames):
 parts=[]
 for df in frames:
  for y in (0,1):
   part=df[df.y==y];parts.append(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED))
 return pd.concat(parts,ignore_index=True)
def fit(model,train,fs):
 if model=='HGB':
  clf=HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(matrix(train,fs),train.y);return ('HGB',clf,None)
 sc=StandardScaler().fit(matrix(train,fs,True));clf=LogisticRegression(max_iter=300,class_weight='balanced').fit(sc.transform(matrix(train,fs,True)),train.y);return ('LR',clf,sc)
def proba(bundle,df,fs):
 kind,clf,sc=bundle
 return clf.predict_proba(matrix(df,fs))[:,1] if kind=='HGB' else clf.predict_proba(sc.transform(matrix(df,fs,True)))[:,1]

def run(scenarios):
 compet=[];attack=[]
 for target,test in scenarios.items():
  train=sample_train([v for k,v in scenarios.items()if k!=target])
  if train.y.nunique()<2:raise RuntimeError('Training folds lack both classes.')
  models={}
  for fs in ['ALL9','NO_PROTO','ONLY_PROTO']:
   for m in ['HGB','LR']:
    b=fit(m,train,fs);models[(m,fs)]=b;p=proba(b,test,fs);pred=(p>=0.5).astype(int)
    both=test.y.nunique()==2
    compet.append({'held_out_target':target,'model':m,'feature_set':fs,'rows':len(test),'malicious':int(test.y.sum()),'benign':int((1-test.y).sum()),
     'accuracy':accuracy_score(test.y,pred),'balanced_accuracy':balanced_accuracy_score(test.y,pred) if both else np.nan,
     'AUROC':roc_auc_score(test.y,p) if both else np.nan,'majority_accuracy':max(test.y.mean(),1-test.y.mean()),
     'malicious_recall':recall_score(test.y,pred,pos_label=1),'benign_recall':recall_score(test.y,pred,pos_label=0)})
  mal=test[test.y==1];mal=mal.sample(min(ATTACK_N,len(mal)),random_state=SEED).reset_index(drop=True)
  idx={c:i for i,c in enumerate(NUM)};base=mal[NUM].to_numpy(float)
  for fs in ['ALL9','NO_PROTO']:
   kind,clf,_=models[('HGB',fs)]
   def predict(arr):
    d=pd.DataFrame(arr,columns=NUM);d['proto']=mal.proto.values;return clf.predict(matrix(d,fs))
   p0=predict(base);detected=p0==1
   for variant in ['liberal','conservative']:
    pace=(base[:,idx['orig_pkts']]+base[:,idx['resp_pkts']]>=2)
    pad=(base[:,idx['orig_pkts']]>=1) if variant=='liberal' else (base[:,idx['orig_bytes']]>0)
    inj=(base[:,idx['orig_pkts']]>=1) if variant=='liberal' else (base[:,idx['orig_pkts']]>=2)
    combos=list(itertools.product(DUR,PAD,INJ));preds=[]
    for d,b,k in combos:
     arr=base.copy();arr[:,idx['duration']]+=d*pace;arr[:,idx['orig_bytes']]+=b*pad
     arr[:,idx['orig_ip_bytes']]+=b*pad+40*k*inj;arr[:,idx['orig_pkts']]+=k*inj;preds.append(predict(arr))
    preds=np.array(preds)
    for primitive,keep in [('pacing_only',lambda c:c[1]==0 and c[2]==0),('padding_only',lambda c:c[0]==0 and c[2]==0),
      ('injection_only',lambda c:c[0]==0 and c[1]==0),('all_combined',lambda c:True)]:
     rows=[i for i,c in enumerate(combos)if keep(c)]
     evaded=((preds[rows]==0).any(axis=0))&detected;frac=evaded.sum()/max(detected.sum(),1)
     attack.append({'held_out_target':target,'detector_features':fs,'eligibility_variant':variant,'primitive_set':primitive,'attacked_malicious_flows':len(mal),
      'baseline_malicious_recall':detected.mean(),'evadable_fraction_of_detected':frac,'upper_bound_recall_after_attack':detected.mean()*(1-frac),
      'upper_bound_recall_drop':detected.mean()*frac,'eligible_pacing_fraction':pace.mean(),'eligible_padding_fraction':pad.mean(),'eligible_injection_fraction':inj.mean(),
      'attackable_by_declared_threshold':bool(detected.mean()*frac>=MIN_DAMAGE)})
 return pd.DataFrame(compet),pd.DataFrame(attack)

scenarios=load_all()
compet,attack=run(scenarios)
compet.to_csv(OUT/'A_shortcut_competence.csv',index=False);attack.to_csv(OUT/'B_attackable_damage_upper_bounds.csv',index=False)
receipt={'output_directory':str(OUT),'design_only_scenarios':DESIGN_ONLY,'those_scenarios_ineligible_as_blind_confirmatory_targets':True,
 'declared_damage_threshold':MIN_DAMAGE,'grid':{'duration_s':DUR,'padding_bytes':PAD,'dummy_header_packets':INJ},
 'rows_per_scenario':{k:len(v) for k,v in scenarios.items()},'confirmatory_outcome_generated':False,'protocol_frozen':False,'NF_changed':False,
 'caveat':'Feature-space upper bounds on re-extracted Zeek counters; not packet-validity proof. Binary-detector recall only; monitor not evaluated.'}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print('\nA — SHORTCUT / COMPETENCE (leave-one-scenario-out)');print(compet.round(4).to_string(index=False))
print('\nB — ATTACKABLE DAMAGE UPPER BOUNDS');print(attack.round(4).to_string(index=False))
print('\nUse: if only ONLY_PROTO is accurate, the data are shortcut-dominated; if upper-bound drops are below threshold, no attackable regime exists under these primitives.')
