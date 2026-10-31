# Complete E1.1 manual-provenance screening for CICIoT2023 + CICIoMT2024
import json, hashlib
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
SEED=10; OUT=Path('/kaggle/working/e1_1_manual_provenance'); OUT.mkdir(parents=True,exist_ok=True)
CAP_ATTACK=3000; CAP_BENIGN=30000; MAX_ATTACK_TOTAL=24000; MIN_LABEL=500; SOURCE_FRAC=.60; TRAIN_FRAC=.50; REF_FRAC=.20; TARGET_FPR=.05
MIN_DIMS=4; MIN_SOURCE=.55; MIN_ZERO=.50; MAX_FPR=.10; MIN_VIEWS=3
PATHS={'CICIoT2023':[Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/train/train.csv'),Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/validation/validation.csv'),Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/test/test.csv')],'CICIoMT2024':[Path('/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024/train_iomt.csv'),Path('/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024/test_iomt.csv')]}
ALIASES={'protocol_state':['protocoltype','finflagnumber','synflagnumber','rstflagnumber','pshflagnumber','ackflagnumber','eceflagnumber','cwrflagnumber','tcp','udp','icmp'],'application_protocol':['http','https','dns','telnet','smtp','ssh','irc','dhcp','arp','igmp','ipv','llc'],'timing_rate':['duration','flowduration','rate','srate','drate','iat'],'volume_size':['headerlength','totsum','totsize','number','min','max','avg','std'],'count_burst':['ackcount','syncount','fincount','urgcount','rstcount','magnitue','magnitude','radius','covariance','variance','weight']}
def norm(x):return ''.join(c for c in str(x).lower() if c.isalnum())
def benign(x):return 'benign' in str(x).lower() or 'normal' in str(x).lower()
def label_col(d):
 x=[c for c in d if str(c).strip().lower()=='label']
 if not x:raise KeyError('No label column');
 return x[0]
def load(paths):
 keep=[];used={};rng=np.random.default_rng(SEED);lab=None
 for p in paths:
  if not p.exists():raise FileNotFoundError(p)
  for d in pd.read_csv(p,chunksize=200000,low_memory=False):
   lab=label_col(d);d[lab]=d[lab].astype(str).str.strip()
   for v,g in d.groupby(lab,sort=True):
    cap=CAP_BENIGN if benign(v) else CAP_ATTACK;left=cap-used.get(v,0)
    if left<=0:continue
    if len(g)>left:g=g.sample(left,random_state=int(rng.integers(1,2**31-1)))
    keep.append(g);used[v]=used.get(v,0)+len(g)
 out=pd.concat(keep,ignore_index=True);out['_row_id']=np.arange(len(out));return out,lab
def take(d,n,s):
 if len(d)<n:raise ValueError(f'Need {n}, have {len(d)}')
 return d.sample(n=n,random_state=s).copy()
def hh(d):return hashlib.sha256(np.sort(d._row_id.to_numpy(np.int64)).tobytes()).hexdigest()[:20]
def check(parts):
 z=list(parts.items())
 for i,(a,x) in enumerate(z):
  for b,y in z[i+1:]:
   if set(x._row_id)&set(y._row_id):raise RuntimeError(f'LEAKAGE {a} {b}')
def model():return Pipeline([('impute',SimpleImputer(strategy='median')),('scale',StandardScaler()),('clf',LogisticRegression(solver='lbfgs',max_iter=2000,class_weight='balanced',random_state=SEED))])
def threshold(m,X):
 p=np.sort(np.asarray(m.predict_proba(X)[:,1],float));i=len(p)-int(np.floor(TARGET_FPR*len(p)));return float(np.nextafter(p[i] if 0<=i<len(p) else p[-1],np.inf))
def score(m,X,y,t,name):
 p=m.predict_proba(X)[:,1];q=(p>t).astype(int);y=np.asarray(y,int);n=y==0;a=y==1
 return dict(split=name,rows=len(y),attack_fraction=float(y.mean()),threshold=t,accuracy=float(accuracy_score(y,q)),balanced_accuracy=float(balanced_accuracy_score(y,q)),f1=float(f1_score(y,q,zero_division=0)),normal_false_positive_rate=float(q[n].mean()) if n.any() else np.nan,attack_recall=float(q[a].mean()) if a.any() else np.nan)
def views(features):
 lookup={norm(c):c for c in features};out={}
 used=set()
 for view,aliases in ALIASES.items():
  out[view]=[lookup[a] for a in aliases if a in lookup and lookup[a] not in used];used.update(out[view])
 out['unassigned_numeric']=[c for c in features if c not in used]
 return out
def run(name,raw,lab):
 raw=raw.copy();raw['_attack_name']=raw[lab].astype(str).str.strip();raw['label']=(~raw._attack_name.map(benign)).astype(int)
 features=[c for c in raw if c not in {lab,'label','_row_id','_attack_name'} and pd.api.types.is_numeric_dtype(raw[c])];normal=raw[raw.label.eq(0)];attack=raw[raw.label.eq(1)];cnt=attack._attack_name.value_counts();labels=sorted(cnt[cnt>=MIN_LABEL].index)
 source=labels[:int(np.ceil(len(labels)*SOURCE_FRAC))];held=labels[len(source):];per=min(CAP_ATTACK,MAX_ATTACK_TOTAL//len(labels),min(int(cnt[x]) for x in labels));ntr=int(per*TRAIN_FRAC);nref=int(per*REF_FRAC)
 st=[];sr=[];ss=[];zh=[]
 for i,x in enumerate(labels):
  d=take(attack[attack._attack_name.eq(x)],per,SEED+i)
  if x in source:st.append(d.iloc[:ntr]);sr.append(d.iloc[ntr:ntr+nref]);ss.append(d.iloc[ntr+nref:])
  else:zh.append(d)
 st=pd.concat(st);sr=pd.concat(sr);ss=pd.concat(ss);zh=pd.concat(zh);pool=take(normal,len(st)+len(sr)+len(ss)+len(zh),SEED+900);nt=pool.iloc[:len(st)];nr=pool.iloc[len(st):len(st)+len(sr)];ns=pool.iloc[len(st)+len(sr):len(st)+len(sr)+len(ss)];nz=pool.iloc[len(st)+len(sr)+len(ss):]
 check({'nt':nt,'nr':nr,'ns':ns,'nz':nz,'st':st,'sr':sr,'ss':ss,'zh':zh});train=pd.concat([nt,st]).sample(frac=1,random_state=SEED);src=pd.concat([ns,ss]).sample(frac=1,random_state=SEED+1);zero=pd.concat([nz,zh]).sample(frac=1,random_state=SEED+2)
 pd.DataFrame([dict(dataset=name,split=k,rows=len(v),attack_fraction=float(v.label.mean()),row_id_sha256=hh(v)) for k,v in {'train':train,'normal_reference':nr,'source_test':src,'zero_test':zero}.items()]).to_csv(OUT/f'{name}_split_manifest.csv',index=False)
 pm=model();pm.fit(train[features],train.label);pt=threshold(pm,nr[features]);primary=pd.DataFrame([dict(dataset=name,**score(pm,x[features],x.label,pt,k)) for k,x in {'clean_normal_reference':nr,'source_family_test':src,'balanced_zero_day_test':zero}.items()]);primary.to_csv(OUT/f'{name}_primary_results.csv',index=False)
 rows=[];schema=[]
 for view,use in views(features).items():
  schema += [dict(dataset=name,feature=c,semantic_view=view) for c in use];r=dict(dataset=name,view=view,raw_feature_count=len(use),status='FAIL',failure_reason='')
  try:
   m=model();m.fit(train[use],train.label);t=threshold(m,nr[use]);a=score(m,nr[use],nr.label,t,'clean');b=score(m,src[use],src.label,t,'source');c=score(m,zero[use],zero.label,t,'zero');r.update(threshold=t,transformed_feature_count=len(use),clean_normal_fpr=a['normal_false_positive_rate'],source_balanced_accuracy=b['balanced_accuracy'],source_attack_recall=b['attack_recall'],zero_day_balanced_accuracy=c['balanced_accuracy'],zero_day_attack_recall=c['attack_recall']);fail=[]
   if len(use)<MIN_DIMS:fail.append('too_few_features')
   if b['balanced_accuracy']<MIN_SOURCE:fail.append('source_balanced_accuracy_below_0.55')
   if c['balanced_accuracy']<MIN_ZERO:fail.append('zero_day_balanced_accuracy_below_0.50')
   if a['normal_false_positive_rate']>MAX_FPR:fail.append('clean_normal_fpr_above_0.10')
   r['failure_reason']='|'.join(fail);r['status']='PASS' if not fail else 'FAIL'
  except Exception as e:r['failure_reason']=f'{type(e).__name__}: {str(e)[:180]}'
  rows.append(r)
 vr=pd.DataFrame(rows);vr.to_csv(OUT/f'{name}_manual_view_results.csv',index=False);pd.DataFrame(schema).to_csv(OUT/f'{name}_manual_schema.csv',index=False);ps=primary[primary.split.eq('source_family_test')].iloc[0];pz=primary[primary.split.eq('balanced_zero_day_test')].iloc[0];pn=primary[primary.split.eq('clean_normal_reference')].iloc[0];accepted=vr[vr.status.eq('PASS')].view.tolist();decision=dict(dataset=name,experiment='E1_1_manual_provenance',pass_=bool(len(accepted)>=MIN_VIEWS and ps.balanced_accuracy>=MIN_SOURCE and pz.balanced_accuracy>=MIN_ZERO and pn.normal_false_positive_rate<=MAX_FPR),accepted_views=accepted,accepted_view_count=len(accepted),primary_source_bacc=float(ps.balanced_accuracy),primary_zero_bacc=float(pz.balanced_accuracy),primary_normal_fpr=float(pn.normal_false_positive_rate),source_labels=source,heldout_labels=held);json.dump(decision,open(OUT/f'{name}_e1_1_decision.json','w'),indent=2);print('\n'+'='*95);print(name,'PRIMARY IDS RESULTS');print(primary.round(4).to_string(index=False));print('\n'+name,'MANUAL SEMANTIC VIEW RESULTS');print(vr.round(4).to_string(index=False));print('\n'+name,'E1.1 FINAL DECISION');print(json.dumps(decision,indent=2));return decision
D=[]
for name,paths in PATHS.items():
 raw,lab=load(paths);print(name,'sampled labels:',raw[lab].value_counts().to_dict());D.append(run(name,raw,lab))
pd.DataFrame(D).to_csv(OUT/'e1_1_decisions.csv',index=False)
print('\nFILES WRITTEN:');[print('-',p.name) for p in sorted(OUT.glob('*'))]
