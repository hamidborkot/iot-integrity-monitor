# E2_E3_CLEAN_SELECTIVE_CALIBRATION.py
# Complete clean calibration and natural-shift evaluation. No attacks.
import json
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
SEED=10;OUT=Path('/kaggle/working/e2_e3_clean_calibration');OUT.mkdir(parents=True,exist_ok=True)
CAP_A=3000;CAP_N=30000;MAX_A=24000;MIN_LABEL=500;SRC_FRAC=.60;TR=.50;REF=.20;FPR=.05;WINDOW=128;NREFWIN=128
PATHS={'CICIoT2023':[Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/train/train.csv'),Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/validation/validation.csv'),Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/test/test.csv')],'CICIoMT2024':[Path('/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024/train_iomt.csv'),Path('/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024/test_iomt.csv')]}
ALIASES={'CICIoT2023':{'protocol_state':['protocoltype','finflagnumber','synflagnumber','rstflagnumber','pshflagnumber','ackflagnumber','eceflagnumber','cwrflagnumber','tcp','udp','icmp'],'volume_size':['headerlength','totsum','totsize','number','min','max','avg','std'],'count_burst':['ackcount','syncount','fincount','urgcount','rstcount','magnitue','magnitude','radius','covariance','variance','weight']},'CICIoMT2024':{'protocol_state':['protocoltype','finflagnumber','synflagnumber','rstflagnumber','pshflagnumber','ackflagnumber','eceflagnumber','cwrflagnumber','tcp','udp','icmp'],'timing_rate':['duration','flowduration','rate','srate','drate','iat'],'count_burst':['ackcount','syncount','fincount','urgcount','rstcount','magnitue','magnitude','radius','covariance','variance','weight']}}
def norm(x):return ''.join(c for c in str(x).lower() if c.isalnum())
def benign(x):return 'benign' in str(x).lower() or 'normal' in str(x).lower()
def lc(d):
 x=[c for c in d if str(c).strip().lower()=='label']
 if not x:raise KeyError('No label column')
 return x[0]
def load(paths):
 keep=[];used={};rng=np.random.default_rng(SEED);lab=None
 for p in paths:
  if not p.exists():raise FileNotFoundError(p)
  for d in pd.read_csv(p,chunksize=200000,low_memory=False):
   lab=lc(d);d[lab]=d[lab].astype(str).str.strip()
   for v,g in d.groupby(lab,sort=True):
    left=(CAP_N if benign(v) else CAP_A)-used.get(v,0)
    if left<=0:continue
    if len(g)>left:g=g.sample(left,random_state=int(rng.integers(1,2**31-1)))
    keep.append(g);used[v]=used.get(v,0)+len(g)
 out=pd.concat(keep,ignore_index=True);out['_row_id']=np.arange(len(out));return out,lab
def take(d,n,seed):
 if len(d)<n:raise ValueError(f'Need {n}; found {len(d)}')
 return d.sample(n=n,random_state=seed).copy()
def split(name,raw,lab):
 raw=raw.copy();raw['_attack']=raw[lab].astype(str).str.strip();raw['label']=(~raw._attack.map(benign)).astype(int);normal=raw[raw.label.eq(0)];attack=raw[raw.label.eq(1)];cnt=attack._attack.value_counts();labels=sorted(cnt[cnt>=MIN_LABEL].index);source=labels[:int(np.ceil(len(labels)*SRC_FRAC))];held=labels[len(source):];per=min(CAP_A,MAX_A//len(labels),min(int(cnt[x]) for x in labels));a=[];b=[];c=[];z=[]
 for i,x in enumerate(labels):
  d=take(attack[attack._attack.eq(x)],per,SEED+i);(a if x in source else z).append(d.iloc[:int(per*TR)] if x in source else d)
  if x in source:b.append(d.iloc[int(per*TR):int(per*(TR+REF))]);c.append(d.iloc[int(per*(TR+REF)):])
 a=pd.concat(a);b=pd.concat(b);c=pd.concat(c);z=pd.concat(z);pool=take(normal,len(a)+len(b)+len(c)+len(z),SEED+999);nt=pool.iloc[:len(a)];nr=pool.iloc[len(a):len(a)+len(b)];ns=pool.iloc[len(a)+len(b):len(a)+len(b)+len(c)];nz=pool.iloc[len(a)+len(b)+len(c):]
 train=pd.concat([nt,a]).sample(frac=1,random_state=SEED);known=pd.concat([nr,b]).sample(frac=1,random_state=SEED+1);src=pd.concat([ns,c]).sample(frac=1,random_state=SEED+2);zero=pd.concat([nz,z]).sample(frac=1,random_state=SEED+3)
 features=[x for x in raw if x not in {lab,'label','_row_id','_attack'} and pd.api.types.is_numeric_dtype(raw[x])];lookup={norm(x):x for x in features};views={k:[lookup[x] for x in v if x in lookup] for k,v in ALIASES[name].items()};return train,nr,known,src,zero,features,views,source,held
def fit():return Pipeline([('impute',SimpleImputer(strategy='median')),('scale',StandardScaler()),('clf',LogisticRegression(solver='lbfgs',max_iter=2000,class_weight='balanced',random_state=SEED))])
def thr(m,X):
 p=np.sort(m.predict_proba(X)[:,1]);i=len(p)-int(np.floor(FPR*len(p)));return float(np.nextafter(p[i] if i<len(p) else p[-1],np.inf))
def pred(m,X,t):
 p=m.predict_proba(X)[:,1];return p,(p>t).astype(int)
def signature(P0,P):
 y0=(P0>.5).astype(int);y=(P>.5).astype(int);g=len(P);out=[P0.mean(),np.maximum(P0,1-P0).mean()]
 for i in range(g):out += [P[i].mean(),np.maximum(P[i],1-P[i]).mean(),(y[i]==y0).mean()]
 for i in range(g):
  for j in range(i+1,g):out.append((y[i]==y[j]).mean())
 return np.asarray(out,float)
def windows(n,count,seed):
 rng=np.random.default_rng(seed);return [rng.choice(n,min(WINDOW,n),replace=False) for _ in range(count)]
def profile(P0,P):
 R=np.vstack([signature(P0[x],P[:,x]) for x in windows(len(P0),NREFWIN,SEED)]);med=np.median(R,0);mad=1.4826*np.median(abs(R-med),0)+1e-5;score=np.mean(abs((R-med)/mad),1);return med,mad,float(np.quantile(score,.95))
def monitor(name,P0,P,profiles):
 rows=[]
 for w,i in enumerate(windows(len(P0),max(1,len(P0)//WINDOW),SEED+99)):
  s=signature(P0[i],P[:,i]);cand=[]
  for pname,(med,mad,t) in profiles.items():cand.append((np.mean(abs((s-med)/mad)),pname,t,med,mad))
  score,pname,t,med,mad=min(cand,key=lambda x:x[0]/x[2]);drift=abs((s-med)/mad);g=P.shape[0];viewdrift=np.array([drift[2+3*j] for j in range(g)]);weights=np.exp(-np.clip(viewdrift,0,8));state='trusted' if score<=t else ('suspect' if score<=1.5*t and (weights>.25).sum()>=2 else 'abstain');rows.append(dict(dataset=name,window=w,profile=pname,state=state,support_score=score,support_threshold=t,suspect_view=int(viewdrift.argmax()),min_weight=float(weights.min()),primary_accuracy=float(((P0[i]>.5).astype(int)==Y_CURRENT[i]).mean()),primary_attack_rate=float((P0[i]>.5).mean())))
 return pd.DataFrame(rows)
def run(name):
 global Y_CURRENT
 raw,lab=load(PATHS[name]);train,nr,known,src,zero,features,views,source,held=split(name,raw,lab);pm=fit();pm.fit(train[features],train.label);pt=thr(pm,nr[features]);models={};ts={}
 for v,c in views.items():models[v]=fit();models[v].fit(train[c],train.label);ts[v]=thr(models[v],nr[c])
 def probabilities(d):
  p,_=pred(pm,d[features],pt);pv=np.vstack([pred(models[v],d[views[v]],ts[v])[0] for v in views]);return p,pv
 pn,vn=probabilities(nr);pk,vk=probabilities(known);profiles={'normal':profile(pn,vn),'known':profile(pk,vk)};allrows=[]
 for splitname,d in {'clean_normal':nr,'source_family':src,'zero_day':zero}.items():
  p,v=probabilities(d);Y_CURRENT=d.label.to_numpy();r=monitor(name,p,v,profiles);r['split']=splitname;allrows.append(r)
 win=pd.concat(allrows,ignore_index=True);win.to_csv(OUT/f'{name}_window_results.csv',index=False);summary=win.groupby(['dataset','split','state']).agg(windows=('window','size'),mean_primary_accuracy=('primary_accuracy','mean'),mean_support=('support_score','mean')).reset_index();summary.to_csv(OUT/f'{name}_summary.csv',index=False);clean=win[win.split.eq('clean_normal')];decision=dict(dataset=name,views=list(views),clean_trusted_coverage=float((clean.state=='trusted').mean()),clean_false_suspect_rate=float((clean.state=='suspect').mean()),clean_false_abstain_rate=float((clean.state=='abstain').mean()),e2_e3_pass=bool((clean.state=='trusted').mean()>=.85 and (clean.state=='suspect').mean()<=.10 and (clean.state=='abstain').mean()<=.15),source_labels=source,heldout_labels=held);json.dump(decision,open(OUT/f'{name}_e2_e3_decision.json','w'),indent=2);print('\n'+'='*100);print(name,'E2/E3 CLEAN SELECTIVE MONITOR SUMMARY');print(summary.to_string(index=False));print(json.dumps(decision,indent=2));return decision
D=[run(x) for x in PATHS];pd.DataFrame(D).to_csv(OUT/'e2_e3_decisions.csv',index=False);print('\nFILES:');[print('-',x.name) for x in sorted(OUT.glob('*'))]
