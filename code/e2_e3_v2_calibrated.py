# E2_E3_V2_CALIBRATED.py -- complete clean monitor calibration (no attacks)
import json
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
SEED=10; OUT=Path("/kaggle/working/e2_e3_v2"); OUT.mkdir(parents=True,exist_ok=True)
CAPA,CAPN,MAXA,MINLAB=3000,30000,24000,500; SRC=.60; TR=.50; RF=.20; FPR=.05; W=128; NW=128
PATHS={"CICIoT2023":["/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/train/train.csv","/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/validation/validation.csv","/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23/test/test.csv"],"CICIoMT2024":["/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024/train_iomt.csv","/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024/test_iomt.csv"]}
V={"CICIoT2023":{"protocol_state":["protocoltype","finflagnumber","synflagnumber","rstflagnumber","pshflagnumber","ackflagnumber","eceflagnumber","cwrflagnumber","tcp","udp","icmp"],"volume_size":["headerlength","totsum","totsize","number","min","max","avg","std"],"count_burst":["ackcount","syncount","fincount","urgcount","rstcount","magnitue","magnitude","radius","covariance","variance","weight"]},"CICIoMT2024":{"protocol_state":["protocoltype","finflagnumber","synflagnumber","rstflagnumber","pshflagnumber","ackflagnumber","eceflagnumber","cwrflagnumber","tcp","udp","icmp"],"timing_rate":["duration","flowduration","rate","srate","drate","iat"],"count_burst":["ackcount","syncount","fincount","urgcount","rstcount","magnitue","magnitude","radius","covariance","variance","weight"]}}
def nm(x):return ''.join(c for c in str(x).lower() if c.isalnum())
def bn(x):return 'benign' in str(x).lower() or 'normal' in str(x).lower()
def lab(d):
 x=[c for c in d if str(c).strip().lower()=='label']
 if not x:raise KeyError('label missing')
 return x[0]
def load(ps):
 a=[];u={};r=np.random.default_rng(SEED);l=None
 for p in ps:
  if not Path(p).exists():raise FileNotFoundError(p)
  for d in pd.read_csv(p,chunksize=200000,low_memory=False):
   l=lab(d);d[l]=d[l].astype(str).str.strip()
   for z,g in d.groupby(l,sort=True):
    left=(CAPN if bn(z) else CAPA)-u.get(z,0)
    if left<=0:continue
    if len(g)>left:g=g.sample(left,random_state=int(r.integers(1,2**31-1)))
    a.append(g);u[z]=u.get(z,0)+len(g)
 d=pd.concat(a,ignore_index=True);d['_id']=np.arange(len(d));return d,l
def take(d,n,s):
 if len(d)<n:raise ValueError(f'need {n}, got {len(d)}')
 return d.sample(n=n,random_state=s).copy()
def split(name,d,l):
 d=d.copy();d['_a']=d[l].astype(str);d['y']=(~d._a.map(bn)).astype(int);n=d[d.y.eq(0)];a=d[d.y.eq(1)];ct=a._a.value_counts();L=sorted(ct[ct>=MINLAB].index);S=L[:int(np.ceil(len(L)*SRC))];H=L[len(S):];per=min(CAPA,MAXA//len(L),min(int(ct[x]) for x in L));A=[];B=[];C=[];Z=[]
 for i,x in enumerate(L):
  q=take(a[a._a.eq(x)],per,SEED+i);t=int(per*TR);f=int(per*(TR+RF))
  if x in S:A.append(q.iloc[:t]);B.append(q.iloc[t:f]);C.append(q.iloc[f:])
  else:Z.append(q)
 A=pd.concat(A);B=pd.concat(B);C=pd.concat(C);Z=pd.concat(Z);p=take(n,len(A)+len(B)+len(C)+len(Z),SEED+900);N0=p.iloc[:len(A)];NR=p.iloc[len(A):len(A)+len(B)];NS=p.iloc[len(A)+len(B):len(A)+len(B)+len(C)];NZ=p.iloc[len(A)+len(B)+len(C):]
 f=[c for c in d if c not in {l,'y','_id','_a'} and pd.api.types.is_numeric_dtype(d[c])];lk={nm(c):c for c in f};vw={k:[lk[x] for x in z if x in lk] for k,z in V[name].items()}
 return pd.concat([N0,A]).sample(frac=1,random_state=SEED),NR,pd.concat([NR,B]).sample(frac=1,random_state=SEED+1),pd.concat([NS,C]).sample(frac=1,random_state=SEED+2),pd.concat([NZ,Z]).sample(frac=1,random_state=SEED+3),f,vw,S,H
def clf():return Pipeline([('imp',SimpleImputer(strategy='median')),('sc',StandardScaler()),('lr',LogisticRegression(solver='lbfgs',max_iter=2000,class_weight='balanced',random_state=SEED))])
def tau(m,X):
 p=np.sort(m.predict_proba(X)[:,1]);i=len(p)-int(np.floor(FPR*len(p)));return float(np.nextafter(p[i] if i<len(p) else p[-1],np.inf))
def wins(n,s):
 r=np.random.default_rng(s);return [r.choice(n,min(W,n),replace=False) for _ in range(max(1,n//W))]
def sig(pp,pv,tp,tv,ix):
 yp=pp[ix]>tp;yv=pv[:,ix]>np.asarray(tv)[:,None];z=[yp.mean(),np.maximum(pp[ix],1-pp[ix]).mean()]
 for i in range(len(pv)):z += [yv[i].mean(),np.maximum(pv[i,ix],1-pv[i,ix]).mean(),(yv[i]==yp).mean()]
 for i in range(len(pv)):
  for j in range(i+1,len(pv)):z.append((yv[i]==yv[j]).mean())
 return np.asarray(z,float)
def prof(pp,pv,tp,tv):
 R=np.vstack([sig(pp,pv,tp,tv,x) for x in wins(len(pp),SEED)]);m=np.median(R,0);s=1.4826*np.median(abs(R-m),0)+1e-5;q=np.mean(abs((R-m)/s),1);return m,s,float(np.quantile(q,.95))
def run(name):
 d,l=load(PATHS[name]);tr,nr,kr,st,zt,fs,vs,S,H=split(name,d,l);pm=clf();pm.fit(tr[fs],tr.y);tp=tau(pm,nr[fs]);vm={};tv=[]
 for k,c in vs.items():vm[k]=clf();vm[k].fit(tr[c],tr.y);tv.append(tau(vm[k],nr[c]))
 def P(x):return pm.predict_proba(x[fs])[:,1],np.vstack([vm[k].predict_proba(x[vs[k]])[:,1] for k in vs])
 pn,vn=P(nr);pk,vk=P(kr);PR={'normal':prof(pn,vn,tp,tv),'known':prof(pk,vk,tp,tv)};rows=[]
 for split,x in {'clean_normal':nr,'source_family':st,'zero_day':zt}.items():
  pp,pv=P(x);Y=x.y.to_numpy()
  for w,ix in enumerate(wins(len(x),SEED+99)):
   q=sig(pp,pv,tp,tv,ix);cand=[]
   for n,(m,s,t) in PR.items():cand.append((np.mean(abs((q-m)/s)),n,m,s,t))
   sc,pnme,m,sd,th=min(cand,key=lambda x:x[0]/x[4]);dr=abs((q-m)/sd);vd=np.array([dr[2+3*i] for i in range(len(vs))]);wt=np.exp(-np.clip(vd,0,8));state='trusted' if sc<=th else ('suspect' if sc<=1.5*th and (wt>.25).sum()>=2 else 'abstain');yp=(pp[ix]>tp).astype(int);rows.append(dict(dataset=name,split=split,window=w,state=state,profile=pnme,support_score=sc,support_threshold=th,suspect_view=list(vs)[int(vd.argmax())],min_weight=float(wt.min()),primary_accuracy=float((yp==Y[ix]).mean()),primary_attack_rate=float(yp.mean())))
 r=pd.DataFrame(rows);r.to_csv(OUT/f'{name}_window_results.csv',index=False);su=r.groupby(['split','state']).agg(windows=('window','size'),primary_accuracy=('primary_accuracy','mean'),support=('support_score','mean')).reset_index();su.to_csv(OUT/f'{name}_summary.csv',index=False);cl=r[r.split.eq('clean_normal')];D=dict(dataset=name,primary_threshold=tp,view_thresholds=dict(zip(vs,tv)),clean_trusted_coverage=float((cl.state=='trusted').mean()),clean_false_suspect=float((cl.state=='suspect').mean()),clean_false_abstain=float((cl.state=='abstain').mean()),pass_=bool((cl.state=='trusted').mean()>=.85 and (cl.state=='suspect').mean()<=.10 and (cl.state=='abstain').mean()<=.15),views=list(vs),source_labels=S,heldout_labels=H);json.dump(D,open(OUT/f'{name}_decision.json','w'),indent=2);print('\n'+'='*90);print(name,'E2/E3-v2 SUMMARY');print(su.to_string(index=False));print(json.dumps(D,indent=2));return D
D=[run(x) for x in PATHS];pd.DataFrame(D).to_csv(OUT/'decisions.csv',index=False);print('\nFILES:');[print('-',x.name) for x in sorted(OUT.glob('*'))]
