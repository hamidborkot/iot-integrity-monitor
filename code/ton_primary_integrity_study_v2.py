# =============================================================================
# TON-IoT PRIMARY-DETECTOR INTEGRITY STUDY v2 -- SELF-CONTAINED AND RESUMABLE
# FIXES v1: collapse is defined RELATIVE TO CLEAN PRIMARY ACCURACY, not 1-accuracy;
#            calibration safely handles one-class outcomes; integer rounding happens in RAW units.
# Run: RUN="smoke" first, then RUN="development", then frozen RUN="confirm".
# =============================================================================
import os, time
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import roc_auc_score, mean_absolute_error

torch.set_num_threads(os.cpu_count() or 4)
RUN = "smoke"  # smoke | development | confirm
SEEDS = [0] if RUN == "smoke" else ([0,1,2] if RUN == "development" else [10,11,12])
CSV = Path('/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network/TON_IoT_Train_Test_Network.csv')
OUT = Path('/kaggle/working/ton_primary_integrity_v2'); OUT.mkdir(parents=True, exist_ok=True)
SOURCE = ['scanning','dos','ddos','password']
HELDOUT = ['injection','xss','ransomware','backdoor','mitm']
VIEWS = {
 'context_state':['proto','service','conn_state'],
 'volume':['src_bytes','dst_bytes','missed_bytes','src_pkts','dst_pkts'],
 'timing':['duration'],
 'dns':['dns_query','dns_qclass','dns_qtype','dns_rcode','dns_AA','dns_RD','dns_RA','dns_rejected'],
 'tls':['ssl_version','ssl_cipher','ssl_resumed','ssl_established','ssl_subject','ssl_issuer'],
 'http':['http_trans_depth','http_method','http_uri','http_version','http_request_body_len','http_response_body_len','http_status_code','http_user_agent','http_orig_mime_types','http_resp_mime_types'],
 'zeek_anomaly':['weird_name','weird_addl','weird_notice'],
}
if RUN == 'smoke':
    NTRAIN, NNORMAL_TEST, EPOCHS, STEPS, CAL_WINDOWS, TEST_WINDOWS, WN, EPS = 5000, 5000, 3, 8, 12, 12, 512, [.5]
else:
    NTRAIN, NNORMAL_TEST, EPOCHS, STEPS, CAL_WINDOWS, TEST_WINDOWS, WN, EPS = 50000, 50000, 8, 20, 32, 40, 512, [.1,.25,.5]

class MLP(nn.Module):
    def __init__(self,d,h=(64,32)):
        super().__init__(); L=[]; q=d
        for z in h: L += [nn.Linear(q,z),nn.ReLU()]; q=z
        self.net=nn.Sequential(*L,nn.Linear(q,1))
    def forward(self,x): return self.net(x).squeeze(-1)

class ConstantCollapse:
    def __init__(self,p): self.p=float(p)
    def predict_proba(self,X): return np.tile([1-self.p,self.p],(len(X),1))

def cap(df,n,seed): return df.sample(min(n,len(df)),random_state=seed).copy()
def pprob(model,X):
    with torch.no_grad(): return torch.sigmoid(model(torch.tensor(X,dtype=torch.float32))).numpy()
def train(X,y,seed,h=(64,32)):
    torch.manual_seed(seed); m=MLP(X.shape[1],h); opt=torch.optim.Adam(m.parameters(),lr=3e-3,weight_decay=1e-4); loss=nn.BCEWithLogitsLoss()
    xt=torch.tensor(X,dtype=torch.float32); yt=torch.tensor(np.asarray(y).astype('float32'))
    for _ in range(EPOCHS):
        idx=torch.randperm(len(xt))
        for i in range(0,len(xt),512):
            j=idx[i:i+512]; opt.zero_grad(); loss(m(xt[j]),yt[j]).backward(); opt.step()
    return m.eval()

def make_view(tr,va,te,cols):
    cols=[c for c in cols if c in tr.columns]; num=[c for c in cols if pd.api.types.is_numeric_dtype(tr[c])]; cat=[c for c in cols if c not in num]
    a=[]; b=[]; c=[]; scaler=None
    if num:
        scaler=StandardScaler().fit(tr[num].fillna(0)); a.append(scaler.transform(tr[num].fillna(0))); b.append(scaler.transform(va[num].fillna(0))); c.append(scaler.transform(te[num].fillna(0)))
    if cat:
        enc=OneHotEncoder(handle_unknown='ignore',sparse_output=False).fit(tr[cat].fillna('-').astype(str)); a.append(enc.transform(tr[cat].fillna('-').astype(str))); b.append(enc.transform(va[cat].fillna('-').astype(str))); c.append(enc.transform(te[cat].fillna('-').astype(str)))
    return np.hstack(a).astype('float32'),np.hstack(b).astype('float32'),np.hstack(c).astype('float32'),dict(num=num,cat=cat,scaler=scaler,dim=sum(x.shape[1] for x in a))

def build_inputs(tr,va,te):
    xv={}; meta={}
    for n,cols in VIEWS.items(): xv[n]=make_view(tr,va,te,cols); meta[n]=xv[n][3]
    names=list(VIEWS); primary=tuple(np.hstack([xv[n][i] for n in names]).astype('float32') for i in range(3)); offs={}; q=0
    for n in names: offs[n]=(q,q+meta[n]['dim']); q+=meta[n]['dim']
    return xv,meta,primary,offs

def estimate(Pref,P):
    dr=(Pref>.5).mean(1)-(P>.5).mean(1); w=np.exp(-(np.maximum(dr-np.quantile(dr,.2),0)/.05)**2); V=(P>.5).astype(int); e=[]
    for i in range(len(V)):
        ov=np.delete(V,i,0); ow=np.delete(w,i); pseudo=((ow[:,None]*ov).sum(0)>=.5*ow.sum()).astype(int); e.append((V[i]==pseudo).mean())
    return np.asarray(e),w,dr

def monitor_features(p0,pv,p0ref,pvref):
    z=[p0.mean(),np.maximum(p0,1-p0).mean()]
    for i in range(len(pv)): z += [(pv[i]>.5).mean(),((pv[i]>.5)==(p0>.5)).mean(),abs((pv[i]>.5).mean()-(pvref[i]>.5).mean())]
    pair=[((pv[i]>.5)==(pv[j]>.5)).mean() for i in range(len(pv)) for j in range(i+1,len(pv))]
    return np.asarray(z+[np.mean(pair),np.min(pair),np.std(pair),abs((p0>.5).mean()-(p0ref>.5).mean())],dtype='float32')

def constrain_raw_round(x,x0,lo,hi,raw_mean,raw_std,intidx):
    x=x.clamp(x0-.0+lo-x0+0, x0+.0+hi-x0+0) # preserve graph then range below
    x=torch.maximum(torch.minimum(x,hi),lo)
    if intidx:
        raw=x*raw_std+raw_mean; raw[:,intidx]=torch.round(raw[:,intidx]); x=(raw-raw_mean)/raw_std
    return torch.maximum(torch.minimum(x,hi),lo)

def attack(primary,views,Xp,Xv,y,offs,target,eps,mode,seed,monitor=None):
    # target is volume or timing; all other evidence views are frozen.
    torch.manual_seed(seed); a,b=offs[target]; x0=torch.tensor(Xp,dtype=torch.float32); x=x0.clone(); yt=torch.tensor(np.asarray(y).astype('float32')); idx=torch.where(yt==1)[0]
    lo=x0[:,a:b].min(0).values; hi=x0[:,a:b].max(0).values; names=VIEWS[target]
    # Raw integer conversion uses fitted volume/timing scaler.
    sc=monitor['meta'][target]['scaler']; mean=torch.tensor(sc.mean_,dtype=torch.float32) if sc is not None else torch.zeros(b-a); std=torch.tensor(sc.scale_,dtype=torch.float32) if sc is not None else torch.ones(b-a)
    intidx=[i for i,n in enumerate(names) if target=='volume' and n!='duration']; step=2*eps/STEPS; lossf=nn.BCEWithLogitsLoss()
    with torch.no_grad(): fixed={n:torch.sigmoid(m(torch.tensor(Xv[n][2],dtype=torch.float32))) for n,m in views.items() if n!=target}
    for _ in range(STEPS):
        x.requires_grad_(True); p0=torch.sigmoid(primary(x)); loss=lossf(p0[idx],yt[idx])
        if mode=='adaptive':
            pv=[]
            for n,m in views.items(): pv.append(torch.sigmoid(m(x[:,a:b])) if n==target else fixed[n])
            pv=torch.stack(pv); rate=torch.sigmoid(10*(pv-.5)).mean(1); dr=monitor['rate_ref']-rate; w=torch.exp(-(torch.relu(dr-torch.quantile(dr,.2))/.05)**2)
            vv=2*pv-1; loo=(w[:,None]*vv).sum(0,keepdim=True)-w[:,None]*vv; soft=torch.sigmoid(10*vv*loo).mean(); loss=loss-monitor['mu']*(soft-monitor['est_ref'])**2
        g,=torch.autograd.grad(loss,x); x=x.detach(); x[:,a:b]=(x[:,a:b]+step*g[:,a:b].sign()).clamp(x0[:,a:b]-eps,x0[:,a:b]+eps)
        x[:,a:b]=constrain_raw_round(x[:,a:b],x0[:,a:b],lo,hi,mean,std,intidx)
    return x.detach().numpy()

def sample_windows(n,k,wn,seed):
    rng=np.random.default_rng(seed); return [rng.choice(n,min(wn,n),replace=False) for _ in range(k)]

def fit_monitor(X,A,baseline):
    damage=baseline-np.asarray(A); cls=(damage>.05).astype(int)
    reg=Ridge(alpha=1.).fit(X,A)
    if len(np.unique(cls))<2:
        clf=ConstantCollapse(float(cls[0])); clean_scores=np.repeat(float(cls[0]),len(cls)); status='DEGENERATE_CALIBRATION_ONE_CLASS'
    else:
        clf=LogisticRegression(max_iter=1000,class_weight='balanced').fit(X,cls); clean_scores=clf.predict_proba(X[cls==0])[:,1] if np.any(cls==0) else clf.predict_proba(X)[:,1]; status='OK'
    return clf,reg,float(np.quantile(clean_scores,.90)),float(np.quantile(clean_scores,.95)),status

def eval_windows(primary,views,Xp,Xv,y,p0ref,pvref,clf,reg,ttrusted,tsuspect,baseline,source,seed):
    p0=pprob(primary,Xp); pv=np.stack([pprob(views[n],Xv[n][2]) for n in views]); rows=[]
    for wid,ix in enumerate(sample_windows(len(y),TEST_WINDOWS,WN,seed)):
        feat=monitor_features(p0[ix],pv[:,ix],p0ref,pvref); cp=float(clf.predict_proba(feat[None,:])[:,1][0]); ah=float(np.clip(reg.predict(feat[None,:])[0],0,1)); at=((p0[ix]>.5).astype(int)==np.asarray(y)[ix]).mean(); w,d=estimate(pvref,pv[:,ix]); names=list(views); sus=names[int(np.argmin(w))]
        state='suspect' if cp>=tsuspect else ('trusted' if cp<=ttrusted else 'abstain')
        rows.append(dict(source=source,seed=seed,window=wid,true_accuracy=at,estimated_accuracy=ah,true_damage=baseline-at,collapse_probability=cp,state=state,suspect_view=sus,minimum_weight=float(w.min()),volume_weight=float(w[names.index('volume')]),timing_weight=float(w[names.index('timing')]),volume_drift=float(d[names.index('volume')]),timing_drift=float(d[names.index('timing')])))
    return rows

# --------------------------------------------- data ---------------------------------------------
if not CSV.exists(): raise FileNotFoundError(CSV)
df=pd.read_csv(CSV,low_memory=False); df['type']=df.type.astype(str).str.lower().str.strip(); df['label']=pd.to_numeric(df.label,errors='coerce').fillna(0).astype(int)
normal=df[df.label==0]; source=df[df.type.isin(SOURCE)]; held=df[df.type.isin(HELDOUT)]
if source.empty or held.empty: raise RuntimeError('Missing attack families: '+str(df.type.value_counts().to_dict()))
print('SOURCE:',source.type.value_counts().to_dict()); print('HELDOUT:',held.type.value_counts().to_dict()); print('NORMAL:',len(normal))

for seed in SEEDS:
    out=OUT/f'ton_primary_{RUN}_seed{seed}.csv'
    if out.exists(): print('Resume seed',seed); continue
    ntr=cap(normal,NTRAIN,seed); atr=cap(source,NTRAIN,seed); alltr=pd.concat([ntr,atr]).sample(frac=1,random_state=seed).reset_index(drop=True); cut=int(.8*len(alltr)); tr,va=alltr.iloc[:cut],alltr.iloc[cut:]
    te=pd.concat([cap(normal.drop(ntr.index,errors='ignore'),NNORMAL_TEST,seed+99),held]).sample(frac=1,random_state=seed+99).reset_index(drop=True)
    XV,meta,(Xp_tr,Xp_va,Xp_te),offs=build_inputs(tr,va,te)
    primary=train(Xp_tr,tr.label,seed,(96,48)); views={n:train(XV[n][0],tr.label,seed*100+i,(32,16)) for i,n in enumerate(VIEWS)}
    p0ref=pprob(primary,Xp_va); pvref=np.stack([pprob(views[n],XV[n][1]) for n in views]); baseline_ref=((p0ref>.5).astype(int)==va.label.values).mean()
    # Calibration includes clean and source-family constrained attacks. Collapse is relative to clean primary accuracy.
    calX=[]; calA=[]
    for ix in sample_windows(len(va),CAL_WINDOWS,WN,seed): calX.append(monitor_features(p0ref[ix],pvref[:,ix],p0ref,pvref)); calA.append(((p0ref[ix]>.5).astype(int)==va.label.values[ix]).mean())
    for target in ['volume','timing']:
        for eps in EPS:
            for mode in ['whitebox','adaptive']:
                mon={'meta':meta,'rate_ref':torch.tensor((pvref>.5).mean(1),dtype=torch.float32),'est_ref':torch.tensor(np.mean(estimate(pvref,pvref)[0]),dtype=torch.float32),'mu':30.}
                xa=attack(primary,views,Xp_va,{n:XV[n] for n in views},va.label,offs,target,eps,mode,seed,mon); p0a=pprob(primary,xa); pva=[]
                for n in views:
                    aa,bb=offs[n]; xin=xa[:,aa:bb] if n==target else XV[n][1]; pva.append(pprob(views[n],xin))
                pva=np.stack(pva)
                for ix in sample_windows(len(va),max(4,CAL_WINDOWS//3),WN,seed+int(eps*100)):
                    calX.append(monitor_features(p0a[ix],pva[:,ix],p0ref,pvref)); calA.append(((p0a[ix]>.5).astype(int)==va.label.values[ix]).mean())
    clf,reg,ttrust,tsus,cal_status=fit_monitor(np.asarray(calX),np.asarray(calA),baseline_ref)
    rows=[]; rows+=eval_windows(primary,views,Xp_te,{n:XV[n] for n in views},te.label,p0ref,pvref,clf,reg,ttrust,tsus,baseline_ref,'clean_heldout',seed)
    for target in ['volume','timing']:
        for eps in EPS:
            for mode in ['whitebox','adaptive']:
                mon={'meta':meta,'rate_ref':torch.tensor((pvref>.5).mean(1),dtype=torch.float32),'est_ref':torch.tensor(np.mean(estimate(pvref,pvref)[0]),dtype=torch.float32),'mu':30.}
                xa=attack(primary,views,Xp_te,{n:XV[n] for n in views},te.label,offs,target,eps,mode,seed,mon); xv={}
                for n in views:
                    aa,bb=offs[n]; xv[n]=(xa[:,aa:bb],XV[n][1],XV[n][2]) if n==target else XV[n]
                rr=eval_windows(primary,views,xa,xv,te.label,p0ref,pvref,clf,reg,ttrust,tsus,baseline_ref,f'{mode}:{target}:eps{eps}',seed)
                for r in rr: r.update(ground_truth_channel=target,attribution_correct=int(r['suspect_view']==target),calibration_status=cal_status,clean_reference_accuracy=baseline_ref)
                rows+=rr
    pd.DataFrame(rows).to_csv(out,index=False); print('Finished seed',seed,out)

res=pd.concat([pd.read_csv(p) for p in sorted(OUT.glob(f'ton_primary_{RUN}_seed*.csv'))],ignore_index=True)
summary=res.groupby('source').agg(seeds=('seed','nunique'),windows=('window','size'),true_accuracy=('true_accuracy','mean'),true_damage=('true_damage','mean'),estimated_accuracy=('estimated_accuracy','mean'),collapse_probability=('collapse_probability','mean'),suspect_rate=('state',lambda x:(x=='suspect').mean()),trusted_rate=('state',lambda x:(x=='trusted').mean()),abstain_rate=('state',lambda x:(x=='abstain').mean()),attribution_accuracy=('attribution_correct','mean')).reset_index()
summary['accuracy_estimation_mae']=[np.mean(np.abs(g.estimated_accuracy-g.true_accuracy)) for _,g in res.groupby('source')]
summary.to_csv(OUT/'ton_primary_summary.csv',index=False)
print('\n=== TON PRIMARY-DETECTOR INTEGRITY RESULTS v2 ==='); print(summary.round(4).to_string(index=False)); print('\nSaved:',OUT/'ton_primary_summary.csv')
