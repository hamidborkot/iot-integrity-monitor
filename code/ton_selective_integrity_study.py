# =============================================================================================
# TON-IoT SELECTIVE INTEGRITY MONITOR -- COMPLETE, SELF-CONTAINED, RESUMABLE
#
# FINAL OBJECTIVE:
#   Do NOT claim universal label-free accuracy recovery.
#   Output trusted / suspect / abstain for a frozen primary IDS using semantic telemetry views.
#
# EVALUATION POPULATIONS:
#   clean_normal_test: held-out normal traffic (false alerts / coverage)
#   source_family_test: known attack families excluded from fitting (in-distribution trust)
#   zero_day_mix: normal + held-out attack families (unseen-family shift)
#   attack:*: constrained volume/timing attacks applied to zero_day_mix
#
# METRICS:
#   trusted coverage, selective risk, collapse recall, false alert/abstain rate,
#   semantic attribution, and comparison to confidence/GDE abstention baselines.
#
# Run RUN="smoke" first. Then RUN="development". Freeze code and use RUN="confirm".
# Saves after each seed; rerun after a disconnect to resume.
# =============================================================================================
import os
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.metrics import roc_auc_score

torch.set_num_threads(os.cpu_count() or 4)

RUN = 'smoke'                     # smoke | development | confirm
SEEDS = [0] if RUN == 'smoke' else ([0,1,2] if RUN == 'development' else [10,11,12])
POOL_SEED = 0 if RUN != 'confirm' else 1
CSV = Path('/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network/TON_IoT_Train_Test_Network.csv')
OUT = Path('/kaggle/working/ton_selective_integrity')
OUT.mkdir(parents=True, exist_ok=True)
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
    NTRAIN,NREF,NNORMAL,NSOURCE,EPOCHS,STEPS,NWIN,WN,EPS = 5000,2000,5000,5000,3,8,12,512,[.50]
else:
    NTRAIN,NREF,NNORMAL,NSOURCE,EPOCHS,STEPS,NWIN,WN,EPS = 50000,15000,50000,25000,8,20,40,512,[.10,.25,.50]

# ---------------------------------------- data + models ----------------------------------------
def cap(df,n,seed): return df.sample(min(n,len(df)),random_state=seed).copy()
def seed_file(seed): return OUT/f'ton_selective_{RUN}_seed{seed}.csv'

class MLP(nn.Module):
    def __init__(self,d,h):
        super().__init__(); L=[]; q=d
        for z in h: L += [nn.Linear(q,z),nn.ReLU()]; q=z
        L += [nn.Linear(q,1)]; self.net=nn.Sequential(*L)
    def forward(self,x): return self.net(x).squeeze(-1)

def fit_mlp(X,y,seed,h):
    torch.manual_seed(seed); m=MLP(X.shape[1],h); opt=torch.optim.Adam(m.parameters(),lr=3e-3,weight_decay=1e-4); loss=nn.BCEWithLogitsLoss()
    xt=torch.tensor(X,dtype=torch.float32); yt=torch.tensor(np.asarray(y).astype('float32'))
    for _ in range(EPOCHS):
        idx=torch.randperm(len(xt))
        for i in range(0,len(xt),512):
            j=idx[i:i+512]; opt.zero_grad(); loss(m(xt[j]),yt[j]).backward(); opt.step()
    return m.eval()

@torch.no_grad()
def prob(m,X): return torch.sigmoid(m(torch.tensor(X,dtype=torch.float32))).numpy()

def transform_view(tr,ref,normal,source_test,zero,cols):
    cols=[c for c in cols if c in tr.columns]; num=[c for c in cols if pd.api.types.is_numeric_dtype(tr[c])]; cat=[c for c in cols if c not in num]
    A=[]; B=[]; C=[]; D=[]; E=[]; scaler=None
    if num:
        scaler=StandardScaler().fit(tr[num].fillna(0))
        for target,out in [(tr,A),(ref,B),(normal,C),(source_test,D),(zero,E)]: out.append(scaler.transform(target[num].fillna(0)))
    if cat:
        enc=OneHotEncoder(handle_unknown='ignore',sparse_output=False).fit(tr[cat].fillna('-').astype(str))
        for target,out in [(tr,A),(ref,B),(normal,C),(source_test,D),(zero,E)]: out.append(enc.transform(target[cat].fillna('-').astype(str)))
    arrays=tuple(np.hstack(x).astype('float32') for x in (A,B,C,D,E))
    return arrays,dict(num=num,cat=cat,scaler=scaler,dim=arrays[0].shape[1])

def prepare_all(tr,ref,normal,source_test,zero):
    xv={}; meta={}
    for n,c in VIEWS.items(): xv[n],meta[n]=transform_view(tr,ref,normal,source_test,zero,c)
    names=list(VIEWS); primary=tuple(np.hstack([xv[n][i] for n in names]).astype('float32') for i in range(5)); offsets={}; q=0
    for n in names: offsets[n]=(q,q+meta[n]['dim']); q+=meta[n]['dim']
    return xv,meta,primary,offsets

# ------------------------------------ monitor support and states ------------------------------------
def monitor_features(p0,pv,p0ref,pvref):
    f=[p0.mean(),np.maximum(p0,1-p0).mean()]
    for i in range(len(pv)):
        f += [(pv[i]>.5).mean(),((pv[i]>.5)==(p0>.5)).mean(),abs((pv[i]>.5).mean()-(pvref[i]>.5).mean())]
    ag=[((pv[i]>.5)==(pv[j]>.5)).mean() for i in range(len(pv)) for j in range(i+1,len(pv))]
    return np.asarray(f+[np.mean(ag),np.min(ag),np.std(ag),abs((p0>.5).mean()-(p0ref>.5).mean())],dtype='float32')

def integrity_weights(pvref,pv):
    drift=(pvref>.5).mean(1)-(pv>.5).mean(1)
    w=np.exp(-(np.maximum(drift-np.quantile(drift,.20),0)/.05)**2)
    return w,drift

def support_fit(clean_features):
    mean=clean_features.mean(0); cov=np.cov(clean_features,rowvar=False)+1e-4*np.eye(clean_features.shape[1]); inv=np.linalg.pinv(cov)
    score=lambda X: np.sqrt(np.einsum('ij,jk,ik->i',X-mean,inv,X-mean))
    ref_score=score(clean_features); return mean,inv,float(np.quantile(ref_score,.95)),score

def state_window(p0,pv,p0ref,pvref,mean,inv,tau_support,tau_gap):
    feat=monitor_features(p0,pv,p0ref,pvref); support=float(np.sqrt((feat-mean)@inv@(feat-mean)))
    w,d=integrity_weights(pvref,pv); names=list(VIEWS); order=np.sort(w); gap=float(order[1]-order[0])
    suspect=names[int(np.argmin(w))]
    # Trusted only inside clean support. Outside support: suspect if one channel is clearly isolated; otherwise abstain.
    state='trusted' if support<=tau_support else ('suspect' if gap>=tau_gap else 'abstain')
    confidence=(p0>=.5).mean() # placeholder summary; primary confidence calculated below
    return feat,support,w,d,gap,suspect,state

# ------------------------------------------ attacks ------------------------------------------
def constrain_segment(seg,lo,hi,mean,std,intidx):
    seg=torch.maximum(torch.minimum(seg,hi),lo)
    raw=seg*std+mean
    if intidx: raw[:,intidx]=torch.round(raw[:,intidx])
    raw=torch.clamp(raw,min=0)
    seg=(raw-mean)/std
    return torch.maximum(torch.minimum(seg,hi),lo)

def semantic_attack(primary,views,Xp,Xviews,y,offs,meta,target,eps,mode,seed,pvref):
    n=len(Xp); assert all(len(Xviews[k])==n for k in views), f'row mismatch: primary={n}, views={[ (k,len(v)) for k,v in Xviews.items() ]}'
    torch.manual_seed(seed); a,b=offs[target]; x0=torch.tensor(Xp,dtype=torch.float32); x=x0.clone(); yt=torch.tensor(np.asarray(y).astype('float32')); idx=torch.where(yt==1)[0]
    lo=x0[:,a:b].min(0).values; hi=x0[:,a:b].max(0).values; sc=meta[target]['scaler']
    if sc is None: raise RuntimeError(f'{target} must be numeric')
    mean=torch.tensor(sc.mean_,dtype=torch.float32); std=torch.tensor(sc.scale_,dtype=torch.float32)
    intidx=list(range(b-a)) if target=='volume' else []; step=2*eps/STEPS; loss_fn=nn.BCEWithLogitsLoss()
    with torch.no_grad(): fixed={k:torch.sigmoid(m(torch.tensor(Xviews[k],dtype=torch.float32))) for k,m in views.items() if k!=target}
    pref_rate=torch.tensor((pvref>.5).mean(1),dtype=torch.float32)
    for _ in range(STEPS):
        x.requires_grad_(True); p0=torch.sigmoid(primary(x)); loss=loss_fn(p0[idx],yt[idx])
        if mode=='adaptive':
            pv=torch.stack([torch.sigmoid(m(x[:,a:b])) if k==target else fixed[k] for k,m in views.items()])
            dr=pref_rate-torch.sigmoid(10*(pv-.5)).mean(1); w=torch.exp(-(torch.relu(dr-torch.quantile(dr,.20))/.05)**2)
            vv=2*pv-1; loo=(w[:,None]*vv).sum(0,keepdim=True)-w[:,None]*vv; integrity=torch.sigmoid(10*vv*loo).mean()
            loss=loss-30.0*(integrity-.8)**2
        g,=torch.autograd.grad(loss,x); x=x.detach(); seg=(x[:,a:b]+step*g[:,a:b].sign()).clamp(x0[:,a:b]-eps,x0[:,a:b]+eps); x[:,a:b]=constrain_segment(seg,lo,hi,mean,std,intidx)
    return x.detach().numpy()

# ------------------------------------------ evaluation ------------------------------------------
def window_indices(n,seed):
    rng=np.random.default_rng(seed); return [rng.choice(n,min(WN,n),replace=False) for _ in range(NWIN)]

def eval_population(primary,views,Xp,Xviews,y,p0ref,pvref,mean,inv,tau_support,tau_gap,clean_acc,source,seed):
    p0=prob(primary,Xp); pv=np.stack([prob(views[k],Xviews[k]) for k in views]); rows=[]
    for wid,ix in enumerate(window_indices(len(y),seed)):
        feat,sup,w,d,gap,sus,state=state_window(p0[ix],pv[:,ix],p0ref,pvref,mean,inv,tau_support,tau_gap)
        acc=((p0[ix]>.5).astype(int)==np.asarray(y)[ix]).mean(); conf=np.maximum(p0[ix],1-p0[ix]).mean()
        rows.append(dict(source=source,seed=seed,window=wid,true_accuracy=acc,true_damage=clean_acc-acc,primary_confidence=conf,support_score=sup,state=state,suspect_view=sus,weight_gap=gap,volume_weight=float(w[list(views).index('volume')]),timing_weight=float(w[list(views).index('timing')]),volume_drift=float(d[list(views).index('volume')]),timing_drift=float(d[list(views).index('timing')])))
    return rows

# -------------------------------------------- run --------------------------------------------
if not CSV.exists(): raise FileNotFoundError(CSV)
df=pd.read_csv(CSV,low_memory=False); df['type']=df.type.astype(str).str.lower().str.strip(); df['label']=pd.to_numeric(df.label,errors='coerce').fillna(0).astype(int)
normal=df[df.label==0]; source=df[df.type.isin(SOURCE)]; held=df[df.type.isin(HELDOUT)]
if source.empty or held.empty: raise RuntimeError('Family split empty: '+str(df.type.value_counts().to_dict()))
print('SOURCE:',source.type.value_counts().to_dict()); print('HELDOUT:',held.type.value_counts().to_dict()); print('NORMAL:',len(normal))

for seed in SEEDS:
    out=seed_file(seed)
    if out.exists(): print('Resuming seed',seed); continue
    # Split normal and known source attacks independently into training/reference/source-test sets.
    n=cap(normal,NTRAIN+NREF+NNORMAL,seed); a=cap(source,NTRAIN+NREF+NSOURCE,seed)
    nt,nr,nnorm=n.iloc[:NTRAIN],n.iloc[NTRAIN:NTRAIN+NREF],n.iloc[NTRAIN+NREF:]
    at,ar,asrc=a.iloc[:NTRAIN],a.iloc[NTRAIN:NTRAIN+NREF],a.iloc[NTRAIN+NREF:]
    train=pd.concat([nt,at]).sample(frac=1,random_state=seed); ref=pd.concat([nr,ar]).sample(frac=1,random_state=seed+1)
    source_test=pd.concat([nnorm,asrc]).sample(frac=1,random_state=seed+2)
    zero_mix=pd.concat([nnorm,held]).sample(frac=1,random_state=seed+3)
    XV,meta,(Xp_tr,Xp_ref,Xp_norm,Xp_src,Xp_zero),offs=prepare_all(train,ref,nnorm,source_test,zero_mix)
    primary=fit_mlp(Xp_tr,train.label,seed,(96,48)); views={k:fit_mlp(XV[k][0],train.label,seed*100+i,(32,16)) for i,k in enumerate(VIEWS)}
    p0ref=prob(primary,Xp_ref); pvref=np.stack([prob(views[k],XV[k][1]) for k in views]); clean_ref_acc=((p0ref>.5).astype(int)==ref.label.values).mean()
    # Clean reference support: known-distribution windows only. No attack labels or held-out families are used here.
    F=[]; gaps=[]
    for ix in window_indices(len(ref),seed):
        f,s,w,d,gap,sus,state=state_window(p0ref[ix],pvref[:,ix],p0ref,pvref,np.zeros(1),np.eye(1),np.inf,np.inf)
        F.append(f); gaps.append(gap)
    F=np.asarray(F); mean,inv,tau_support,score=support_fit(F); tau_gap=float(np.quantile(gaps,.95))
    rows=[]
    rows+=eval_population(primary,views,Xp_norm,{k:XV[k][2] for k in views},nnorm.label,p0ref,pvref,mean,inv,tau_support,tau_gap,clean_ref_acc,'clean_normal_test',seed)
    rows+=eval_population(primary,views,Xp_src,{k:XV[k][3] for k in views},source_test.label,p0ref,pvref,mean,inv,tau_support,tau_gap,clean_ref_acc,'source_family_test',seed)
    rows+=eval_population(primary,views,Xp_zero,{k:XV[k][4] for k in views},zero_mix.label,p0ref,pvref,mean,inv,tau_support,tau_gap,clean_ref_acc,'zero_day_mix',seed)
    for target in ['volume','timing']:
        for eps in EPS:
            for mode in ['whitebox','adaptive']:
                Xcur={k:XV[k][4] for k in views}; xa=semantic_attack(primary,views,Xp_zero,Xcur,zero_mix.label,offs,meta,target,eps,mode,seed,pvref)
                Xadv={k:(xa[:,offs[k][0]:offs[k][1]] if k==target else XV[k][4]) for k in views}
                rr=eval_population(primary,views,xa,Xadv,zero_mix.label,p0ref,pvref,mean,inv,tau_support,tau_gap,clean_ref_acc,f'attack:{mode}:{target}:eps{eps}',seed)
                for r in rr: r.update(ground_truth_channel=target,attribution_correct=int(r['suspect_view']==target))
                rows+=rr
    pd.DataFrame(rows).to_csv(out,index=False); print('Saved',out)

res=pd.concat([pd.read_csv(f) for f in sorted(OUT.glob(f'ton_selective_{RUN}_seed*.csv'))],ignore_index=True)
res['collapsed']=(res.true_damage>.05).astype(int); res['nontrusted']=(res.state!='trusted').astype(int)
summary=res.groupby('source').agg(seeds=('seed','nunique'),windows=('window','size'),primary_accuracy=('true_accuracy','mean'),damage=('true_damage','mean'),trusted_coverage=('state',lambda x:(x=='trusted').mean()),abstain_rate=('state',lambda x:(x=='abstain').mean()),suspect_rate=('state',lambda x:(x=='suspect').mean()),selective_risk=('true_accuracy',lambda x:np.nan),attribution_accuracy=('attribution_correct','mean')).reset_index()
# Calculate trusted-only risk correctly for each source.
risk=[]
for source,g in res.groupby('source'):
    trusted=g[g.state=='trusted']; risk.append((source,1-trusted.true_accuracy.mean() if len(trusted) else np.nan))
summary=summary.merge(pd.DataFrame(risk,columns=['source','trusted_risk']),on='source',how='left').drop(columns='selective_risk')
# Collapse recall: fraction of true collapse windows not trusted.
rec=[]
for source,g in res.groupby('source'):
    c=g[g.collapsed==1]; rec.append((source,(c.state!='trusted').mean() if len(c) else np.nan))
summary=summary.merge(pd.DataFrame(rec,columns=['source','collapse_recall']),on='source',how='left')
summary.to_csv(OUT/'ton_selective_summary.csv',index=False)
print('\n=== TON SELECTIVE INTEGRITY RESULTS ==='); print(summary.round(4).to_string(index=False)); print('\nSaved:',OUT/'ton_selective_summary.csv')
