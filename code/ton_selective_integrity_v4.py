# =============================================================================================
# TON-IoT SELECTIVE INTEGRITY MONITOR v4 -- COMPLETE FINAL SEMANTIC PROTOCOL
#
# PRIMARY OBJECTIVE
#   Determine whether a FROZEN PRIMARY IDS should be trusted, suspected, or abstained from,
#   without runtime labels, using provenance-aware semantic telemetry views.
#
# KEY FIXES
#   1. Two trusted support profiles: normal traffic and known source-attack traffic.
#   2. Robust MAD support score: no singular covariance / no Mahalanobis instability.
#   3. Clean normal, known source-family, zero-day, and attacked zero-day populations are separate.
#   4. Attacks modify only volume or timing evidence; context/DNS/TLS/HTTP/Zeek evidence stays fixed.
#   5. Saves after every seed. Re-run after disconnect to resume.
#
# RUN ORDER
#   RUN="smoke" -> verify.
#   RUN="development" -> exploratory results.
#   Freeze code. Then RUN="confirm", seeds 10/11/12 -> final evidence.
# =============================================================================================
import os
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.metrics import roc_auc_score, roc_curve

torch.set_num_threads(os.cpu_count() or 4)

RUN = 'smoke'  # smoke | development | confirm
SEEDS = [0] if RUN == 'smoke' else ([0, 1, 2] if RUN == 'development' else [10, 11, 12])
POOL_SEED = 0 if RUN != 'confirm' else 1
CSV = Path('/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network/TON_IoT_Train_Test_Network.csv')
OUT = Path('/kaggle/working/ton_selective_integrity_v4')
OUT.mkdir(parents=True, exist_ok=True)

SOURCE_FAMILIES = ['scanning', 'dos', 'ddos', 'password']
HELDOUT_FAMILIES = ['injection', 'xss', 'ransomware', 'backdoor', 'mitm']
VIEWS = {
    'context_state': ['proto', 'service', 'conn_state'],
    'volume': ['src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts', 'dst_pkts'],
    'timing': ['duration'],
    'dns': ['dns_query', 'dns_qclass', 'dns_qtype', 'dns_rcode', 'dns_AA', 'dns_RD', 'dns_RA', 'dns_rejected'],
    'tls': ['ssl_version', 'ssl_cipher', 'ssl_resumed', 'ssl_established', 'ssl_subject', 'ssl_issuer'],
    'http': ['http_trans_depth', 'http_method', 'http_uri', 'http_version', 'http_request_body_len', 'http_response_body_len', 'http_status_code', 'http_user_agent', 'http_orig_mime_types', 'http_resp_mime_types'],
    'zeek_anomaly': ['weird_name', 'weird_addl', 'weird_notice'],
}
if RUN == 'smoke':
    NTRAIN, NREF, NNORMAL, NSOURCE = 5000, 3000, 5000, 5000
    EPOCHS, PGD_STEPS, NWIN, WN, EPS = 3, 8, 24, 256, [.50]
else:
    NTRAIN, NREF, NNORMAL, NSOURCE = 50000, 20000, 50000, 25000
    EPOCHS, PGD_STEPS, NWIN, WN, EPS = 8, 20, 100, 256, [.10, .25, .50]

# ------------------------------------------ utilities ------------------------------------------
def cap(df, n, seed):
    return df.sample(min(n, len(df)), random_state=seed).copy()

def seed_file(seed):
    return OUT / f'ton_selective_{RUN}_pool{POOL_SEED}_seed{seed}.csv'

class MLP(nn.Module):
    def __init__(self, d, hidden):
        super().__init__()
        layers=[]; prev=d
        for h in hidden:
            layers += [nn.Linear(prev,h), nn.ReLU()]
            prev=h
        layers += [nn.Linear(prev,1)]
        self.net=nn.Sequential(*layers)
    def forward(self,x): return self.net(x).squeeze(-1)

def train_mlp(X,y,seed,hidden):
    torch.manual_seed(seed)
    model=MLP(X.shape[1],hidden)
    opt=torch.optim.Adam(model.parameters(),lr=3e-3,weight_decay=1e-4)
    loss=nn.BCEWithLogitsLoss()
    xt=torch.tensor(X,dtype=torch.float32)
    yt=torch.tensor(np.asarray(y).astype('float32'))
    for _ in range(EPOCHS):
        order=torch.randperm(len(xt))
        for i in range(0,len(xt),512):
            j=order[i:i+512]
            opt.zero_grad(); loss(model(xt[j]),yt[j]).backward(); opt.step()
    return model.eval()

@torch.no_grad()
def pprob(model,X):
    return torch.sigmoid(model(torch.tensor(X,dtype=torch.float32))).numpy()

def transform_view(tr, nref, kref, ntest, stest, ztest, cols):
    cols=[c for c in cols if c in tr.columns]
    num=[c for c in cols if pd.api.types.is_numeric_dtype(tr[c])]
    cat=[c for c in cols if c not in num]
    outputs=[[],[],[],[],[],[]]; scaler=None
    data=[tr,nref,kref,ntest,stest,ztest]
    if num:
        scaler=StandardScaler().fit(tr[num].fillna(0))
        for df,out in zip(data,outputs): out.append(scaler.transform(df[num].fillna(0)))
    if cat:
        enc=OneHotEncoder(handle_unknown='ignore',sparse_output=False).fit(tr[cat].fillna('-').astype(str))
        for df,out in zip(data,outputs): out.append(enc.transform(df[cat].fillna('-').astype(str)))
    if not outputs[0]: raise RuntimeError(f'No usable features: {cols}')
    return tuple(np.hstack(x).astype('float32') for x in outputs), dict(num=num,cat=cat,scaler=scaler,dim=sum(x.shape[1] for x in outputs[0]))

def prepare_all(tr,nref,kref,ntest,stest,ztest):
    XV={}; meta={}
    for n,c in VIEWS.items(): XV[n],meta[n]=transform_view(tr,nref,kref,ntest,stest,ztest,c)
    names=list(VIEWS)
    XP=tuple(np.hstack([XV[n][i] for n in names]).astype('float32') for i in range(6))
    off={}; q=0
    for n in names: off[n]=(q,q+meta[n]['dim']); q+=meta[n]['dim']
    return XV,meta,XP,off

# -------------------------------------- monitor support --------------------------------------
def monitor_features(p0,pv,p0ref,pvref):
    f=[p0.mean(),np.maximum(p0,1-p0).mean()]
    for i in range(len(pv)):
        f += [(pv[i]>.5).mean(),((pv[i]>.5)==(p0>.5)).mean(),abs((pv[i]>.5).mean()-(pvref[i]>.5).mean())]
    pa=[((pv[i]>.5)==(pv[j]>.5)).mean() for i in range(len(pv)) for j in range(i+1,len(pv))]
    return np.asarray(f+[np.mean(pa),np.min(pa),np.std(pa),abs((p0>.5).mean()-(p0ref>.5).mean())],dtype='float32')

def integrity_weights(pvref,pv):
    drift=(pvref>.5).mean(1)-(pv>.5).mean(1)
    weights=np.exp(-(np.maximum(drift-np.quantile(drift,.20),0)/.05)**2)
    return weights,drift

def robust_profile(feature_windows):
    med=np.median(feature_windows,axis=0)
    mad=1.4826*np.median(np.abs(feature_windows-med),axis=0)+1e-6
    def score(X): return np.mean(np.abs((X-med)/mad),axis=-1)
    ref=score(feature_windows)
    return dict(median=med,mad=mad,threshold=float(np.quantile(ref,.99)))

def score_profile(feat,profile):
    return float(np.mean(np.abs((feat-profile['median'])/profile['mad'])))

def windows(n,count,size,seed):
    rng=np.random.default_rng(seed)
    return [rng.choice(n,min(size,n),replace=False) for _ in range(count)]

def profile_windows(p0,pv,p0ref,pvref,seed):
    return np.asarray([monitor_features(p0[ix],pv[:,ix],p0ref,pvref) for ix in windows(len(p0),NWIN,WN,seed)])

def gap_threshold(pvref,seed):
    gaps=[]
    for ix in windows(pvref.shape[1],NWIN,WN,seed):
        w,_=integrity_weights(pvref,pvref[:,ix]); sw=np.sort(w); gaps.append(float(sw[1]-sw[0]))
    return float(np.quantile(gaps,.99))

# ------------------------------------------ attacks ------------------------------------------
def constrain_segment(seg,lo,hi,mean,std,integer_idx):
    seg=torch.maximum(torch.minimum(seg,hi),lo)
    raw=seg*std+mean
    if integer_idx: raw[:,integer_idx]=torch.round(raw[:,integer_idx])
    raw=torch.clamp(raw,min=0)
    seg=(raw-mean)/std
    return torch.maximum(torch.minimum(seg,hi),lo)

def attack(primary,views,Xp,Xcurrent,y,offs,meta,target,eps,mode,seed,pvref):
    n=len(Xp)
    assert all(len(Xcurrent[k])==n for k in views), f'ROW MISMATCH: primary={n}, views={[ (k,len(v)) for k,v in Xcurrent.items() ]}'
    torch.manual_seed(seed)
    a,b=offs[target]
    x0=torch.tensor(Xp,dtype=torch.float32); x=x0.clone(); yt=torch.tensor(np.asarray(y).astype('float32')); idx=torch.where(yt==1)[0]
    lo=x0[:,a:b].min(0).values; hi=x0[:,a:b].max(0).values
    scaler=meta[target]['scaler']
    if scaler is None: raise RuntimeError(f'{target} is not numeric')
    mean=torch.tensor(scaler.mean_,dtype=torch.float32); std=torch.tensor(scaler.scale_,dtype=torch.float32)
    integer_idx=list(range(b-a)) if target=='volume' else []
    with torch.no_grad(): fixed={k:torch.sigmoid(m(torch.tensor(Xcurrent[k],dtype=torch.float32))) for k,m in views.items() if k!=target}
    pref_rate=torch.tensor((pvref>.5).mean(1),dtype=torch.float32)
    for _ in range(PGD_STEPS):
        x.requires_grad_(True)
        p0=torch.sigmoid(primary(x)); obj=F.binary_cross_entropy(p0[idx],yt[idx])
        if mode=='adaptive':
            pv=torch.stack([torch.sigmoid(m(x[:,a:b])) if k==target else fixed[k] for k,m in views.items()])
            dr=pref_rate-torch.sigmoid(10*(pv-.5)).mean(1)
            w=torch.exp(-(torch.relu(dr-torch.quantile(dr,.20))/.05)**2)
            vv=2*pv-1; loo=(w[:,None]*vv).sum(0,keepdim=True)-w[:,None]*vv
            integrity=torch.sigmoid(10*vv*loo).mean()
            obj=obj-30*(integrity-.8)**2
        g,=torch.autograd.grad(obj,x)
        x=x.detach()
        step=2*eps/PGD_STEPS
        x[:,a:b]=constrain_segment((x[:,a:b]+step*g[:,a:b].sign()).clamp(x0[:,a:b]-eps,x0[:,a:b]+eps),lo,hi,mean,std,integer_idx)
    return x.detach().numpy()

# ------------------------------------------ selective evaluation ------------------------------------------
def eval_population(primary,views,Xp,Xcurrent,y,p0ref,pvref,normal_prof,known_prof,gap_tau,normal_base,known_base,source,seed):
    p0=pprob(primary,Xp); pv=np.stack([pprob(views[k],Xcurrent[k]) for k in views]); rows=[]
    for wid,ix in enumerate(windows(len(y),NWIN,WN,seed)):
        feat=monitor_features(p0[ix],pv[:,ix],p0ref,pvref)
        sn=score_profile(feat,normal_prof); sk=score_profile(feat,known_prof)
        profile='normal' if sn<=sk else 'known'; score=min(sn,sk); tau=normal_prof['threshold'] if profile=='normal' else known_prof['threshold']
        w,d=integrity_weights(pvref,pv[:,ix]); names=list(views); suspect=names[int(np.argmin(w))]; sw=np.sort(w); gap=float(sw[1]-sw[0])
        state='trusted' if score<=tau else ('suspect' if gap>=gap_tau else 'abstain')
        true_acc=((p0[ix]>.5).astype(int)==np.asarray(y)[ix]).mean(); baseline=normal_base if profile=='normal' else known_base
        rows.append(dict(source=source,seed=seed,window=wid,true_accuracy=true_acc,baseline_accuracy=baseline,true_damage=baseline-true_acc,
                         normal_support=sn,known_support=sk,selected_profile=profile,support_score=score,state=state,suspect_view=suspect,weight_gap=gap,
                         primary_confidence=float(np.maximum(p0[ix],1-p0[ix]).mean()),volume_weight=float(w[names.index('volume')]),timing_weight=float(w[names.index('timing')]),
                         volume_drift=float(d[names.index('volume')]),timing_drift=float(d[names.index('timing')])))
    return rows

# -------------------------------------------- data --------------------------------------------
if not CSV.exists(): raise FileNotFoundError(CSV)
df=pd.read_csv(CSV,low_memory=False); df['type']=df.type.astype(str).str.lower().str.strip(); df['label']=pd.to_numeric(df.label,errors='coerce').fillna(0).astype(int)
normal=df[df.label==0]; source=df[df.type.isin(SOURCE_FAMILIES)]; held=df[df.type.isin(HELDOUT_FAMILIES)]
if source.empty or held.empty: raise RuntimeError('Family split empty: '+str(df.type.value_counts().to_dict()))
print('SOURCE:',source.type.value_counts().to_dict()); print('HELDOUT:',held.type.value_counts().to_dict()); print('NORMAL:',len(normal))

for seed in SEEDS:
    out=seed_file(seed)
    if out.exists(): print('Resuming seed',seed); continue
    npool=cap(normal,NTRAIN+NREF+NNORMAL,seed); spool=cap(source,NTRAIN+NREF+NSOURCE,seed)
    nt,nref,ntest=npool.iloc[:NTRAIN],npool.iloc[NTRAIN:NTRAIN+NREF],npool.iloc[NTRAIN+NREF:]
    at,aref,atest=spool.iloc[:NTRAIN],spool.iloc[NTRAIN:NTRAIN+NREF],spool.iloc[NTRAIN+NREF:]
    train=pd.concat([nt,at]).sample(frac=1,random_state=seed)
    known_ref=pd.concat([nref,aref]).sample(frac=1,random_state=seed+1)
    source_test=pd.concat([ntest,atest]).sample(frac=1,random_state=seed+2)
    zero_mix=pd.concat([ntest,held]).sample(frac=1,random_state=seed+3)
    XV,meta,(Xp_tr,Xp_nref,Xp_kref,Xp_ntest,Xp_source,Xp_zero),offs=prepare_all(train,nref,known_ref,ntest,source_test,zero_mix)
    primary=train_mlp(Xp_tr,train.label,seed,(96,48)); views={k:train_mlp(XV[k][0],train.label,seed*100+i,(32,16)) for i,k in enumerate(VIEWS)}
    p0n=pprob(primary,Xp_nref); pvn=np.stack([pprob(views[k],XV[k][1]) for k in views])
    p0k=pprob(primary,Xp_kref); pvk=np.stack([pprob(views[k],XV[k][2]) for k in views])
    normal_base=((p0n>.5).astype(int)==nref.label.values).mean(); known_base=((p0k>.5).astype(int)==known_ref.label.values).mean()
    normal_prof=robust_profile(profile_windows(p0n,pvn,p0n,pvn,seed)); known_prof=robust_profile(profile_windows(p0k,pvk,p0k,pvk,seed+7)); gap_tau=max(gap_threshold(pvn,seed),gap_threshold(pvk,seed+7))
    print(f'seed {seed}: normal_base={normal_base:.4f}, known_base={known_base:.4f}, normal_tau={normal_prof["threshold"]:.4f}, known_tau={known_prof["threshold"]:.4f}, gap_tau={gap_tau:.4f}')
    rows=[]
    rows+=eval_population(primary,views,Xp_ntest,{k:XV[k][3] for k in views},ntest.label,p0k,pvk,normal_prof,known_prof,gap_tau,normal_base,known_base,'clean_normal_test',seed)
    rows+=eval_population(primary,views,Xp_source,{k:XV[k][4] for k in views},source_test.label,p0k,pvk,normal_prof,known_prof,gap_tau,normal_base,known_base,'source_family_test',seed)
    rows+=eval_population(primary,views,Xp_zero,{k:XV[k][5] for k in views},zero_mix.label,p0k,pvk,normal_prof,known_prof,gap_tau,normal_base,known_base,'zero_day_mix',seed)
    for target in ['volume','timing']:
        for eps in EPS:
            for mode in ['whitebox','adaptive']:
                current={k:XV[k][5] for k in views}; xa=attack(primary,views,Xp_zero,current,zero_mix.label,offs,meta,target,eps,mode,seed,pvk)
                xadv={k:(xa[:,offs[k][0]:offs[k][1]] if k==target else XV[k][5]) for k in views}
                rr=eval_population(primary,views,xa,xadv,zero_mix.label,p0k,pvk,normal_prof,known_prof,gap_tau,normal_base,known_base,f'attack:{mode}:{target}:eps{eps}',seed)
                for r in rr: r.update(ground_truth_channel=target,attribution_correct=int(r['suspect_view']==target))
                rows+=rr
    pd.DataFrame(rows).to_csv(out,index=False); print('Saved',out)

res=pd.concat([pd.read_csv(f) for f in sorted(OUT.glob(f'ton_selective_{RUN}_seed*.csv'))],ignore_index=True)
res['collapsed']=(res.true_damage>.05).astype(int)
summary=res.groupby('source').agg(seeds=('seed','nunique'),windows=('window','size'),primary_accuracy=('true_accuracy','mean'),damage=('true_damage','mean'),
                                  trusted_coverage=('state',lambda x:(x=='trusted').mean()),abstain_rate=('state',lambda x:(x=='abstain').mean()),suspect_rate=('state',lambda x:(x=='suspect').mean()),
                                  attribution_accuracy=('attribution_correct','mean')).reset_index()
risk=[]; rec=[]
for source,g in res.groupby('source'):
    trusted=g[g.state=='trusted']; collapsed=g[g.collapsed==1]
    risk.append((source,1-trusted.true_accuracy.mean() if len(trusted) else np.nan))
    rec.append((source,(collapsed.state!='trusted').mean() if len(collapsed) else np.nan))
summary=summary.merge(pd.DataFrame(risk,columns=['source','trusted_risk']),on='source').merge(pd.DataFrame(rec,columns=['source','collapse_recall']),on='source')
summary.to_csv(OUT/'ton_selective_summary_v4.csv',index=False)
print('\n=== TON SELECTIVE INTEGRITY RESULTS v4 ==='); print(summary.round(4).to_string(index=False)); print('\nSaved:',OUT/'ton_selective_summary_v4.csv')
