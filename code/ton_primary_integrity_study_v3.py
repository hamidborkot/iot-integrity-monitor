# =============================================================================================
# TON-IoT PRIMARY-DETECTOR INTEGRITY STUDY v3 -- SINGLE SELF-CONTAINED CELL
# Fixes all previous split-length errors by passing the CURRENT semantic tensors explicitly.
# A runtime assertion checks that primary and every view have the SAME row count before each attack.
# Run smoke first. Do not mix with older TON scripts or files.
# =============================================================================================
import os
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.linear_model import LogisticRegression, Ridge

torch.set_num_threads(os.cpu_count() or 4)

RUN = "smoke"  # smoke | development | confirm
SEEDS = [0] if RUN == "smoke" else ([0, 1, 2] if RUN == "development" else [10, 11, 12])
CSV = Path('/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network/TON_IoT_Train_Test_Network.csv')
OUT = Path('/kaggle/working/ton_primary_integrity_v3')
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
    NTRAIN, NNORMAL_TEST, EPOCHS, PGD_STEPS, CAL_WINDOWS, TEST_WINDOWS, WINDOW_N, EPS = 5000, 5000, 3, 8, 12, 12, 512, [.50]
else:
    NTRAIN, NNORMAL_TEST, EPOCHS, PGD_STEPS, CAL_WINDOWS, TEST_WINDOWS, WINDOW_N, EPS = 50000, 50000, 8, 20, 32, 40, 512, [.10, .25, .50]

# ------------------------------------------ utilities ------------------------------------------
def sample_cap(df, n, seed):
    return df.sample(min(n, len(df)), random_state=seed).copy()

def run_file(seed):
    return OUT / f'ton_primary_{RUN}_seed{seed}.csv'

class MLP(nn.Module):
    def __init__(self, d, hidden):
        super().__init__()
        layers=[]; q=d
        for h in hidden:
            layers += [nn.Linear(q,h), nn.ReLU()]
            q=h
        layers += [nn.Linear(q,1)]
        self.net=nn.Sequential(*layers)
    def forward(self,x):
        return self.net(x).squeeze(-1)

def train_mlp(X, y, seed, hidden, epochs=EPOCHS, batch=512):
    torch.manual_seed(seed)
    model=MLP(X.shape[1],hidden)
    opt=torch.optim.Adam(model.parameters(),lr=3e-3,weight_decay=1e-4)
    loss_fn=nn.BCEWithLogitsLoss()
    xt=torch.tensor(X,dtype=torch.float32)
    yt=torch.tensor(np.asarray(y).astype('float32'))
    for _ in range(epochs):
        order=torch.randperm(len(xt))
        for i in range(0,len(xt),batch):
            j=order[i:i+batch]
            opt.zero_grad()
            loss_fn(model(xt[j]),yt[j]).backward()
            opt.step()
    return model.eval()

@torch.no_grad()
def predict_prob(model, X):
    return torch.sigmoid(model(torch.tensor(X,dtype=torch.float32))).numpy()

def encode_view(train, val, test, cols):
    cols=[c for c in cols if c in train.columns]
    numeric=[c for c in cols if pd.api.types.is_numeric_dtype(train[c])]
    categorical=[c for c in cols if c not in numeric]
    A=[]; B=[]; C=[]; scaler=None
    if numeric:
        scaler=StandardScaler().fit(train[numeric].fillna(0))
        A.append(scaler.transform(train[numeric].fillna(0)))
        B.append(scaler.transform(val[numeric].fillna(0)))
        C.append(scaler.transform(test[numeric].fillna(0)))
    if categorical:
        enc=OneHotEncoder(handle_unknown='ignore',sparse_output=False)
        enc.fit(train[categorical].fillna('-').astype(str))
        A.append(enc.transform(train[categorical].fillna('-').astype(str)))
        B.append(enc.transform(val[categorical].fillna('-').astype(str)))
        C.append(enc.transform(test[categorical].fillna('-').astype(str)))
    if not A:
        raise RuntimeError(f'View has no usable features: {cols}')
    return tuple(np.hstack(z).astype('float32') for z in (A,B,C)), dict(numeric=numeric,categorical=categorical,scaler=scaler,dim=sum(x.shape[1] for x in A))

def prepare_dataset(train,val,test):
    XV={}; meta={}
    for name,cols in VIEWS.items():
        XV[name],meta[name]=encode_view(train,val,test,cols)
    names=list(VIEWS)
    XP=tuple(np.hstack([XV[n][i] for n in names]).astype('float32') for i in range(3))
    offsets={}; q=0
    for n in names:
        offsets[n]=(q,q+meta[n]['dim']); q+=meta[n]['dim']
    return XV,meta,XP,offsets

def estimate_views(Pref,Pcur):
    drift=(Pref>.5).mean(1)-(Pcur>.5).mean(1)
    weights=np.exp(-(np.maximum(drift-np.quantile(drift,.20),0)/.05)**2)
    votes=(Pcur>.5).astype(int); est=[]
    for i in range(len(votes)):
        ov=np.delete(votes,i,0); ow=np.delete(weights,i)
        pseudo=((ow[:,None]*ov).sum(0)>=.5*ow.sum()).astype(int)
        est.append((votes[i]==pseudo).mean())
    return np.asarray(est),weights,drift

def monitor_vector(p0,pv,p0ref,pvref):
    f=[p0.mean(),np.maximum(p0,1-p0).mean()]
    for i in range(len(pv)):
        f += [(pv[i]>.5).mean(), ((pv[i]>.5)==(p0>.5)).mean(), abs((pv[i]>.5).mean()-(pvref[i]>.5).mean())]
    pa=[((pv[i]>.5)==(pv[j]>.5)).mean() for i in range(len(pv)) for j in range(i+1,len(pv))]
    return np.asarray(f+[np.mean(pa),np.min(pa),np.std(pa),abs((p0>.5).mean()-(p0ref>.5).mean())],dtype='float32')

def enforce_raw_constraints(segment, base_segment, lo, hi, mean, scale, integer_idx):
    segment=torch.maximum(torch.minimum(segment,hi),lo)
    raw=segment*scale+mean
    if integer_idx:
        raw[:,integer_idx]=torch.round(raw[:,integer_idx])
    raw=torch.clamp(raw,min=0)
    segment=(raw-mean)/scale
    segment=torch.maximum(torch.minimum(segment,hi),lo)
    return segment

# ---------------------------------------- semantic attacks ----------------------------------------
def attack_primary(primary,views,Xprimary,Xviews,y,offsets,meta,target,eps,mode,seed,pvref,mu=30.0):
    # Critical guard: catches the exact mismatch that caused the earlier error.
    n=len(Xprimary)
    assert all(len(Xviews[name])==n for name in views), f'row mismatch: primary={n}, views={[ (k,len(v)) for k,v in Xviews.items() ]}'
    torch.manual_seed(seed)
    a,b=offsets[target]
    x0=torch.tensor(Xprimary,dtype=torch.float32); x=x0.clone()
    yt=torch.tensor(np.asarray(y).astype('float32')); attack_rows=torch.where(yt==1)[0]
    lo=x0[:,a:b].min(0).values; hi=x0[:,a:b].max(0).values
    scaler=meta[target]['scaler']
    if scaler is None: raise RuntimeError(f'Mutable view must be numeric: {target}')
    mean=torch.tensor(scaler.mean_,dtype=torch.float32); scale=torch.tensor(scaler.scale_,dtype=torch.float32)
    integer_idx=list(range(b-a)) if target=='volume' else []
    step=2*eps/PGD_STEPS; loss_fn=nn.BCEWithLogitsLoss()
    with torch.no_grad():
        fixed={name:torch.sigmoid(model(torch.tensor(Xviews[name],dtype=torch.float32))) for name,model in views.items() if name!=target}
    pref_rate=torch.tensor((pvref>.5).mean(1),dtype=torch.float32)
    ref_est=float(np.mean(estimate_views(pvref,pvref)[0]))
    for _ in range(PGD_STEPS):
        x.requires_grad_(True)
        p0=torch.sigmoid(primary(x)); loss=loss_fn(p0[attack_rows],yt[attack_rows])
        if mode=='adaptive':
            pv=[]
            for name,model in views.items():
                pv.append(torch.sigmoid(model(x[:,a:b])) if name==target else fixed[name])
            pv=torch.stack(pv)
            drift=pref_rate-torch.sigmoid(10*(pv-.5)).mean(1)
            w=torch.exp(-(torch.relu(drift-torch.quantile(drift,.20))/.05)**2)
            vv=2*pv-1; loo=(w[:,None]*vv).sum(0,keepdim=True)-w[:,None]*vv
            soft_est=torch.sigmoid(10*vv*loo).mean()
            loss=loss-mu*(soft_est-ref_est)**2
        grad,=torch.autograd.grad(loss,x)
        x=x.detach()
        adv=(x[:,a:b]+step*grad[:,a:b].sign()).clamp(x0[:,a:b]-eps,x0[:,a:b]+eps)
        x[:,a:b]=enforce_raw_constraints(adv,x0[:,a:b],lo,hi,mean,scale,integer_idx)
    return x.detach().numpy()

# -------------------------------------- monitor calibration --------------------------------------
class ConstantCollapse:
    def __init__(self,p): self.p=float(p)
    def predict_proba(self,X): return np.tile([1-self.p,self.p],(len(X),1))

def fit_monitor(features, accuracies, clean_baseline):
    damage=clean_baseline-np.asarray(accuracies)
    collapse=(damage>.05).astype(int)
    reg=Ridge(alpha=1.).fit(features,accuracies)
    if len(np.unique(collapse))<2:
        clf=ConstantCollapse(float(collapse[0])); status='ONE_CLASS_CALIBRATION'
        p=np.repeat(float(collapse[0]),len(collapse))
    else:
        clf=LogisticRegression(max_iter=1000,class_weight='balanced').fit(features,collapse); status='OK'
        p=clf.predict_proba(features[collapse==0])[:,1] if np.any(collapse==0) else clf.predict_proba(features)[:,1]
    return clf,reg,float(np.quantile(p,.90)),float(np.quantile(p,.95)),status

def windows(n,count,wn,seed):
    rng=np.random.default_rng(seed); return [rng.choice(n,min(wn,n),replace=False) for _ in range(count)]

def evaluate_windows(primary,views,Xp,Xv,y,p0ref,pvref,clf,reg,ttrusted,tsuspect,baseline,source,seed):
    p0=predict_prob(primary,Xp); pv=np.stack([predict_prob(views[name],Xv[name]) for name in views]); rows=[]
    for wid,ix in enumerate(windows(len(y),TEST_WINDOWS,WINDOW_N,seed)):
        feat=monitor_vector(p0[ix],pv[:,ix],p0ref,pvref)
        pc=float(clf.predict_proba(feat[None,:])[:,1][0]); ah=float(np.clip(reg.predict(feat[None,:])[0],0,1))
        at=((p0[ix]>.5).astype(int)==np.asarray(y)[ix]).mean()
        est,w,d=estimate_views(pvref,pv[:,ix]); names=list(views); sus=names[int(np.argmin(w))]
        state='suspect' if pc>=tsuspect else ('trusted' if pc<=ttrusted else 'abstain')
        rows.append(dict(source=source,seed=seed,window=wid,true_accuracy=at,clean_primary_accuracy=baseline,true_damage=baseline-at,estimated_accuracy=ah,estimation_error=abs(ah-at),collapse_probability=pc,state=state,suspect_view=sus,minimum_weight=float(w.min()),volume_weight=float(w[names.index('volume')]),timing_weight=float(w[names.index('timing')]),volume_drift=float(d[names.index('volume')]),timing_drift=float(d[names.index('timing')])))
    return rows

# -------------------------------------------- data --------------------------------------------
if not CSV.exists(): raise FileNotFoundError(CSV)
df=pd.read_csv(CSV,low_memory=False); df['type']=df.type.astype(str).str.lower().str.strip(); df['label']=pd.to_numeric(df.label,errors='coerce').fillna(0).astype(int)
normal=df[df.label==0]; source=df[df.type.isin(SOURCE_FAMILIES)]; held=df[df.type.isin(HELDOUT_FAMILIES)]
if source.empty or held.empty: raise RuntimeError('Empty source/heldout split: '+str(df.type.value_counts().to_dict()))
print('SOURCE:',source.type.value_counts().to_dict()); print('HELDOUT:',held.type.value_counts().to_dict()); print('NORMAL:',len(normal))

for seed in SEEDS:
    file=run_file(seed)
    if file.exists(): print('Resume seed',seed); continue
    ntr=sample_cap(normal,NTRAIN,seed); atr=sample_cap(source,NTRAIN,seed)
    srcall=pd.concat([ntr,atr]).sample(frac=1,random_state=seed).reset_index(drop=True); cut=int(.8*len(srcall)); tr,va=srcall.iloc[:cut].copy(),srcall.iloc[cut:].copy()
    te=pd.concat([sample_cap(normal.drop(ntr.index,errors='ignore'),NNORMAL_TEST,seed+99),held]).sample(frac=1,random_state=seed+99).reset_index(drop=True)
    XV,meta,(Xp_tr,Xp_va,Xp_te),offs=prepare_dataset(tr,va,te)
    primary=train_mlp(Xp_tr,tr.label,seed,(96,48)); views={name:train_mlp(XV[name][0],tr.label,seed*100+i,(32,16)) for i,name in enumerate(VIEWS)}
    p0ref=predict_prob(primary,Xp_va); pvref=np.stack([predict_prob(views[name],XV[name][1]) for name in views]); clean_ref=((p0ref>.5).astype(int)==va.label.values).mean()

    # Offline calibration: clean source validation and attacked source validation.
    calX=[]; calA=[]
    for ix in windows(len(va),CAL_WINDOWS,WINDOW_N,seed):
        calX.append(monitor_vector(p0ref[ix],pvref[:,ix],p0ref,pvref)); calA.append(((p0ref[ix]>.5).astype(int)==va.label.values[ix]).mean())
    for target in ['volume','timing']:
        for eps in EPS:
            for mode in ['whitebox','adaptive']:
                Xva_views={name:XV[name][1] for name in views}
                xa=attack_primary(primary,views,Xp_va,Xva_views,va.label,offs,meta,target,eps,mode,seed,pvref)
                p0a=predict_prob(primary,xa); pva=[]
                for name in views:
                    a,b=offs[name]; xin=xa[:,a:b] if name==target else XV[name][1]; pva.append(predict_prob(views[name],xin))
                pva=np.stack(pva)
                for ix in windows(len(va),max(4,CAL_WINDOWS//3),WINDOW_N,seed+int(eps*100)):
                    calX.append(monitor_vector(p0a[ix],pva[:,ix],p0ref,pvref)); calA.append(((p0a[ix]>.5).astype(int)==va.label.values[ix]).mean())
    clf,reg,ttrust,tsus,status=fit_monitor(np.asarray(calX),np.asarray(calA),clean_ref)
    print(f'seed {seed}: calibration={status}, clean primary accuracy={clean_ref:.4f}, calibration windows={len(calA)}')

    rows=[]
    Xte_views={name:XV[name][2] for name in views}
    rows+=evaluate_windows(primary,views,Xp_te,Xte_views,te.label,p0ref,pvref,clf,reg,ttrust,tsus,clean_ref,'clean_heldout',seed)
    for target in ['volume','timing']:
        for eps in EPS:
            for mode in ['whitebox','adaptive']:
                xa=attack_primary(primary,views,Xp_te,Xte_views,te.label,offs,meta,target,eps,mode,seed,pvref)
                Xadv_views={}
                for name in views:
                    a,b=offs[name]; Xadv_views[name]=xa[:,a:b] if name==target else XV[name][2]
                rr=evaluate_windows(primary,views,xa,Xadv_views,te.label,p0ref,pvref,clf,reg,ttrust,tsus,clean_ref,f'{mode}:{target}:eps{eps}',seed)
                for r in rr: r.update(ground_truth_channel=target,attribution_correct=int(r['suspect_view']==target),calibration_status=status)
                rows+=rr
    pd.DataFrame(rows).to_csv(file,index=False); print('Saved',file)

res=pd.concat([pd.read_csv(p) for p in sorted(OUT.glob(f'ton_primary_{RUN}_seed*.csv'))],ignore_index=True)
summary=res.groupby('source').agg(seeds=('seed','nunique'),windows=('window','size'),clean_primary_accuracy=('clean_primary_accuracy','mean'),true_accuracy=('true_accuracy','mean'),true_damage=('true_damage','mean'),estimated_accuracy=('estimated_accuracy','mean'),mae=('estimation_error','mean'),collapse_probability=('collapse_probability','mean'),trusted_rate=('state',lambda x:(x=='trusted').mean()),suspect_rate=('state',lambda x:(x=='suspect').mean()),abstain_rate=('state',lambda x:(x=='abstain').mean()),attribution_accuracy=('attribution_correct','mean')).reset_index()
summary.to_csv(OUT/'ton_primary_summary_v3.csv',index=False)
print('\n=== TON PRIMARY-DETECTOR INTEGRITY RESULTS v3 ==='); print(summary.round(4).to_string(index=False)); print('\nSaved:',OUT/'ton_primary_summary_v3.csv')
