# E1-PRIMARY-IOT: complete semantic-view screening for CICIoMT2024 and CICIoT2023
# Run this as one clean Kaggle notebook script. It performs E1 only: no attacks.
import os, json, hashlib, warnings
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings("ignore", category=UserWarning)

SEED=10
OUT=Path('/kaggle/working/e1_primary_iot'); OUT.mkdir(parents=True,exist_ok=True)
IOT23=Path('/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23')
IOMT=Path('/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024')
CAP_PER_ATTACK_LABEL=3000; MIN_ROWS_PER_LABEL=500
SOURCE_FRACTION=.60; TRAIN_F=.50; REF_F=.20
TARGET_FPR=.05; MIN_DIMS=4; MIN_SOURCE_BACC=.55; MIN_ZERO_BACC=.50; MAX_FPR=.10; MIN_VIEWS=4

# All group rules are frozen before reading results. Every feature is assigned once only.
def semantic_groups(columns):
    groups={"protocol_state":[],"application_protocol":[],"timing_rate":[],"volume_size":[],"count_burst":[]}
    for c in columns:
        s=c.lower().replace('_',' ').replace('-',' ')
        if any(x in s for x in ['http','https','dns','telnet','smtp','ssh','irc','dhcp','arp','igmp','llc']): groups['application_protocol'].append(c)
        elif any(x in s for x in ['protocol','header','flag','tcp','udp','icmp']): groups['protocol_state'].append(c)
        elif any(x in s for x in ['duration','rate','iat','time','active','idle']): groups['timing_rate'].append(c)
        elif any(x in s for x in ['byte','packet','length','size','payload']): groups['volume_size'].append(c)
        else: groups['count_burst'].append(c)
    return groups

def find_label(df):
    exact=[c for c in df.columns if c.strip().lower()=='label']
    if exact:return exact[0]
    cand=[c for c in df.columns if any(x in c.lower() for x in ['label','class','attack','target'])]
    if not cand: raise KeyError('No label-like column found')
    return cand[0]

def sampled_csv(paths, dataset):
    keep=[]; used={}; label_col=None; rng=np.random.default_rng(SEED)
    for path in paths:
        for ch in pd.read_csv(path,chunksize=200000,low_memory=False):
            lab=find_label(ch); label_col=lab
            ch[lab]=ch[lab].astype(str).str.strip()
            for value,g in ch.groupby(lab,sort=True):
                left=CAP_PER_ATTACK_LABEL-used.get(value,0)
                if left<=0: continue
                take=min(left,len(g))
                if len(g)>take:g=g.sample(take,random_state=int(rng.integers(1,2**31-1)))
                keep.append(g); used[value]=used.get(value,0)+len(g)
    if not keep:raise RuntimeError(f'No rows sampled for {dataset}')
    out=pd.concat(keep,ignore_index=True); out['_row_id']=np.arange(len(out),dtype=np.int64)
    return out,label_col

def benign_mask(s): return s.astype(str).str.lower().str.contains('benign|normal',regex=True)
def h(df): return hashlib.sha256(np.sort(df._row_id.to_numpy(np.int64)).tobytes()).hexdigest()[:20]
def smp(df,n,seed):
    if len(df)<n:raise ValueError(f'Need {n} rows but found {len(df)}')
    return df.sample(n=n,random_state=seed).copy()
def cols(df):return [c for c in df.columns if c not in {'label','_row_id','_attack_name'} and pd.api.types.is_numeric_dtype(df[c])]
def make_model(features):
    return Pipeline([('prep',Pipeline([('impute',SimpleImputer(strategy='median')),('scale',StandardScaler())])),('clf',LogisticRegression(solver='lbfgs',max_iter=2000,class_weight='balanced',random_state=SEED))])
def threshold(model,X):
    p=np.sort(np.asarray(model.predict_proba(X)[:,1],float)); n=len(p); allowed=int(np.floor(TARGET_FPR*n))
    if allowed<=0:return float(np.nextafter(p[-1],np.inf))
    ix=n-allowed
    if ix>=n:return float(np.nextafter(p[-1],np.inf))
    return float(np.nextafter(p[ix],np.inf))
def evaluate(model,X,y,t,name):
    p=model.predict_proba(X)[:,1]; pred=(p>t).astype(int); y=np.asarray(y,int); n=y==0; a=y==1
    return dict(split=name,rows=len(y),attack_fraction=float(y.mean()),threshold=float(t),accuracy=float(accuracy_score(y,pred)),balanced_accuracy=float(balanced_accuracy_score(y,pred)),f1=float(f1_score(y,pred,zero_division=0)),precision=float(precision_score(y,pred,zero_division=0)),recall=float(recall_score(y,pred,zero_division=0)),normal_false_positive_rate=float(pred[n].mean()) if n.any() else np.nan,attack_recall=float(pred[a].mean()) if a.any() else np.nan)
def disjoint(parts):
    z=list(parts.items())
    for i,(a,x) in enumerate(z):
        ids=set(x._row_id)
        for b,y in z[i+1:]:
            if ids & set(y._row_id):raise RuntimeError(f'LEAKAGE: {a} overlaps {b}')

def run_dataset(name,raw,lab):
    raw=raw.copy(); raw['_attack_name']=raw[lab].astype(str).str.strip(); raw['label']=(~benign_mask(raw['_attack_name'])).astype(int)
    numeric=cols(raw); groups=semantic_groups(numeric)
    normal=raw[raw.label.eq(0)].copy(); attack=raw[raw.label.eq(1)].copy()
    counts=attack._attack_name.value_counts(); eligible=sorted(counts[counts>=MIN_ROWS_PER_LABEL].index.tolist())
    if len(eligible)<4:raise RuntimeError(f'{name}: only {len(eligible)} attack labels have >= {MIN_ROWS_PER_LABEL} sampled rows')
    source_labels=eligible[:int(np.ceil(SOURCE_FRACTION*len(eligible)))]; held_labels=eligible[len(source_labels):]
    if not held_labels:raise RuntimeError(f'{name}: no held-out labels')
    per=min(CAP_PER_ATTACK_LABEL,min(int(counts[x]) for x in eligible)); ntr=max(1,int(per*TRAIN_F)); nref=max(1,int(per*REF_F)); ntest=per-ntr-nref
    st=[];sr=[];ss=[];zh=[]
    for i,label in enumerate(eligible):
        x=smp(attack[attack._attack_name.eq(label)],per,SEED+i)
        if label in source_labels:
            st.append(x.iloc[:ntr]); sr.append(x.iloc[ntr:ntr+nref]); ss.append(x.iloc[ntr+nref:])
        else: zh.append(x)
    st=pd.concat(st,ignore_index=True); sr=pd.concat(sr,ignore_index=True); ss=pd.concat(ss,ignore_index=True); zh=pd.concat(zh,ignore_index=True)
    ntrn,nrefn,nssn,nzn=len(st),len(sr),len(ss),len(zh)
    pool=smp(normal,ntrn+nrefn+nssn+nzn,SEED+900)
    nt=pool.iloc[:ntrn]; nr=pool.iloc[ntrn:ntrn+nrefn]; ns=pool.iloc[ntrn+nrefn:ntrn+nrefn+nssn]; nz=pool.iloc[ntrn+nrefn+nssn:]
    disjoint({'normal_train':nt,'normal_reference':nr,'normal_source_test':ns,'normal_zero_test':nz,'source_train':st,'source_reference':sr,'source_test':ss,'heldout_test':zh})
    train=pd.concat([nt,st],ignore_index=True).sample(frac=1,random_state=SEED+1); known=pd.concat([nr,sr],ignore_index=True).sample(frac=1,random_state=SEED+2); source_test=pd.concat([ns,ss],ignore_index=True).sample(frac=1,random_state=SEED+3); zero=pd.concat([nz,zh],ignore_index=True).sample(frac=1,random_state=SEED+4)
    manifest=pd.DataFrame([dict(dataset=name,split=k,rows=len(v),attack_fraction=float(v.label.mean()),row_id_sha256=h(v)) for k,v in {'train':train,'normal_reference':nr,'known_reference':known,'source_family_test':source_test,'balanced_zero_day_test':zero}.items()])
    manifest.to_csv(OUT/f'{name}_split_manifest.csv',index=False)
    pd.DataFrame([dict(dataset=name,attack_label=x,role='source' if x in source_labels else 'heldout',sampled_rows=int(counts[x]),per_label_used=per) for x in eligible]).to_csv(OUT/f'{name}_attack_label_protocol.csv',index=False)
    model=make_model(numeric); model.fit(train[numeric],train.label); t=threshold(model,nr[numeric]); pr=[]
    for split,x in {'known_reference':known,'clean_normal_reference':nr,'source_family_test':source_test,'balanced_zero_day_test':zero}.items():
        q=evaluate(model,x[numeric],x.label,t,split);q.update(dataset=name,model='primary',raw_feature_count=len(numeric));pr.append(q)
    primary=pd.DataFrame(pr); primary.to_csv(OUT/f'{name}_primary_results.csv',index=False)
    rows=[]; schema=[]
    for view,use in groups.items():
        schema += [dict(dataset=name,feature=c,semantic_view=view) for c in use]
        r=dict(dataset=name,view=view,raw_feature_count=len(use),status='FAIL',failure_reason='')
        try:
            m=make_model(use);m.fit(train[use],train.label);tv=threshold(m,nr[use]);clean=evaluate(m,nr[use],nr.label,tv,'clean');src=evaluate(m,source_test[use],source_test.label,tv,'source');zd=evaluate(m,zero[use],zero.label,tv,'zero')
            r.update(threshold=tv,transformed_feature_count=len(use),clean_normal_fpr=clean['normal_false_positive_rate'],source_balanced_accuracy=src['balanced_accuracy'],source_attack_recall=src['attack_recall'],zero_day_balanced_accuracy=zd['balanced_accuracy'],zero_day_attack_recall=zd['attack_recall'])
            fail=[]
            if len(use)<MIN_DIMS:fail.append('too_few_features')
            if src['balanced_accuracy']<MIN_SOURCE_BACC:fail.append('source_balanced_accuracy_below_0.55')
            if zd['balanced_accuracy']<MIN_ZERO_BACC:fail.append('zero_day_balanced_accuracy_below_0.50')
            if clean['normal_false_positive_rate']>MAX_FPR:fail.append('clean_normal_fpr_above_0.10')
            r['failure_reason']='|'.join(fail);r['status']='PASS' if not fail else 'FAIL'
        except Exception as e:r['failure_reason']=f'{type(e).__name__}: {str(e)[:180]}'
        rows.append(r)
    schema=pd.DataFrame(schema);schema.to_csv(OUT/f'{name}_semantic_schema.csv',index=False)
    vr=pd.DataFrame(rows);vr.to_csv(OUT/f'{name}_view_screening_results.csv',index=False)
    ps=primary[primary.split.eq('source_family_test')].iloc[0];pz=primary[primary.split.eq('balanced_zero_day_test')].iloc[0];pn=primary[primary.split.eq('clean_normal_reference')].iloc[0]; accepted=vr[vr.status.eq('PASS')].view.tolist()
    decision=dict(dataset=name,experiment='E1_primary_iot_semantic_screening',seed=SEED,source_attack_labels=source_labels,heldout_attack_labels=held_labels,pass_=bool(len(accepted)>=MIN_VIEWS and ps.balanced_accuracy>=MIN_SOURCE_BACC and pz.balanced_accuracy>=MIN_ZERO_BACC and pn.normal_false_positive_rate<=MAX_FPR),accepted_views=accepted,accepted_view_count=len(accepted),required_minimum_views=MIN_VIEWS,primary_source_balanced_accuracy=float(ps.balanced_accuracy),primary_zero_day_balanced_accuracy=float(pz.balanced_accuracy),primary_clean_normal_fpr=float(pn.normal_false_positive_rate))
    with open(OUT/f'{name}_e1_decision.json','w') as f:json.dump(decision,f,indent=2)
    print('\n'+'='*100);print(name,'PRIMARY IDS RESULTS');print('='*100);print(primary.round(4).to_string(index=False))
    print('\n'+name,'SEMANTIC VIEW ELIGIBILITY RESULTS');print(vr.round(4).to_string(index=False))
    print('\n'+name,'E1 FINAL DECISION');print(json.dumps(decision,indent=2))
    return decision

if not IOT23.exists():raise FileNotFoundError(IOT23)
if not IOMT.exists():raise FileNotFoundError(IOMT)
iot23,lab23=sampled_csv([IOT23/'train/train.csv',IOT23/'validation/validation.csv',IOT23/'test/test.csv'],'CICIoT2023')
iomt,labmt=sampled_csv([IOMT/'train_iomt.csv',IOMT/'test_iomt.csv'],'CICIoMT2024')
print('CICIoT2023 sampled labels:',iot23[lab23].value_counts().to_dict())
print('CICIoMT2024 sampled labels:',iomt[labmt].value_counts().to_dict())
d1=run_dataset('CICIoT2023',iot23,lab23);d2=run_dataset('CICIoMT2024',iomt,labmt)
pd.DataFrame([d1,d2]).to_csv(OUT/'e1_primary_iot_decisions.csv',index=False)
print('\nFILES WRITTEN:',*[p.name for p in sorted(OUT.glob('*'))],sep='\n- ')
