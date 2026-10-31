"""Self-contained neural-target attack evaluation on five REAL saved datasets.
Uses the nine previously trained full-feature SGD models, not view-bank proxies.
Computes single-target PGD, coordinated-ensemble PGD, and genuine surrogate transfer,
then evaluates ALine-S/D, AC, DoC and homogeneous-family GDE on the attacked targets.
Range/type feature-space scope only. No packet-validity/confirmation claim.
"""
import hashlib
import json
import traceback
import warnings
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn
from scipy.special import ndtr,ndtri
from sklearn.neural_network import MLPClassifier

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
OUT=BASE/'neural_target_and_coordinated_attacks_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
WINDOW_SIZE=128
EPSILONS=[.25,.50]
ATTACK_SEEDS=[1101,1102,1103]
PGD_STEPS=30
RESTARTS=2
SURROGATE_FRACTION=.50
PROBIT_CLIP=1e-5
DEVICE=torch.device('cuda' if torch.cuda.is_available() else 'cpu')
DTYPE=torch.float64
RECIPES=[('MLP16',(16,),20),('MLP32',(32,),60),('MLP32_16',(32,16),160)]
MODEL_NAMES=[f'{group}_seed_{seed}' for group,_,_ in RECIPES for seed in [901,902,903]]
GROUPS={group:list(range(i*3,(i+1)*3)) for i,(group,_,_) in enumerate(RECIPES)}
TARGET_INDICES=GROUPS['MLP32_16']
SETTINGS={'datasets':DATASETS,'window_size':WINDOW_SIZE,'epsilons':EPSILONS,
          'attack_seeds':ATTACK_SEEDS,'pgd_steps':PGD_STEPS,'restarts':RESTARTS,
          'surrogate_fraction':SURROGATE_FRACTION,'surrogate_architecture':[32,16],
          'surrogate_max_iter':160,'models':MODEL_NAMES,'single_target_indices':TARGET_INDICES,
          'budget_scale':'Original frozen logistic-primary StandardScaler',
          'optimization_loss':'Negative target logit; mean negative logits for coordinated attack',
          'probit_clip':PROBIT_CLIP,'scope':'Exploratory range/type feature-space evaluation'}
SETTINGS_HASH=hashlib.sha256(json.dumps(SETTINGS,sort_keys=True).encode()).hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_bank():
    folders=[p for p in BASE.glob('aline_gde_published_equations_v1*') if p.is_dir()]
    valid=[p for p in folders if all((p/d/name).exists()
                                   for d in DATASETS for name in [f'{m}.joblib' for m in MODEL_NAMES])]
    if len(valid)!=1:
        raise RuntimeError(f'Expected one complete saved neural bank directory; found: {[str(p) for p in valid]}')
    return valid[0]


def preprocessing(bundle,frame):
    features=bundle['primary_features']
    imputed=bundle['primary_model'].named_steps['imputer'].transform(frame[features])
    scaled=bundle['primary_model'].named_steps['scaler'].transform(imputed)
    if not np.isfinite(scaled).all() or scaled.shape[1]!=len(features):
        raise ValueError('Invalid frozen preprocessing output.')
    return imputed,scaled


def torch_model(model):
    if model.activation!='relu' or model.out_activation_!='logistic' or list(model.classes_)!=[0,1]:
        raise ValueError('Expected saved binary ReLU/logistic sklearn MLP.')
    layers=[]
    for i,(weight,bias) in enumerate(zip(model.coefs_,model.intercepts_)):
        layer=nn.Linear(weight.shape[0],weight.shape[1],bias=True,dtype=DTYPE)
        with torch.no_grad():
            layer.weight.copy_(torch.as_tensor(weight.T,dtype=DTYPE))
            layer.bias.copy_(torch.as_tensor(bias,dtype=DTYPE))
        layers.append(layer)
        if i<len(model.coefs_)-1:
            layers.append(nn.ReLU())
    result=nn.Sequential(*layers).to(DEVICE).eval()
    for parameter in result.parameters():
        parameter.requires_grad_(False)
    return result


def agreement(decisions):
    d=decisions.astype(float)
    return (d@d.T+(1-d)@(1-d).T)/decisions.shape[1]


def aline_prepare(decisions,accuracies):
    m=len(accuracies)
    i,j=np.triu_indices(m,1)
    x=ndtri(np.clip(agreement(decisions)[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    design=np.column_stack([x,np.ones_like(x)])
    pair_design=np.zeros((len(i),m))
    pair_design[np.arange(len(i)),i]=.5
    pair_design[np.arange(len(i)),j]=.5
    return {'i':i,'j':j,'x':x,'design':design,'pair_design':pair_design,
            'rank':np.linalg.matrix_rank(design),
            'z_accuracy':ndtri(np.clip(accuracies,PROBIT_CLIP,1-PROBIT_CLIP))}


def aline_estimate(prepared,decisions):
    m=len(decisions)
    if prepared['rank']<2:
        return np.full(m,np.nan),np.full(m,np.nan),np.nan
    i,j=prepared['i'],prepared['j']
    y=ndtri(np.clip(agreement(decisions)[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    slope,intercept=np.linalg.lstsq(prepared['design'],y,rcond=None)[0]
    S=ndtr(slope*prepared['z_accuracy']+intercept)
    rhs=y+slope*((prepared['z_accuracy'][i]+prepared['z_accuracy'][j])*.5-prepared['x'])
    D=ndtr(np.linalg.lstsq(prepared['pair_design'],rhs,rcond=None)[0])
    denominator=np.sum((y-y.mean())**2)
    r2=1-np.sum((y-(slope*prepared['x']+intercept))**2)/denominator if denominator>1e-12 else np.nan
    return S,D,float(r2)


def attack_context(bundle,frame,epsilon):
    imputed,scaled=preprocessing(bundle,frame)
    features=list(bundle['primary_features'])
    mutable=list(bundle['mutable_columns'])
    positions=[features.index(c) for c in mutable]
    original=frame[mutable].to_numpy(dtype=float)
    base=imputed[:,positions]
    scales=bundle['primary_model'].named_steps['scaler'].scale_[positions]
    low=base.copy();high=base.copy();integer=[]
    for k,column in enumerate(mutable):
        values=bundle['train_df'][column].dropna().to_numpy(dtype=float)
        values=values[np.isfinite(values)]
        qlow,qhigh=np.quantile(values,[.001,.999])
        low[:,k]=np.maximum(base[:,k]-epsilon*scales[k],np.minimum(base[:,k],qlow))
        high[:,k]=np.minimum(base[:,k]+epsilon*scales[k],np.maximum(base[:,k],qhigh))
        integer.append(np.all(np.isclose(values,np.round(values),atol=1e-8)))
    eligible=(frame.label.to_numpy()==1)[:,None]&np.isfinite(original)
    return {'frame':frame,'scaled':scaled,'original':original,'mutable':mutable,'positions':positions,
            'base':torch.as_tensor(base,dtype=DTYPE,device=DEVICE),
            'scales':torch.as_tensor(scales,dtype=DTYPE,device=DEVICE),
            'low':torch.as_tensor(low,dtype=DTYPE,device=DEVICE),
            'high':torch.as_tensor(high,dtype=DTYPE,device=DEVICE),
            'integer':torch.as_tensor(integer,dtype=torch.bool,device=DEVICE),
            'eligible':torch.as_tensor(eligible,dtype=torch.bool,device=DEVICE),
            'malicious':torch.as_tensor(frame.label.to_numpy()==1,device=DEVICE),
            'epsilon':epsilon}


def project(context,delta):
    candidate=context['base']+delta*context['scales'][None,:]
    candidate=torch.minimum(torch.maximum(candidate,context['low']),context['high'])
    rounded=torch.round(candidate)
    feasible=(rounded>=context['low'])&(rounded<=context['high'])
    typed=torch.where(feasible,rounded,context['base'])
    candidate=torch.where(context['integer'][None,:],typed,candidate)
    projected=(candidate-context['base'])/context['scales'][None,:]
    return torch.where(context['eligible'],projected,torch.zeros_like(projected))


def optimize(context,source_models,seed):
    rng=np.random.default_rng(seed)
    base=torch.as_tensor(context['scaled'],dtype=DTYPE,device=DEVICE)
    shape=context['base'].shape
    best_delta=torch.zeros(shape,dtype=DTYPE,device=DEVICE)
    best_loss=torch.full((shape[0],),-torch.inf,dtype=DTYPE,device=DEVICE)
    def row_loss(delta):
        x=base.clone()
        x[:,context['positions']]=x[:,context['positions']]+delta
        logits=torch.stack([model(x).reshape(-1) for model in source_models]).mean(dim=0)
        return -logits
    def retain(delta,loss):
        improve=context['malicious']&(loss>best_loss)
        best_loss[improve]=loss[improve].detach()
        best_delta[improve]=delta[improve].detach()
    for restart in range(RESTARTS):
        delta=(torch.zeros(shape,dtype=DTYPE,device=DEVICE) if restart==0 else
               torch.as_tensor(rng.uniform(-context['epsilon'],context['epsilon'],size=tuple(shape)),
                               dtype=DTYPE,device=DEVICE))
        delta=project(context,delta)
        for step in range(PGD_STEPS+1):
            delta=delta.detach().requires_grad_(step<PGD_STEPS)
            losses=row_loss(delta)
            with torch.no_grad(): retain(delta,losses)
            if step==PGD_STEPS: break
            loss=losses[context['malicious']].sum()
            gradient=torch.autograd.grad(loss,delta)[0]
            with torch.no_grad():
                delta=project(context,delta+(2.5*context['epsilon']/PGD_STEPS)*gradient.sign())
    return best_delta.detach().cpu().numpy()


def attacked_frame(context,delta):
    base=context['base'].detach().cpu().numpy()
    scales=context['scales'].detach().cpu().numpy()
    eligible=context['eligible'].detach().cpu().numpy()
    values=np.where(eligible,base+delta*scales[None,:],context['original'])
    if np.any(eligible&(np.abs(values-context['original'])>context['epsilon']*scales[None,:]+1e-7)):
        raise AssertionError('Budget exceeded.')
    frame=context['frame'].copy()
    frame[context['mutable']]=values
    benign=frame.label.to_numpy()==0
    if not np.allclose(frame.loc[benign,context['mutable']].to_numpy(dtype=float),
                       context['frame'].loc[benign,context['mutable']].to_numpy(dtype=float),equal_nan=True):
        raise AssertionError('Benign feature changes.')
    immutable=[c for c in frame if c not in context['mutable']]
    if not frame[immutable].equals(context['frame'][immutable]):
        raise AssertionError('Immutable field changes.')
    return frame


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    frozen={'settings_sha256':SETTINGS_HASH,'settings':SETTINGS}
    settings_path=OUT/'settings.json'
    if settings_path.exists() and json.loads(settings_path.read_text())!=frozen:
        raise RuntimeError('Settings changed; use a new OUT directory.')
    settings_path.write_text(json.dumps(frozen,indent=2))
    bank_root=find_bank()
    statuses=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        try:
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            models=[joblib.load(bank_root/dataset/f'{name}.joblib') for name in MODEL_NAMES]
            reference_path=bank_root/dataset/'real_ID_reference.csv'
            reference=pd.read_csv(reference_path)
            _,reference_X=preprocessing(bundle,reference)
            reference_y=reference.label.to_numpy(dtype=int)
            reference_p=np.vstack([model.predict_proba(reference_X)[:,1] for model in models])
            reference_decisions=reference_p>.5
            reference_accuracy=(reference_decisions==reference_y).mean(axis=1)
            reference_confidence=np.maximum(reference_p,1-reference_p).mean(axis=1)
            prepared=aline_prepare(reference_decisions,reference_accuracy)
            identity_S,identity_D,_=aline_estimate(prepared,reference_decisions)
            if prepared['rank']>=2:
                expected=np.clip(reference_accuracy,PROBIT_CLIP,1-PROBIT_CLIP)
                if not np.allclose(identity_S,expected,atol=1e-7) or not np.allclose(identity_D,expected,atol=1e-7):
                    raise AssertionError('Real-reference ALine identity failed.')
            source=bundle['source_test_df']
            order=np.random.default_rng(1002).permutation(len(source))
            count=len(source)//WINDOW_SIZE*WINDOW_SIZE
            clean=source.iloc[order[:count]].reset_index(drop=True).copy()
            _,clean_X=preprocessing(bundle,clean)
            torch_models=[torch_model(model) for model in models]
            verification=[]
            with torch.no_grad():
                real=torch.as_tensor(clean_X,dtype=DTYPE,device=DEVICE)
                for name,model,network in zip(MODEL_NAMES,models,torch_models):
                    expected=model.predict_proba(clean_X)[:,1]
                    observed=torch.sigmoid(network(real).reshape(-1)).cpu().numpy()
                    max_difference=float(np.max(np.abs(expected-observed)))
                    if max_difference>1e-7:
                        raise AssertionError(f'Torch/sklearn mismatch for {name}: {max_difference}')
                    verification.append({'dataset':dataset,'model':name,'max_real_record_probability_difference':max_difference})
            save_csv(verification,directory/'torch_sklearn_real_data_checks.csv')
            fingerprint={'bundle_sha256':sha(bundle_path),'reference_sha256':sha(reference_path),
                         'model_sha256':{name:sha(bank_root/dataset/f'{name}.joblib') for name in MODEL_NAMES},
                         'settings_sha256':SETTINGS_HASH}
            manifest=directory/'input_fingerprint.json'
            if manifest.exists() and json.loads(manifest.read_text())!=fingerprint:
                raise RuntimeError('Frozen inputs changed.')
            manifest.write_text(json.dumps(fingerprint,indent=2))
            rows=[];gde_rows=[]
            clean_estimates={};clean_accuracy={}
            def evaluate(frame,metadata,paired=False):
                _,X=preprocessing(bundle,frame)
                p=np.vstack([model.predict_proba(X)[:,1] for model in models])
                predictions=p>.5
                labels=frame.label.to_numpy(dtype=int)
                scopes=[('whole_case',-1,np.arange(len(frame)))]+[
                    ('window_128',wid,np.arange(start,start+WINDOW_SIZE))
                    for wid,start in enumerate(range(0,len(frame)-WINDOW_SIZE+1,WINDOW_SIZE))]
                for scope,wid,index in scopes:
                    truth=(predictions[:,index]==labels[index]).mean(axis=1)
                    S,D,r2=aline_estimate(prepared,predictions[:,index])
                    AC=np.maximum(p[:,index],1-p[:,index]).mean(axis=1)
                    DoC=np.clip(reference_accuracy+AC-reference_confidence,0,1)
                    estimates={'ALine_S':S,'ALine_D':D,'AC':AC,'DoC':DoC}
                    if metadata['case']=='clean_source':
                        clean_accuracy[(scope,wid)]=truth.copy()
                        for method,value in estimates.items(): clean_estimates[(scope,wid,method)]=value.copy()
                    for method,value in estimates.items():
                        for j,name in enumerate(MODEL_NAMES):
                            damage=(clean_accuracy[(scope,wid)][j]-truth[j]) if paired else np.nan
                            estimated_damage=(clean_estimates[(scope,wid,method)][j]-value[j]) if paired else np.nan
                            rows.append({**metadata,'scope':scope,'window':wid,'target_model':name,'estimator':method,
                                'actual_accuracy':float(truth[j]),'estimated_accuracy':float(value[j]),
                                'absolute_accuracy_error':float(abs(value[j]-truth[j])),
                                'true_damage':float(damage),'estimated_damage':float(estimated_damage),
                                'damage_underestimation':float(damage-estimated_damage),
                                'differential_absolute_error':float(abs(damage-estimated_damage)),
                                'agreement_line_R2':r2,'target_is_logistic':False})
                    for group,member_indices in GROUPS.items():
                        a=agreement(predictions[member_indices][:,index])
                        i,j=np.triu_indices(len(member_indices),1)
                        estimated=float(a[i,j].mean())
                        actual=float(truth[member_indices].mean())
                        gde_rows.append({**metadata,'scope':scope,'window':wid,'homogeneous_recipe':group,
                            'actual_family_accuracy':actual,'estimated_family_accuracy':estimated,
                            'absolute_accuracy_error':abs(estimated-actual),
                            'estimates_single_neural_primary':False,'target_is_logistic':False})
            evaluate(clean,{'dataset':dataset,'case':'clean_source','attack_family':'none'})
            for domain,frame in bundle['evaluation_domains'].items():
                evaluate(frame.reset_index(drop=True),{'dataset':dataset,'case':domain,'attack_family':'none'})
            _,train_X=preprocessing(bundle,bundle['train_df'])
            train_y=bundle['train_df'].label.to_numpy(dtype=int)
            for attack_seed in ATTACK_SEEDS:
                rng=np.random.default_rng(attack_seed)
                chosen=[]
                for label in [0,1]:
                    available=np.flatnonzero(train_y==label)
                    chosen.extend(rng.choice(available,max(1,int(SURROGATE_FRACTION*len(available))),replace=False))
                surrogate_path=directory/f'independent_surrogate_{attack_seed}.joblib'
                if surrogate_path.exists():
                    surrogate=joblib.load(surrogate_path)
                else:
                    surrogate=MLPClassifier(hidden_layer_sizes=(32,16),solver='sgd',learning_rate='adaptive',
                        learning_rate_init=.001,momentum=.9,alpha=.001,batch_size=min(256,len(chosen)),
                        max_iter=160,early_stopping=False,n_iter_no_change=161,random_state=attack_seed)
                    with warnings.catch_warnings(record=True) as captured:
                        warnings.simplefilter('always');surrogate.fit(train_X[chosen],train_y[chosen])
                    joblib.dump(surrogate,surrogate_path,compress=3)
                    (directory/f'surrogate_{attack_seed}_training_warnings.json').write_text(
                        json.dumps([str(item.message) for item in captured],indent=2))
                surrogate_network=torch_model(surrogate)
                attacks=[('single_target_pgd',MODEL_NAMES[index],[torch_models[index]]) for index in TARGET_INDICES]
                attacks += [('coordinated_ensemble_pgd','all_nine_neural_models',torch_models),
                            ('genuine_surrogate_transfer','independent_half_train_surrogate',[surrogate_network])]
                for epsilon in EPSILONS:
                    context=attack_context(bundle,clean,epsilon)
                    for family,attack_target,attack_models in attacks:
                        name=f'{family}_{attack_target}_eps_{epsilon:.2f}_seed_{attack_seed}'
                        artifact=directory/f'{name}.npz'
                        if artifact.exists():
                            with np.load(artifact,allow_pickle=False) as saved:
                                delta=saved['per_record_delta_standardized'].copy()
                                if not np.array_equal(saved['source_row_ids'].astype(str),clean['_row_id'].to_numpy(dtype=str)):
                                    raise AssertionError('Cached attack row alignment changed.')
                        else:
                            delta=optimize(context,attack_models,attack_seed)
                            np.savez_compressed(artifact,per_record_delta_standardized=delta,
                                source_row_ids=clean['_row_id'].to_numpy(dtype=str),
                                mutable_columns=np.asarray(bundle['mutable_columns'],dtype=str))
                        attacked=attacked_frame(context,delta)
                        evaluate(attacked,{'dataset':dataset,'case':name,'attack_family':family,
                            'attack_target':attack_target,'epsilon':epsilon,'attack_seed':attack_seed},paired=True)
                        save_csv(rows,directory/'neural_accuracy_estimator_results.csv')
                        save_csv(gde_rows,directory/'homogeneous_gde_results.csv')
                        print(dataset,name,'ATTACK + TARGET-MATCHED ESTIMATION COMPUTED',flush=True)
            statuses.append({'dataset':dataset,'status':'NEURAL_TARGET_ATTACKS_COMPUTED','detail':''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    successful={row['dataset'] for row in statuses if row['status']=='NEURAL_TARGET_ATTACKS_COMPUTED'}
    tables=[pd.read_csv(OUT/d/'neural_accuracy_estimator_results.csv') for d in successful]
    if tables:
        results=pd.concat(tables,ignore_index=True)
        save_csv(results,OUT/'all_datasets_neural_estimator_results.csv')
        summary=results.groupby(['dataset','attack_family','scope','estimator'],dropna=False).agg(
            actual_accuracy=('actual_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean'),
            absolute_accuracy_error=('absolute_accuracy_error','mean'),
            true_damage=('true_damage','mean'),estimated_damage=('estimated_damage','mean'),
            differential_absolute_error=('differential_absolute_error','mean')).reset_index()
        save_csv(summary,OUT/'target_matched_summary.csv')
        print('\nNEURAL TARGET-MATCHED SUMMARY\n'+summary.round(4).to_string(index=False),flush=True)
    tables=[pd.read_csv(OUT/d/'homogeneous_gde_results.csv') for d in successful]
    if tables: save_csv(pd.concat(tables,ignore_index=True),OUT/'all_datasets_homogeneous_gde_results.csv')
    protocol={
        'data':'Real source/test/reference records; labels never altered',
        'attack_methods':['Single-target neural PGD','Coordinated nine-model PGD','Independent half-train surrogate transfer'],
        'optimization':'Per-record standardized offsets; explicit torch/sklearn real-record consistency checks',
        'constraints':'Previously defined range/type feature-space constraints only',
        'input_budget':'Frozen logistic-primary training scales shared by all neural models',
        'evaluation':'Original sklearn neural models, native binary decisions, target-matched estimator accuracy',
        'no_claims':['packet-semantic validity','provenance-approved attacks','fresh-dataset confirmation',
                     'independent dataset replications','adaptive attacks against the ALine hard algorithm',
                     'global PGD optimality','statistical significance'],
        'limitations':['Coordinated attacks optimize evasion, not preservation of ALine estimates',
                       'Targets and GDE family means are kept distinct',
                       'Attack/model/window repetitions share the same real corpus',
                       'Training/reference/test inputs are development data already inspected',
                       'All zero/negative damage and rank-deficient estimates remain visible'],
        'device_used':str(DEVICE),'optimization_dtype':str(DTYPE)}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    NEURAL_ATTACK_STATUS=main()
