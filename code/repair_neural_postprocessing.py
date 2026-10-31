"""Repair neural target/domain/epsilon aggregation and verify saved attack replay.
All estimator outputs are recomputed from the frozen REAL models and reference.
No training, PGD optimization, synthetic records, synthetic labels, or global float patch.
Undefined diagnostic statistics remain NaN, not zero.
"""
import hashlib
import json
import re
import traceback
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from scipy.special import ndtr,ndtri

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
INPUT=BASE/'neural_target_and_coordinated_attacks_v1'
OUT=BASE/'neural_postprocessing_repair_and_replay_v2'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
WINDOW_SIZE=128
PROBIT_CLIP=1e-5
MODEL_NAMES=[f'{group}_seed_{seed}' for group in ['MLP16','MLP32','MLP32_16'] for seed in [901,902,903]]
TARGET_NAMES=[f'MLP32_16_seed_{seed}' for seed in [901,902,903]]
TARGET_INDICES=[MODEL_NAMES.index(name) for name in TARGET_NAMES]
ATTACK_FAMILIES=['single_target_pgd','coordinated_ensemble_pgd','genuine_surrogate_transfer']
METRICS=['actual_accuracy','estimated_accuracy','absolute_accuracy_error','true_damage',
         'estimated_damage','damage_underestimation','differential_absolute_error']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def safe_number(value):
    # Optional metadata/diagnostics only. Do not replace missing metrics with zero.
    converted=pd.to_numeric(pd.Series([value]),errors='coerce').iloc[0]
    return np.nan if pd.isna(converted) else float(converted)


def scaled(bundle,frame):
    primary=bundle['primary_model']
    features=bundle['primary_features']
    imputed=primary.named_steps['imputer'].transform(frame[features])
    X=primary.named_steps['scaler'].transform(imputed)
    if X.shape[1]!=len(features) or not np.isfinite(X).all():
        raise ValueError('Invalid frozen preprocessing output.')
    return imputed,X


def locate_models(dataset,fingerprint):
    candidates=[]
    for folder in BASE.glob('aline_gde_published_equations_v1*'):
        directory=folder/dataset
        if not directory.is_dir(): continue
        model_files=[directory/f'{name}.joblib' for name in MODEL_NAMES]
        reference=directory/'real_ID_reference.csv'
        if not reference.exists() or not all(path.exists() for path in model_files): continue
        if sha(reference)!=fingerprint['reference_sha256']: continue
        if all(sha(path)==fingerprint['model_sha256'][name]
               for name,path in zip(MODEL_NAMES,model_files)):
            candidates.append(directory)
    if not candidates:
        raise FileNotFoundError(f'{dataset}: no saved neural bank matches the attack fingerprints.')
    # Multiple byte-identical copies are harmless; all hashes were checked.
    return min(candidates,key=lambda path:len(str(path)))


def source_frame(bundle):
    frame=bundle['source_test_df']
    order=np.random.default_rng(1002).permutation(len(frame))
    usable=len(frame)//WINDOW_SIZE*WINDOW_SIZE
    return frame.iloc[order[:usable]].reset_index(drop=True).copy()


def agreement(decisions):
    d=decisions.astype(float)
    return (d@d.T+(1-d)@(1-d).T)/decisions.shape[1]


def prepare_reference(probability,labels):
    decision=probability>.5
    accuracy=(decision==labels).mean(axis=1)
    m=len(accuracy)
    i,j=np.triu_indices(m,1)
    x=ndtri(np.clip(agreement(decision)[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    design=np.column_stack([x,np.ones_like(x)])
    pair_design=np.zeros((len(i),m))
    pair_design[np.arange(len(i)),i]=.5
    pair_design[np.arange(len(i)),j]=.5
    return {'i':i,'j':j,'x':x,'design':design,
            'design_pinv':np.linalg.pinv(design),'rank':np.linalg.matrix_rank(design),
            'pair_pinv':np.linalg.pinv(pair_design),
            'z_accuracy':ndtri(np.clip(accuracy,PROBIT_CLIP,1-PROBIT_CLIP)),
            'accuracy':accuracy,'confidence':np.maximum(probability,1-probability).mean(axis=1)}


def estimate(prepared,probability):
    decision=probability>.5
    AC=np.maximum(probability,1-probability).mean(axis=1)
    DoC=np.clip(prepared['accuracy']+AC-prepared['confidence'],0,1)
    if prepared['rank']<2:
        S=np.full(len(probability),np.nan)
        D=np.full(len(probability),np.nan)
        return {'AC':AC,'DoC':DoC,'ALine_S':S,'ALine_D':D},np.nan,'RANK_DEFICIENT_ALINE'
    i,j=prepared['i'],prepared['j']
    y=ndtri(np.clip(agreement(decision)[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    slope,intercept=prepared['design_pinv']@y
    S=ndtr(slope*prepared['z_accuracy']+intercept)
    rhs=y+slope*((prepared['z_accuracy'][i]+prepared['z_accuracy'][j])*.5-prepared['x'])
    D=ndtr(prepared['pair_pinv']@rhs)
    denominator=np.sum((y-y.mean())**2)
    r2=(1-np.sum((y-(slope*prepared['x']+intercept))**2)/denominator
        if denominator>1e-12 else np.nan)
    return {'AC':AC,'DoC':DoC,'ALine_S':S,'ALine_D':D},safe_number(r2),'COMPUTED'


def replay(bundle,artifact):
    with np.load(artifact,allow_pickle=False) as saved:
        delta=saved['per_record_delta_standardized'].copy()
        row_ids=saved['source_row_ids'].astype(str)
        mutable=saved['mutable_columns'].astype(str).tolist()
    match=re.search(r'_eps_([0-9]+(?:\.[0-9]+)?)_seed_(\d+)$',artifact.stem)
    if not match:
        raise ValueError(f'Cannot parse recorded epsilon/seed: {artifact.name}')
    epsilon=float(match.group(1))
    attack_seed=int(match.group(2))
    source=bundle['source_test_df'].copy()
    source['_row_id']=source['_row_id'].astype(str)
    if source['_row_id'].duplicated().any():
        raise ValueError('Duplicate real source row IDs.')
    clean=source.set_index('_row_id',drop=False).loc[row_ids].reset_index(drop=True).copy()
    if mutable!=list(bundle['mutable_columns']):
        raise ValueError('Saved mutable-feature order mismatch.')
    if delta.shape!=(len(clean),len(mutable)) or not np.isfinite(delta).all():
        raise ValueError('Saved per-record perturbation dimensions/values are invalid.')
    imputed,_=scaled(bundle,clean)
    features=list(bundle['primary_features'])
    positions=[features.index(column) for column in mutable]
    scales=bundle['primary_model'].named_steps['scaler'].scale_[positions]
    original=clean[mutable].to_numpy(dtype=float)
    eligible=(clean.label.to_numpy()==1)[:,None]&np.isfinite(original)
    changed=np.where(eligible,imputed[:,positions]+delta*scales[None,:],original)
    budget=epsilon*scales[None,:]
    tolerance=1e-7+1e-10*np.maximum(1,budget)
    displacement=np.abs(changed-original)
    if np.any(eligible&(displacement>budget+tolerance)):
        raise AssertionError('Cached attack budget violation.')
    for j,column in enumerate(mutable):
        training=bundle['train_df'][column].dropna().to_numpy(dtype=float)
        training=training[np.isfinite(training)]
        qlow,qhigh=np.quantile(training,[.001,.999])
        low=np.maximum(original[:,j]-budget[0,j],np.minimum(original[:,j],qlow))
        high=np.minimum(original[:,j]+budget[0,j],np.maximum(original[:,j],qhigh))
        if np.any(eligible[:,j]&((changed[:,j]<low-tolerance[0,j])|
                                (changed[:,j]>high+tolerance[0,j]))):
            raise AssertionError(f'Training/original-relative box violation: {column}')
        if np.all(np.isclose(training,np.round(training),atol=1e-8)):
            modified=eligible[:,j]&(displacement[:,j]>tolerance[0,j])
            if not np.all(np.isclose(changed[modified,j],np.round(changed[modified,j]),atol=1e-7)):
                raise AssertionError(f'Changed integer feature is noninteger: {column}')
    attacked=clean.copy();attacked[mutable]=changed
    benign=clean.label.to_numpy()==0
    if not np.allclose(attacked.loc[benign,mutable].to_numpy(dtype=float),
                       clean.loc[benign,mutable].to_numpy(dtype=float),equal_nan=True):
        raise AssertionError('Benign predictor changes.')
    immutable=[column for column in clean if column not in mutable]
    if not attacked[immutable].equals(clean[immutable]):
        raise AssertionError('Immutable column changes.')
    family=next((name for name in ATTACK_FAMILIES if artifact.stem.startswith(name+'_')),None)
    if family is None: raise ValueError(f'Unknown cached attack family: {artifact.name}')
    target=(artifact.stem[len(family)+1:match.start()] if family=='single_target_pgd' else None)
    if target is not None and target not in TARGET_NAMES:
        raise ValueError(f'Unexpected direct target: {target}')
    ratio=float(np.max(displacement[eligible]/np.broadcast_to(budget,displacement.shape)[eligible])) if eligible.any() else 0.
    return attacked,clean,{'case':artifact.stem,'case_kind_corrected':'feature_space_attack',
                        'domain_corrected':'source_test','attack_family':family,
                        'attack_target':target,'epsilon':epsilon,'attack_seed':attack_seed},ratio


def predict(models,bundle,frame):
    _,X=scaled(bundle,frame)
    return np.vstack([model.predict_proba(X)[:,1] for model in models])


def scopes(n):
    return [('whole_case',-1,np.arange(n))]+[
        ('window_128',wid,np.arange(start,start+WINDOW_SIZE))
        for wid,start in enumerate(range(0,n-WINDOW_SIZE+1,WINDOW_SIZE))]


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    statuses=[];all_results=[];all_replays=[];all_undefined=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        try:
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            original_dir=INPUT/dataset
            fingerprint=json.loads((original_dir/'input_fingerprint.json').read_text())
            if sha(bundle_path)!=fingerprint['bundle_sha256']:
                raise AssertionError('Frozen real-data bundle changed.')
            bundle=joblib.load(bundle_path)
            bank_dir=locate_models(dataset,fingerprint)
            models=[joblib.load(bank_dir/f'{name}.joblib') for name in MODEL_NAMES]
            reference=pd.read_csv(bank_dir/'real_ID_reference.csv')
            reference_p=predict(models,bundle,reference)
            prepared=prepare_reference(reference_p,reference.label.to_numpy(dtype=int))
            estimates,_,_=estimate(prepared,reference_p)
            if prepared['rank']>=2:
                expected=np.clip(prepared['accuracy'],PROBIT_CLIP,1-PROBIT_CLIP)
                if not np.allclose(estimates['ALine_S'],expected,atol=1e-7) or not np.allclose(estimates['ALine_D'],expected,atol=1e-7):
                    raise AssertionError('Real-reference identity failure.')
            raw=pd.read_csv(original_dir/'neural_accuracy_estimator_results.csv')
            for column in ['actual_accuracy','window']:
                raw[column]=pd.to_numeric(raw[column],errors='coerce')
            clean=source_frame(bundle)
            clean_p=predict(models,bundle,clean)
            clean_labels=clean.label.to_numpy(dtype=int)
            clean_metrics={}
            for scope,wid,index in scopes(len(clean)):
                est,r2,state=estimate(prepared,clean_p[:,index])
                clean_metrics[(scope,wid)]=((clean_p[:,index]>.5)==clean_labels[index]).mean(axis=1),est
            rows=[];verification=[];undefined=[]
            def evaluate(frame,metadata,paired=False):
                p=predict(models,bundle,frame)
                y=frame.label.to_numpy(dtype=int)
                case=metadata['case']
                for scope,wid,index in scopes(len(frame)):
                    truth=((p[:,index]>.5)==y[index]).mean(axis=1)
                    estimates,r2,state=estimate(prepared,p[:,index])
                    if not np.isfinite(r2):
                        undefined.append({'dataset':dataset,'case':case,'scope':scope,'window':wid,
                                          'field':'agreement_line_R2','reason':'undefined diagnostic retained as NaN'})
                    indices=([MODEL_NAMES.index(metadata['attack_target'])]
                             if metadata['attack_family']=='single_target_pgd' else TARGET_INDICES)
                    for j in indices:
                        old=raw[(raw['case']==case)&(raw['scope']==scope)&
                                (raw['window']==wid)&(raw['target_model']==MODEL_NAMES[j])]
                        finite=old['actual_accuracy'].dropna().to_numpy()
                        if len(finite) and not np.allclose(finite,truth[j],atol=1e-7,rtol=1e-7):
                            raise AssertionError(f'Cached actual accuracy mismatch: {case}/{MODEL_NAMES[j]}/{scope}/{wid}')
                        for method,value in estimates.items():
                            actual=float(truth[j]);estimated=safe_number(value[j])
                            if paired:
                                clean_accuracy,clean_estimates=clean_metrics[(scope,wid)]
                                damage=float(clean_accuracy[j]-truth[j])
                                estimated_damage=safe_number(clean_estimates[method][j]-value[j])
                                differential=safe_number(abs(damage-estimated_damage))
                            else:
                                damage=estimated_damage=differential=np.nan
                            if not np.isfinite(estimated):
                                undefined.append({'dataset':dataset,'case':case,'scope':scope,'window':wid,
                                                  'field':method,'reason':state})
                            rows.append({'dataset':dataset,**metadata,'scope':scope,'window':wid,
                                'target_model':MODEL_NAMES[j],'estimator':method,
                                'actual_accuracy':actual,'estimated_accuracy':estimated,
                                'absolute_accuracy_error':safe_number(abs(estimated-actual)),
                                'true_damage':damage,'estimated_damage':estimated_damage,
                                'damage_underestimation':safe_number(damage-estimated_damage),
                                'differential_absolute_error':differential,'agreement_line_R2':r2,
                                'algorithm_status':state})
            evaluate(clean,{'case':'clean_source','case_kind_corrected':'clean_source',
                            'domain_corrected':'clean_source','attack_family':'none',
                            'attack_target':None,'epsilon':np.nan,'attack_seed':np.nan})
            for domain,frame in bundle['evaluation_domains'].items():
                evaluate(frame.reset_index(drop=True),{'case':domain,'case_kind_corrected':'natural_shift',
                    'domain_corrected':domain,'attack_family':'none','attack_target':None,
                    'epsilon':np.nan,'attack_seed':np.nan})
            artifacts=sorted(original_dir.glob('*_eps_*_seed_*.npz'))
            if len(artifacts)!=30:
                raise ValueError(f'Expected 30 completed attack artifacts, found {len(artifacts)}')
            for artifact in artifacts:
                attacked,clean_ordered,metadata,ratio=replay(bundle,artifact)
                if not np.array_equal(clean_ordered['_row_id'].to_numpy(dtype=str),clean['_row_id'].to_numpy(dtype=str)):
                    raise AssertionError('Attack record order differs from the clean paired baseline.')
                evaluate(attacked,metadata,paired=True)
                verification.append({'dataset':dataset,'artifact':artifact.name,
                    'status':'SAVED_ATTACK_REPLAY_VERIFIED','max_budget_ratio':ratio,
                    'optimizer_rerun':False,'model_retrained':False})
                save_csv(rows,directory/'corrected_target_rows.csv')
                save_csv(verification,directory/'saved_attack_replay_checks.csv')
                print(dataset,artifact.stem,'REPLAY + POST-PROCESSING REPAIRED',flush=True)
            results=pd.DataFrame(rows)
            for column in METRICS+['epsilon','attack_seed','agreement_line_R2']:
                results[column]=pd.to_numeric(results[column],errors='coerce')
            keys=['dataset','case_kind_corrected','domain_corrected','attack_family','epsilon','scope','estimator']
            summary=results.groupby(keys,dropna=False).agg(
                reported_rows=('target_model','size'),distinct_trained_targets=('target_model','nunique'),
                valid_estimates=('estimated_accuracy','count'),
                actual_accuracy=('actual_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean'),
                absolute_accuracy_error=('absolute_accuracy_error','mean'),
                true_damage=('true_damage','mean'),estimated_damage=('estimated_damage','mean'),
                differential_absolute_error=('differential_absolute_error','mean')).reset_index()
            save_csv(summary,directory/'corrected_direct_target_summary.csv')
            save_csv(results,directory/'corrected_target_rows.csv')
            save_csv(pd.DataFrame(undefined,columns=['dataset','case','scope','window','field','reason']),
                     directory/'undefined_diagnostics.csv')
            all_results.append(results);all_replays.extend(verification);all_undefined.extend(undefined)
            missing_estimates=int(results['estimated_accuracy'].isna().sum())
            statuses.append({'dataset':dataset,
                'status':'REPAIRED_WITH_UNDEFINED_ESTIMATES' if missing_estimates else 'REPAIRED_AND_REPLAY_VERIFIED',
                'verified_saved_attacks':len(verification),'undefined_estimates':missing_estimates,
                'detail':'Undefined ALine estimates retained, not replaced.' if missing_estimates else ''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','verified_saved_attacks':0,
                             'undefined_estimates':np.nan,'detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    if all_results:
        results=pd.concat(all_results,ignore_index=True)
        save_csv(results,OUT/'all_datasets_corrected_target_rows.csv')
        keys=['dataset','case_kind_corrected','domain_corrected','attack_family','epsilon','scope','estimator']
        summary=results.groupby(keys,dropna=False).agg(
            reported_rows=('target_model','size'),distinct_trained_targets=('target_model','nunique'),
            valid_estimates=('estimated_accuracy','count'),actual_accuracy=('actual_accuracy','mean'),
            estimated_accuracy=('estimated_accuracy','mean'),absolute_accuracy_error=('absolute_accuracy_error','mean'),
            true_damage=('true_damage','mean'),estimated_damage=('estimated_damage','mean'),
            differential_absolute_error=('differential_absolute_error','mean')).reset_index()
        save_csv(summary,OUT/'all_datasets_corrected_direct_target_summary.csv')
        print('\nCORRECTED DIRECT-TARGET SUMMARY\n'+summary.round(4).to_string(index=False),flush=True)
    save_csv(pd.DataFrame(all_replays,columns=['dataset','artifact','status','max_budget_ratio','optimizer_rerun','model_retrained']),
             OUT/'all_saved_attack_replay_checks.csv')
    save_csv(pd.DataFrame(all_undefined,columns=['dataset','case','scope','window','field','reason']),
             OUT/'all_undefined_diagnostics.csv')
    (OUT/'repair_protocol.json').write_text(json.dumps({
        'repair':'Recompute post-processing from frozen real models; no float(None) conversions',
        'missing_data_policy':'NaN for undefined diagnostics, not zero',
        'target_selection':'Three preset MLP32_16 models; directly attacked model only for single-target PGD',
        'aggregation':'Keep clean source, each natural domain, attack family, epsilon, scope and estimator separate',
        'validation':'Replay saved per-record offsets; check budgets/types/immutable values and original actual accuracies',
        'not_performed':['training','PGD rerun','synthetic experiments','confirmatory statistical tests'],
        'scope':'Replaces neural post-processing; does not assert unrelated unseen tasks were completed'},indent=2))
    print('\nREPAIR STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    REPAIR_STATUS=main()
