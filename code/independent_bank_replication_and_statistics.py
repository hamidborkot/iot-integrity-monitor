"""New independent estimator-bank replications and paired conditional-bank bootstrap.
Five whole banks are trained independently per real dataset. A bank, not a model,
window, attack seed, or estimator row, is the resampling unit.
The target is the EXISTING frozen neural MLP32_16_seed_901.
All attack inputs are the already verified saved attacks targeting that model,
the coordinated attacks, and genuine surrogate-transfer attacks.
No feature/label fabrication, no attack reruns, no test-based tuning.
These are conditional-on-fixed-corpus development intervals, NOT confirmation.
"""
import hashlib
import json
import re
import traceback
import warnings
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from scipy.special import ndtr,ndtri
from sklearn.neural_network import MLPClassifier

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
INPUT=BASE/'neural_target_and_coordinated_attacks_v1'
VERIFIED=BASE/'neural_postprocessing_repair_and_replay_v2'
OUT=BASE/'independent_estimator_bank_repetition_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
TARGET_NAME='MLP32_16_seed_901'
BANK_BASE_SEEDS=[2201,2301,2401,2501,2601]
RECIPES=[('MLP16',(16,),20),('MLP32',(32,),60),('MLP32_16',(32,16),160)]
OLD_MODEL_NAMES=[f'{group}_seed_{seed}' for group,_,_ in RECIPES for seed in [901,902,903]]
WINDOW_SIZE=128
PROBIT_CLIP=1e-5
BOOTSTRAP_DRAWS=4000
BOOTSTRAP_SEED=8203
METHODS=['AC','DoC','ALine_S','ALine_D']
SETTINGS={'datasets':DATASETS,'target':TARGET_NAME,'bank_base_seeds':BANK_BASE_SEEDS,
          'recipes':RECIPES,'window_size':WINDOW_SIZE,'probit_clip':PROBIT_CLIP,
          'bootstrap_draws':BOOTSTRAP_DRAWS,'bootstrap_seed':BOOTSTRAP_SEED,
          'comparison_baseline':'DoC','training':'Fixed-budget SGD, no early stopping',
          'learning_rate_init':.001,'momentum':.9,'alpha':.001,
          'statistical_unit':'One newly trained WHOLE estimator bank',
          'inference_scope':'Development; conditional on fixed data, fixed target and fixed attack inputs'}
SETTINGS_HASH=hashlib.sha256(json.dumps(SETTINGS,sort_keys=True).encode()).hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def number(value):
    value=pd.to_numeric(pd.Series([value]),errors='coerce').iloc[0]
    return np.nan if pd.isna(value) else float(value)


def preprocess(bundle,frame):
    primary=bundle['primary_model']
    imputed=primary.named_steps['imputer'].transform(frame[bundle['primary_features']])
    X=primary.named_steps['scaler'].transform(imputed)
    if not np.isfinite(X).all(): raise ValueError('Nonfinite standardized real records.')
    return imputed,X


def original_bank_directory(dataset,fingerprint):
    valid=[]
    for root in BASE.glob('aline_gde_published_equations_v1*'):
        folder=root/dataset
        files=[folder/f'{name}.joblib' for name in OLD_MODEL_NAMES]
        reference=folder/'real_ID_reference.csv'
        if not reference.exists() or not all(path.exists() for path in files): continue
        if sha(reference)!=fingerprint['reference_sha256']: continue
        if all(sha(path)==fingerprint['model_sha256'][name] for name,path in zip(OLD_MODEL_NAMES,files)):
            valid.append(folder)
    if not valid: raise FileNotFoundError(f'{dataset}: original neural bank not found by matching fingerprints.')
    return min(valid,key=lambda path:len(str(path)))


def clean_source(bundle):
    frame=bundle['source_test_df']
    order=np.random.default_rng(1002).permutation(len(frame))
    n=len(frame)//WINDOW_SIZE*WINDOW_SIZE
    return frame.iloc[order[:n]].reset_index(drop=True).copy()


def replay(bundle,artifact):
    with np.load(artifact,allow_pickle=False) as saved:
        ids=saved['source_row_ids'].astype(str)
        mutable=saved['mutable_columns'].astype(str).tolist()
        delta=saved['per_record_delta_standardized'].copy()
    if mutable!=list(bundle['mutable_columns']): raise ValueError('Mutable schema/order changed.')
    parsed=re.search(r'_eps_([0-9]+(?:\.[0-9]+)?)_seed_(\d+)$',artifact.stem)
    if parsed is None: raise ValueError(f'Invalid artifact name {artifact.name}')
    epsilon=float(parsed.group(1));attack_seed=int(parsed.group(2))
    source=bundle['source_test_df'].copy();source['_row_id']=source['_row_id'].astype(str)
    if source['_row_id'].duplicated().any(): raise ValueError('Duplicated real record IDs.')
    original=source.set_index('_row_id',drop=False).loc[ids].reset_index(drop=True).copy()
    imputed,_=preprocess(bundle,original)
    positions=[list(bundle['primary_features']).index(column) for column in mutable]
    scales=bundle['primary_model'].named_steps['scaler'].scale_[positions]
    raw=original[mutable].to_numpy(dtype=float)
    eligible=(original.label.to_numpy()==1)[:,None]&np.isfinite(raw)
    if delta.shape!=raw.shape or not np.isfinite(delta).all(): raise ValueError('Invalid saved per-record offsets.')
    changed=np.where(eligible,imputed[:,positions]+delta*scales[None,:],raw)
    budget=epsilon*scales[None,:]
    if np.any(eligible&(np.abs(changed-raw)>budget+1e-7+1e-10*np.maximum(1,budget))):
        raise AssertionError('Replayed attack budget violation.')
    frame=original.copy();frame[mutable]=changed
    if not frame[[c for c in frame if c not in mutable]].equals(original[[c for c in original if c not in mutable]]):
        raise AssertionError('Immutable data changed.')
    benign=original.label.to_numpy()==0
    if not np.allclose(frame.loc[benign,mutable].to_numpy(dtype=float),raw[benign],equal_nan=True):
        raise AssertionError('Benign values changed.')
    family=next((family for family in ['single_target_pgd','coordinated_ensemble_pgd','genuine_surrogate_transfer']
                 if artifact.stem.startswith(family+'_')),None)
    if family is None: raise ValueError('Unknown attack family.')
    return frame,{'case':artifact.stem,'case_kind':'feature_space_attack','domain':'source_test',
                  'attack_family':family,'epsilon':epsilon,'attack_seed':attack_seed}


def agreement(decisions):
    d=decisions.astype(float)
    return (d@d.T+(1-d)@(1-d).T)/decisions.shape[1]


def prepare_id(probability,labels):
    decisions=probability>.5
    accuracies=(decisions==labels).mean(axis=1)
    m=len(accuracies);i,j=np.triu_indices(m,1)
    x=ndtri(np.clip(agreement(decisions)[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    design=np.column_stack([x,np.ones_like(x)])
    pair_design=np.zeros((len(i),m))
    pair_design[np.arange(len(i)),i]=.5;pair_design[np.arange(len(i)),j]=.5
    return {'i':i,'j':j,'x':x,'design':design,'design_pinv':np.linalg.pinv(design),
            'pair_pinv':np.linalg.pinv(pair_design),'rank':np.linalg.matrix_rank(design),
            'z_accuracy':ndtri(np.clip(accuracies,PROBIT_CLIP,1-PROBIT_CLIP)),
            'accuracy':accuracies,'confidence':np.maximum(probability,1-probability).mean(axis=1)}


def estimates(prepared,probability):
    ac=np.maximum(probability[0],1-probability[0]).mean()
    doc=np.clip(prepared['accuracy'][0]+ac-prepared['confidence'][0],0,1)
    if prepared['rank']<2: return {'AC':number(ac),'DoC':number(doc),'ALine_S':np.nan,'ALine_D':np.nan}
    y=ndtri(np.clip(agreement(probability>.5)[prepared['i'],prepared['j']],PROBIT_CLIP,1-PROBIT_CLIP))
    slope,intercept=prepared['design_pinv']@y
    s=ndtr(slope*prepared['z_accuracy']+intercept)
    i,j=prepared['i'],prepared['j']
    rhs=y+slope*((prepared['z_accuracy'][i]+prepared['z_accuracy'][j])*.5-prepared['x'])
    d=ndtr(prepared['pair_pinv']@rhs)
    return {'AC':number(ac),'DoC':number(doc),'ALine_S':number(s[0]),'ALine_D':number(d[0])}


def scope_indices(n):
    return [('whole_case',-1,np.arange(n))]+[
        ('window_128',wid,np.arange(start,start+WINDOW_SIZE))
        for wid,start in enumerate(range(0,n-WINDOW_SIZE+1,WINDOW_SIZE))]


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    frozen={'settings_sha256':SETTINGS_HASH,'settings':SETTINGS}
    settings_path=OUT/'settings.json'
    if settings_path.exists() and json.loads(settings_path.read_text())!=frozen:
        raise RuntimeError('Settings changed; use a new OUT directory.')
    settings_path.write_text(json.dumps(frozen,indent=2))
    repair_status=pd.read_csv(VERIFIED/'dataset_status.csv')
    passed=set(repair_status.loc[repair_status.status=='REPAIRED_AND_REPLAY_VERIFIED','dataset'])
    statuses=[];all_bank_units=[];all_natural_units=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        try:
            if dataset not in passed: raise RuntimeError('Dataset has not passed the corrected replay audit.')
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            fingerprint=json.loads((INPUT/dataset/'input_fingerprint.json').read_text())
            if sha(bundle_path)!=fingerprint['bundle_sha256']: raise AssertionError('Frozen bundle changed.')
            bundle=joblib.load(bundle_path)
            original_dir=original_bank_directory(dataset,fingerprint)
            target_path=original_dir/f'{TARGET_NAME}.joblib'
            target=joblib.load(target_path)
            reference_path=original_dir/'real_ID_reference.csv'
            reference=pd.read_csv(reference_path)
            _,R=preprocess(bundle,reference)
            _,Xtrain=preprocess(bundle,bundle['train_df'])
            ytrain=bundle['train_df'].label.to_numpy(dtype=int)
            reference_y=reference.label.to_numpy(dtype=int)
            clean=clean_source(bundle)
            case_inputs=[({'case':'clean_source','case_kind':'clean_source','domain':'clean_source',
                          'attack_family':'none','epsilon':np.nan,'attack_seed':np.nan},clean)]
            case_inputs += [({'case':name,'case_kind':'natural_shift','domain':name,'attack_family':'none',
                              'epsilon':np.nan,'attack_seed':np.nan},frame.reset_index(drop=True))
                            for name,frame in bundle['evaluation_domains'].items()]
            selected=[]
            for artifact in sorted((INPUT/dataset).glob('*_eps_*_seed_*.npz')):
                if artifact.stem.startswith('single_target_pgd_') and not artifact.stem.startswith('single_target_pgd_'+TARGET_NAME+'_'):
                    continue
                frame,metadata=replay(bundle,artifact)
                if not np.array_equal(frame['_row_id'].to_numpy(dtype=str),clean['_row_id'].to_numpy(dtype=str)):
                    raise AssertionError('Attack/clean pairing changed.')
                selected.append((metadata,frame))
            if len(selected)!=18: raise ValueError(f'Expected 18 fixed-target/coordinated/transfer artifacts, found {len(selected)}')
            case_inputs+=selected
            cached=[]
            for metadata,frame in case_inputs:
                _,X=preprocess(bundle,frame)
                label=frame.label.to_numpy(dtype=int)
                cached.append((metadata,X,label,target.predict_proba(X)[:,1]))
            invariant={'bundle_sha256':sha(bundle_path),'target_sha256':sha(target_path),
                       'reference_sha256':sha(reference_path),'settings_sha256':SETTINGS_HASH,
                       'attack_sha256':{meta['case']:sha(INPUT/dataset/(meta['case']+'.npz'))
                                       for meta,_ in selected}}
            receipt=directory/'frozen_input_receipt.json'
            if receipt.exists() and json.loads(receipt.read_text())!=invariant: raise RuntimeError('Frozen inputs changed.')
            receipt.write_text(json.dumps(invariant,indent=2))
            case_shapes=[{'dataset':dataset,**meta,'records':len(X)} for meta,X,_,_ in cached]
            save_csv(case_shapes,directory/'evaluation_case_manifest.csv')
            for bank_seed in BANK_BASE_SEEDS:
                bank_dir=directory/f'bank_{bank_seed}';bank_dir.mkdir(parents=True,exist_ok=True)
                bank_units_file=bank_dir/'paired_bank_units.csv'
                natural_units_file=bank_dir/'natural_shift_bank_units.csv'
                complete=bank_dir/'completion.json'
                if complete.exists() and bank_units_file.exists() and natural_units_file.exists():
                    if json.loads(complete.read_text())!=invariant: raise RuntimeError('Completed bank receipt changed.')
                    all_bank_units.append(pd.read_csv(bank_units_file))
                    all_natural_units.append(pd.read_csv(natural_units_file))
                    print(dataset,f'bank={bank_seed}','reused complete bank',flush=True)
                    continue
                new_models=[];training=[]
                for recipe_index,(recipe,architecture,budget) in enumerate(RECIPES):
                    for member in range(3):
                        seed=bank_seed+recipe_index*3+member
                        model_path=bank_dir/f'{recipe}_seed_{seed}.joblib'
                        if model_path.exists(): model=joblib.load(model_path)
                        else:
                            model=MLPClassifier(hidden_layer_sizes=architecture,solver='sgd',learning_rate='adaptive',
                                learning_rate_init=.001,momentum=.9,alpha=.001,batch_size=min(256,len(Xtrain)),
                                max_iter=budget,early_stopping=False,n_iter_no_change=budget+1,random_state=seed)
                            with warnings.catch_warnings(record=True) as captured:
                                warnings.simplefilter('always');model.fit(Xtrain,ytrain)
                            joblib.dump(model,model_path,compress=3)
                            (bank_dir/f'{recipe}_seed_{seed}_warnings.json').write_text(json.dumps([str(w.message) for w in captured],indent=2))
                        if any(not np.isfinite(a).all() for a in model.coefs_+model.intercepts_):
                            raise ValueError('Nonfinite model; no tuning or replacement model generated.')
                        new_models.append(model)
                        training.append({'dataset':dataset,'bank_seed':bank_seed,'member_seed':seed,
                                         'recipe':recipe,'completed_iterations':model.n_iter_,'model_sha256':sha(model_path)})
                        print(dataset,f'bank={bank_seed}',recipe,f'member_seed={seed}','trained/loaded',flush=True)
                save_csv(training,bank_dir/'training_manifest.csv')
                ref_p=np.vstack([target.predict_proba(R)[:,1]]+[model.predict_proba(R)[:,1] for model in new_models])
                prepared=prepare_id(ref_p,reference_y)
                identity=estimates(prepared,ref_p)
                if prepared['rank']>=2:
                    expected=np.clip(prepared['accuracy'][0],PROBIT_CLIP,1-PROBIT_CLIP)
                    if not np.isclose(identity['ALine_S'],expected,atol=1e-7) or not np.isclose(identity['ALine_D'],expected,atol=1e-7):
                        raise AssertionError('Real-reference identity failure.')
                rows=[];clean_values={}
                for metadata,X,label,target_p in cached:
                    probability=np.vstack([target_p]+[model.predict_proba(X)[:,1] for model in new_models])
                    for scope,wid,index in scope_indices(len(X)):
                        truth=float(((target_p[index]>.5)==label[index]).mean())
                        estimated=estimates(prepared,probability[:,index])
                        if metadata['case_kind']=='clean_source': clean_values[(scope,wid)]=(truth,estimated)
                        for method,value in estimated.items():
                            if metadata['case_kind']=='feature_space_attack':
                                clean_accuracy,clean_estimates=clean_values[(scope,wid)]
                                damage=clean_accuracy-truth
                                estimated_damage=clean_estimates[method]-value
                                differential=abs(damage-estimated_damage)
                            else: damage=estimated_damage=differential=np.nan
                            rows.append({'dataset':dataset,'bank_seed':bank_seed,'target_model':TARGET_NAME,
                                **metadata,'scope':scope,'window':wid,'estimator':method,
                                'actual_accuracy':truth,'estimated_accuracy':value,
                                'absolute_accuracy_error':abs(value-truth),'signed_accuracy_error':value-truth,
                                'true_damage':damage,'estimated_damage':estimated_damage,
                                'differential_absolute_error':differential,
                                'agreement_design_rank':prepared['rank']})
                    print(dataset,f'bank={bank_seed}',metadata['case'],'estimated',flush=True)
                results=pd.DataFrame(rows)
                save_csv(results,bank_dir/'estimator_rows.csv')
                # Average windows WITHIN each fixed case, then average fixed attack
                # searches WITHIN a bank. The whole bank remains one statistical unit.
                attacks=results[(results.case_kind=='feature_space_attack')&(results.scope=='window_128')]
                case_means=attacks.groupby(['dataset','bank_seed','attack_family','epsilon','case','estimator']).agg(
                    differential_error=('differential_absolute_error','mean'),
                    true_damage=('true_damage','mean')).reset_index()
                unit=case_means.groupby(['dataset','bank_seed','attack_family','epsilon','estimator']).agg(
                    differential_error=('differential_error','mean'),true_damage=('true_damage','mean'),
                    fixed_attack_cases=('case','nunique')).reset_index()
                save_csv(unit,bank_units_file);all_bank_units.append(unit)
                natural=results[(results.case_kind=='natural_shift')&(results.scope=='window_128')]
                natural_units=natural.groupby(['dataset','bank_seed','domain','estimator']).agg(
                    absolute_error=('absolute_accuracy_error','mean'),
                    signed_error=('signed_accuracy_error','mean'),
                    actual_accuracy=('actual_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean')).reset_index()
                save_csv(natural_units,natural_units_file);all_natural_units.append(natural_units)
                complete.write_text(json.dumps(invariant,indent=2))
                print(dataset,f'bank={bank_seed}','WHOLE-BANK REPETITION COMPLETE',flush=True)
            statuses.append({'dataset':dataset,'status':'FIVE_FRESH_ESTIMATOR_BANKS_COMPUTED','detail':''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    if all_bank_units:
        units=pd.concat(all_bank_units,ignore_index=True)
        save_csv(units,OUT/'all_paired_bank_units.csv')
        interval_rows=[]
        for (dataset,family,epsilon),group in units.groupby(['dataset','attack_family','epsilon']):
            table=group.pivot(index='bank_seed',columns='estimator',values='differential_error')
            for method in ['ALine_S','ALine_D']:
                paired=table[['DoC',method]].dropna()
                gain=(paired['DoC']-paired[method]).to_numpy()
                if len(gain)>=2:
                    rng=np.random.default_rng(BOOTSTRAP_SEED)
                    draws=rng.choice(gain,size=(BOOTSTRAP_DRAWS,len(gain)),replace=True).mean(axis=1)
                    lower,upper=np.quantile(draws,[.025,.975])
                else: lower=upper=np.nan
                interval_rows.append({'dataset':dataset,'attack_family':family,'epsilon':epsilon,
                    'comparison':f'DoC differential error minus {method} differential error',
                    'independent_whole_bank_runs':len(gain),
                    'mean_error_difference':number(np.mean(gain)) if len(gain) else np.nan,
                    'conditional_bank_bootstrap_p025':number(lower),
                    'conditional_bank_bootstrap_p975':number(upper),
                    'interpretation':'Positive favors ALine; negative favors DoC',
                    'interval_scope':'Conditional on fixed corpus, fixed target and fixed attack cases',
                    'few_bank_units_warning':int(len(gain)<10),'confirmatory_test':False})
        save_csv(interval_rows,OUT/'paired_conditional_bank_intervals.csv')
        print('\nPAIRED CONDITIONAL-BANK INTERVALS\n'+pd.DataFrame(interval_rows).round(4).to_string(index=False),flush=True)
    if all_natural_units:
        natural=pd.concat(all_natural_units,ignore_index=True)
        save_csv(natural,OUT/'all_natural_shift_bank_units.csv')
        summary=natural.groupby(['dataset','domain','estimator']).agg(
            whole_banks=('bank_seed','nunique'),actual_accuracy=('actual_accuracy','mean'),
            estimated_accuracy=('estimated_accuracy','mean'),absolute_error=('absolute_error','mean'),
            signed_error=('signed_error','mean')).reset_index()
        save_csv(summary,OUT/'natural_shift_replication_summary.csv')
    protocol={
      'experiments':['Five independently trained estimator banks per dataset','Paired whole-bank bootstrap differences'],
      'target':'Existing frozen neural MLP32_16_seed_901, unchanged',
      'inputs':'Existing real source/reference/natural-shift data and verified attack artifacts',
      'replication_randomness':'All nine estimator-bank members freshly initialized in each bank',
      'resampling_unit':'One entire bank; never a window, individual model, attack strength or search iteration',
      'uncertainty':'Exploratory percentile bootstrap conditional on fixed empirical corpus and fixed attack design',
      'limitations':['Only five bank units; uncertainty intervals can be unstable',
                     'New random seeds do not create new independent datasets or source-domain pairs',
                     'The attacks are transferred to new estimator banks, not reoptimized against them',
                     'No confirmatory p-values, Holm-adjusted primary-family claims, or blind-dataset claim',
                     'No physical packet validity or provenance approval inferred',
                     'Primary-target training uncertainty and corpus-sampling uncertainty are not covered'],
      'no_synthetic_records_or_labels':True}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    BANK_REPLICATION_STATUS=main()
