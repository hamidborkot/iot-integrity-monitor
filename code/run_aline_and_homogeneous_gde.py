"""Compute ALine-S/ALine-D (paper equations 4 and 6) and homogeneous-SGD GDE.
Real saved data only. No provenance approval loop; no synthetic records/labels.
ALine on neural targets is separated from its extension to the frozen logistic target.
GDE estimates homogeneous-family mean accuracy, not arbitrary logistic-primary accuracy.
"""
import hashlib
import importlib.metadata
import json
import runpy
import traceback
import warnings
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from scipy.special import ndtr,ndtri
from sklearn.neural_network import MLPClassifier

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
OUT=BASE/'aline_gde_published_equations_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
WINDOW_SIZE=128
SEEDS=[901,902,903]
RECIPES=[('MLP16',(16,),20),('MLP32',(32,),60),('MLP32_16',(32,16),160)]
PROBIT_CLIP=1e-5
SETTINGS={'datasets':DATASETS,'window_size':WINDOW_SIZE,'seeds':SEEDS,
          'recipes':RECIPES,'solver':'sgd','learning_rate_init':.001,
          'momentum':.9,'alpha':.001,'batch_size':256,
          'early_stopping':False,'probit_clip':PROBIT_CLIP,
          'ALine_equations':'Baek et al., equations (4) and (6)',
          'scope':'Development paper-equation implementation; no author-code bitwise claim'}
SETTINGS_HASH=hashlib.sha256(json.dumps(SETTINGS,sort_keys=True).encode()).hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def input_helpers():
    name='run_md3_and_identifiability_experiments.py'
    paths=sorted({p for root in [Path('/kaggle/input'),Path('/kaggle/working')]
                  if root.exists() for p in root.rglob(name) if p.is_file()},key=lambda p:len(str(p)))
    if not paths:
        raise FileNotFoundError('Keep the previous MD3/bounds script attached; its verified replay helpers are reused.')
    if len({digest(p) for p in paths})!=1:
        raise RuntimeError('Different versions of the previous helper script are attached.')
    module=runpy.run_path(str(paths[0]),run_name='verified_replay_helpers_only')
    return module['cases'],module['scale_frame'],digest(paths[0])


def reference_sample(bundle):
    frame=bundle['known_reference_df']
    target=bundle['train_df']['_family'].value_counts(normalize=True)
    counts=frame['_family'].value_counts()
    if set(target.index)-set(counts.index):
        raise ValueError('Trusted ID reference lacks a training family.')
    total=int(min(counts[f]/target[f] for f in target.index))
    ideals=target*total
    allocation=np.floor(ideals).astype(int)
    remaining=total-int(allocation.sum())
    order=(ideals-allocation).sort_values(ascending=False).index
    for family in order:
        if remaining and allocation[family]<counts[family]:
            allocation[family]+=1;remaining-=1
    if remaining:
        raise AssertionError('Reference allocation did not close.')
    pieces=[frame[frame['_family']==family].sample(int(allocation[family]),random_state=8201+i)
            for i,family in enumerate(target.index) if allocation[family]>0]
    result=pd.concat(pieces,ignore_index=True).sample(frac=1,random_state=8202).reset_index(drop=True)
    if set(result['_row_id'])&set(bundle['source_test_df']['_row_id']):
        raise AssertionError('ID reference/source-test overlap.')
    return result


def agreement(decisions):
    d=decisions.astype(float)
    return (d@d.T+(1-d)@(1-d).T)/decisions.shape[1]


def prepare_aline(reference_decisions,reference_accuracy):
    models=len(reference_accuracy)
    i,j=np.triu_indices(models,1)
    source=agreement(reference_decisions)
    x=ndtri(np.clip(source[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    design=np.column_stack([x,np.ones_like(x)])
    pair_design=np.zeros((len(i),models))
    pair_design[np.arange(len(i)),i]=.5
    pair_design[np.arange(len(i)),j]=.5
    return {'i':i,'j':j,'x':x,'regression_design':design,
            'regression_rank':int(np.linalg.matrix_rank(design)),
            'pair_design':pair_design,'pair_design_rank':int(np.linalg.matrix_rank(pair_design)),
            'z_accuracy':ndtri(np.clip(reference_accuracy,PROBIT_CLIP,1-PROBIT_CLIP)),
            'source_agreement':source}


def aline_predict(prepared,target_decisions):
    # No target labels or target accuracies enter this estimator.
    i,j=prepared['i'],prepared['j']
    target=agreement(target_decisions)
    y=ndtri(np.clip(target[i,j],PROBIT_CLIP,1-PROBIT_CLIP))
    m=target.shape[0]
    if prepared['regression_rank']<2 or prepared['pair_design_rank']<m:
        return {'S':np.full(m,np.nan),'D':np.full(m,np.nan),
                'slope':np.nan,'intercept':np.nan,'agreement_R2':np.nan,
                'status':'RANK_DEFICIENT_NO_VALID_LINE_ESTIMATE'}
    slope,intercept=np.linalg.lstsq(prepared['regression_design'],y,rcond=None)[0]
    fitted=slope*prepared['x']+intercept
    variance=float(np.sum((y-y.mean())**2))
    r2=float(1-np.sum((y-fitted)**2)/variance) if variance>1e-12 else np.nan
    estimate_s=ndtr(slope*prepared['z_accuracy']+intercept)
    rhs=y+slope*((prepared['z_accuracy'][i]+prepared['z_accuracy'][j])*.5-prepared['x'])
    z_ood=np.linalg.lstsq(prepared['pair_design'],rhs,rcond=None)[0]
    return {'S':estimate_s,'D':ndtr(z_ood),'slope':float(slope),'intercept':float(intercept),
            'agreement_R2':r2,'status':'COMPUTED'}


def conformance_check(prepared,decisions,accuracy):
    result=aline_predict(prepared,decisions)
    if result['status']!='COMPUTED':
        return result['status']
    expected=np.clip(accuracy,PROBIT_CLIP,1-PROBIT_CLIP)
    if not np.allclose(result['S'],expected,atol=1e-7,rtol=1e-7):
        raise AssertionError('ALine-S fails its real-reference ID-to-ID identity.')
    if not np.allclose(result['D'],expected,atol=1e-7,rtol=1e-7):
        raise AssertionError('ALine-D fails its real-reference ID-to-ID identity.')
    return 'REAL_REFERENCE_IDENTITY_PASSED'


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    cases,scale_frame,helper_hash=input_helpers()
    settings_path=OUT/'settings.json'
    frozen={'settings_sha256':SETTINGS_HASH,'helper_sha256':helper_hash,'settings':SETTINGS,
            'sklearn_version':importlib.metadata.version('scikit-learn')}
    if settings_path.exists() and json.loads(settings_path.read_text())!=frozen:
        raise RuntimeError('Settings/dependencies changed; use a new output directory.')
    settings_path.write_text(json.dumps(frozen,indent=2))
    statuses=[]
    for dataset in DATASETS:
        directory=OUT/dataset
        directory.mkdir(parents=True,exist_ok=True)
        try:
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            train=bundle['train_df']
            reference=reference_sample(bundle)
            X=scale_frame(bundle,train).to_numpy()
            R=scale_frame(bundle,reference).to_numpy()
            y=train.label.to_numpy(dtype=int)
            reference_y=reference.label.to_numpy(dtype=int)
            models=[];names=[];groups={};training_rows=[]
            for group,architecture,iterations in RECIPES:
                groups[group]=[]
                for seed in SEEDS:
                    model_name=f'{group}_seed_{seed}'
                    model_path=directory/f'{model_name}.joblib'
                    receipt=directory/f'{model_name}.json'
                    fingerprint={'settings_sha256':SETTINGS_HASH,'bundle_sha256':digest(bundle_path)}
                    if model_path.exists() and receipt.exists():
                        if json.loads(receipt.read_text())!=fingerprint:
                            raise RuntimeError('Saved model provenance changed.')
                        model=joblib.load(model_path)
                        warning_messages=['Loaded existing fixed-budget model']
                    else:
                        model=MLPClassifier(hidden_layer_sizes=architecture,solver='sgd',
                            learning_rate='adaptive',learning_rate_init=.001,momentum=.9,
                            alpha=.001,batch_size=min(256,len(X)),max_iter=iterations,
                            early_stopping=False,n_iter_no_change=iterations+1,random_state=seed)
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            model.fit(X,y)
                        warning_messages=[str(w.message) for w in caught]
                        if any(not np.isfinite(a).all() for a in model.coefs_+model.intercepts_):
                            raise ValueError('Nonfinite SGD model parameters; no automatic tuning performed.')
                        joblib.dump(model,model_path,compress=3)
                        receipt.write_text(json.dumps(fingerprint,indent=2))
                    groups[group].append(len(models))
                    models.append(model);names.append(model_name)
                    training_rows.append({'dataset':dataset,'model':model_name,'architecture':str(architecture),
                        'seed':seed,'preset_iterations':iterations,'completed_iterations':model.n_iter_,
                        'training_warning_messages':' | '.join(warning_messages)})
                    print(dataset,model_name,'TRAINED/LOADED',flush=True)
            save_csv(training_rows,directory/'training_records.csv')
            reference_neural=np.vstack([model.predict(R) for model in models]).astype(int)
            reference_primary=(bundle['primary_model'].predict_proba(reference[bundle['primary_features']])[:,1]
                               >bundle['primary_threshold']).astype(int)
            banks={
                'neural_only':(reference_neural,names),
                'logistic_target_extension':(np.vstack([reference_primary,reference_neural]),
                                              ['frozen_logistic_primary']+names)}
            prepared={};reference_accuracies={};checks=[]
            for bank_name,(decisions,model_names) in banks.items():
                acc=(decisions==reference_y).mean(axis=1)
                reference_accuracies[bank_name]=acc
                prepared[bank_name]=prepare_aline(decisions,acc)
                checks.append({'dataset':dataset,'bank':bank_name,'models':len(acc),
                    'regression_rank':prepared[bank_name]['regression_rank'],
                    'pair_equation_rank':prepared[bank_name]['pair_design_rank'],
                    'conformance':conformance_check(prepared[bank_name],decisions,acc)})
            save_csv(checks,directory/'real_reference_conformance.csv')
            reference.to_csv(directory/'real_ID_reference.csv',index=False)
            aline_rows=[];gde_rows=[];line_rows=[]
            seen_physical_cases=set()
            for metadata,frame in cases(bundle,dataset):
                case_hash=hashlib.sha256(pd.util.hash_pandas_object(
                    frame[bundle['primary_features']+['label','_row_id']],index=False
                ).to_numpy().tobytes()).hexdigest()
                if case_hash in seen_physical_cases:
                    continue
                seen_physical_cases.add(case_hash)
                T=scale_frame(bundle,frame).to_numpy()
                neural=np.vstack([model.predict(T) for model in models]).astype(int)
                primary=(bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:,1]
                         >bundle['primary_threshold']).astype(int)
                target_y=frame.label.to_numpy(dtype=int)
                target_banks={'neural_only':neural,'logistic_target_extension':np.vstack([primary,neural])}
                scopes=[('whole_case',-1,np.arange(len(frame)))]
                scopes += [('window_128',wid,np.arange(start,start+WINDOW_SIZE))
                           for wid,start in enumerate(range(0,len(frame)-WINDOW_SIZE+1,WINDOW_SIZE))]
                for scope,wid,index in scopes:
                    common={**metadata,'case_record_sha256':case_hash,'scope':scope,'window':wid,
                            'records':len(index)}
                    for bank_name,target_decisions in target_banks.items():
                        decisions=target_decisions[:,index]
                        predictions=aline_predict(prepared[bank_name],decisions)
                        # Target labels enter ONLY this post-estimation evaluation.
                        actual=(decisions==target_y[index]).mean(axis=1)
                        model_names=banks[bank_name][1]
                        line_rows.append({**common,'bank':bank_name,
                            'status':predictions['status'],'agreement_slope':predictions['slope'],
                            'agreement_intercept':predictions['intercept'],
                            'unlabeled_agreement_R2':predictions['agreement_R2'],
                            'line_R2_ge_0_95':int(np.isfinite(predictions['agreement_R2'])
                                                and predictions['agreement_R2']>=.95)})
                        clean_identity=metadata['case_kind']=='unperturbed'
                        for method in ['S','D']:
                            for j,model_name in enumerate(model_names):
                                estimate=float(predictions[method][j])
                                aline_rows.append({**common,'bank':bank_name,'model':model_name,
                                    'estimator':f'ALine_{method}','true_accuracy':float(actual[j]),
                                    'estimated_accuracy':estimate,'signed_error':estimate-float(actual[j]),
                                    'absolute_error':abs(estimate-float(actual[j])),
                                    'target_kind':'logistic_extension' if model_name=='frozen_logistic_primary' else 'neural',
                                    'algorithm_status':predictions['status']})
                    for group,member_indices in groups.items():
                        decisions=neural[member_indices][:,index]
                        a=agreement(decisions)
                        i,j=np.triu_indices(len(member_indices),1)
                        estimated_family_accuracy=float(a[i,j].mean())
                        actual_family_accuracy=float((decisions==target_y[index]).mean())
                        # Calibration requires labels and is an OFFLINE diagnostic.
                        vote_frequency=decisions.mean(axis=0)
                        ece=0.
                        for level in np.unique(vote_frequency):
                            mask=vote_frequency==level
                            ece+=mask.mean()*abs(target_y[index][mask].mean()-level)
                        gde_rows.append({**common,'homogeneous_training_recipe':group,
                            'independent_training_runs':len(member_indices),
                            'estimator':'GDE_pairwise_family_mean',
                            'true_family_mean_accuracy':actual_family_accuracy,
                            'estimated_family_mean_accuracy':estimated_family_accuracy,
                            'signed_error':estimated_family_accuracy-actual_family_accuracy,
                            'absolute_error':abs(estimated_family_accuracy-actual_family_accuracy),
                            'offline_vote_frequency_calibration_error':float(ece),
                            'estimates_logistic_primary':False})
                save_csv(aline_rows,directory/'aline_results.csv')
                save_csv(gde_rows,directory/'gde_results.csv')
                save_csv(line_rows,directory/'agreement_line_diagnostics.csv')
                print(dataset,metadata['case'],'ALINE + HOMOGENEOUS GDE COMPUTED',flush=True)
            rank_bad=any(row['conformance']=='RANK_DEFICIENT_NO_VALID_LINE_ESTIMATE' for row in checks)
            statuses.append({'dataset':dataset,'status':'COMPUTED_WITH_RANK_FAILURES' if rank_bad else 'COMPUTED',
                             'detail':'Rank-deficient estimates retained as NaN, not replaced.' if rank_bad else ''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    successful={row['dataset'] for row in statuses if row['status']!='FAILED'}
    for filename in ['aline_results.csv','gde_results.csv','agreement_line_diagnostics.csv','real_reference_conformance.csv','training_records.csv']:
        tables=[pd.read_csv(OUT/dataset/filename) for dataset in successful if (OUT/dataset/filename).exists()]
        if tables: save_csv(pd.concat(tables,ignore_index=True),OUT/f'all_datasets_{filename}')
    file=OUT/'all_datasets_aline_results.csv'
    if file.exists():
        results=pd.read_csv(file)
        summary=results.groupby(['dataset','case_kind','scope','bank','estimator','target_kind']).agg(
            evaluated_model_windows=('model','size'),valid_estimates=('estimated_accuracy','count'),
            actual_accuracy=('true_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean'),
            absolute_error=('absolute_error','mean')).reset_index()
        save_csv(summary,OUT/'aline_summary.csv')
        print('\nALINE SUMMARY\n'+summary.round(4).to_string(index=False),flush=True)
    file=OUT/'all_datasets_gde_results.csv'
    if file.exists():
        results=pd.read_csv(file)
        summary=results.groupby(['dataset','case_kind','scope','homogeneous_training_recipe']).agg(
            actual_family_accuracy=('true_family_mean_accuracy','mean'),
            estimated_family_accuracy=('estimated_family_mean_accuracy','mean'),
            absolute_error=('absolute_error','mean'),
            offline_calibration_error=('offline_vote_frequency_calibration_error','mean')).reset_index()
        save_csv(summary,OUT/'gde_summary.csv')
    md3_file=BASE/'md3_library_and_identifiability_bounds_v1'/'all_datasets_md3_results.csv'
    if md3_file.exists():
        md3=pd.read_csv(md3_file)
        if 'case_record_sha256' in md3:
            md3=md3.drop_duplicates(['dataset','case_kind','case_record_sha256'])
        md3_summary=md3.groupby(['dataset','case_kind']).agg(
            unique_recorded_cases=('case','size'),first_warning_fraction=('unlabeled_first_warning','mean'),
            oracle_labels_consumed=('oracle_labels_consumed','sum'),
            label_assisted_confirmation_fraction=('oracle_confirmed_drift','mean')).reset_index()
        save_csv(md3_summary,OUT/'previous_MD3_stage_summary.csv')
        print('\nPREVIOUS MD3 WARNING / ORACLE STAGES\n'+md3_summary.round(4).to_string(index=False),flush=True)
    protocol={
        'baseline_1':'ALine-S equation (4) and ALine-D equation (6), paper-formula implementation',
        'baseline_2':'Homogeneous-SGD pairwise GDE for family mean accuracy',
        'reference':'Real trusted reference subsampled to training-family proportions',
        'label_access':'ID labels for calibration; OOD labels only for post-estimation evaluation',
        'primary':'Original logistic detector unchanged; ALine extension clearly separated',
        'validation':'Real ID-to-ID algebraic identity; not author-code bitwise reproduction',
        'finite_probit_clip':PROBIT_CLIP,
        'limitations':[
            'Algorithm assumptions are empirical and may fail on these shifts',
            'Same-architecture GDE uses three stochastic runs, not a population-expectation certificate',
            'Logistic-target ALine bank is an extension outside the paper neural-only setting',
            'These are transfer evaluations of existing attacks, not adaptive attacks against ALine/GDE',
            'Windows/cases/seeds sharing records are not independent dataset replications',
            'No confirmatory p-values or packet-validity claim',
            'Raw feature-space approval gates are not bypassed by this batch',
            'All nonfinite or rank-deficient results remain visible']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    BASELINE_STATUS=main()
