"""Closing numerical analyses on the verified saved development artifacts.
No new model fitting, new attack optimization, NF loading, or favorable-result tuning.
Numerical helpers are copied from the supplied notebook cell 77 (one-based).
"""
import gc,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
BASE=Path('/kaggle/working/experiment_suite_20261010T163209808723Z/development')
OUT=BASE.parent/('closing_analyses_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
CONFIGURATIONS=[('logistic_existing',10)]+[(family,seed) for family in ['MLP','GBDT'] for seed in [10,11,12]]
WINDOW_SIZE=128
DAMAGE_THRESHOLD=.05
ATOL=1e-7
COVERAGES=[.25,.50,.75,.85,1.]
ESTIMATORS=['AC','DoC','ATC','primary_view_agreement_proxy','MAJ_primary_agreement',
'WACC_primary_agreement','DRIFTONLY_primary_agreement','ANCH_primary_agreement']
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def save(rows,path,columns=None):
    pd.DataFrame(rows,columns=columns).to_csv(path,index=False)
def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def predict(bundle,bank,frame):
    primary=bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:,1]
    views=np.vstack([bank['models'][view].predict_proba(frame[columns])[:,1]
                     for view,columns in bundle['semantic_views'].items()])
    return primary,views

def signature_matrix(bundle,bank,p,v):
    n=len(p)//WINDOW_SIZE
    p=p.reshape(n,WINDOW_SIZE)
    v=v.reshape(len(v),n,WINDOW_SIZE)
    pd=p>bundle['primary_threshold']
    vd=v>np.asarray(bank['thresholds'])[:,None,None]
    columns=[pd.mean(axis=1),np.maximum(p,1-p).mean(axis=1)]
    for j in range(len(v)):
        columns.extend([vd[j].mean(axis=1),np.maximum(v[j],1-v[j]).mean(axis=1),
                        (vd[j]==pd).mean(axis=1)])
    for j in range(len(v)):
        for k in range(j+1,len(v)):
            columns.append((vd[j]==vd[k]).mean(axis=1))
    return np.column_stack(columns)

def gate(bundle,bank,p,v):
    matrix=signature_matrix(bundle,bank,p,v)
    scores=[]
    for profile in ['normal','known']:
        center,scale,threshold=bank['profiles'][profile]
        scores.append(np.abs((matrix-center)/scale).mean(axis=1)/threshold)
    return np.min(np.vstack(scores),axis=0),matrix

def accuracy(bundle,p,labels):
    return ((p>bundle['primary_threshold'])==labels).reshape(-1,WINDOW_SIZE).mean(axis=1)

def replay(bundle,clean,mutable,offsets,epsilon):
    features=list(bundle['primary_features'])
    all_scales=bundle['primary_model'].named_steps['scaler'].scale_
    scales=np.asarray([all_scales[features.index(c)] for c in mutable])
    if offsets.shape != (len(clean)//WINDOW_SIZE,len(mutable)):
        raise ValueError('Saved offset shape mismatch.')
    origin=clean[mutable].to_numpy(dtype=float)
    proposal=origin+np.repeat(offsets,WINDOW_SIZE,axis=0)*scales[None,:]
    changed=origin.copy()
    mask=clean.label.to_numpy()==1
    max_budget_ratio=0.
    for j,column in enumerate(mutable):
        values=bundle['train_df'][column].dropna().to_numpy(dtype=float)
        values=values[np.isfinite(values)]
        qlow,qhigh=np.quantile(values,[.001,.999])
        budget=epsilon*scales[j]
        low=np.maximum(origin[:,j]-budget,np.minimum(origin[:,j],qlow))
        high=np.minimum(origin[:,j]+budget,np.maximum(origin[:,j],qhigh))
        candidate=np.clip(proposal[:,j],low,high)
        integer=np.all(np.isclose(values,np.round(values),atol=1e-8))
        if integer:
            rounded=np.round(candidate)
            feasible=(rounded>=low)&(rounded<=high)
            candidate=np.where(feasible,rounded,origin[:,j])
        eligible=mask&np.isfinite(origin[:,j])
        changed[:,j]=np.where(eligible,candidate,origin[:,j])
        displacement=np.abs(changed[:,j]-origin[:,j])
        if np.any(eligible&(displacement>budget+ATOL)):
            raise AssertionError('Saved witness violates its epsilon budget.')
        if integer:
            actually_changed=eligible&(displacement>ATOL)
            if not np.all(np.isclose(changed[actually_changed,j],
                                    np.round(changed[actually_changed,j]),atol=1e-8)):
                raise AssertionError('Changed integer coordinate is noninteger.')
        if eligible.any():
            max_budget_ratio=max(max_budget_ratio,float(np.max(displacement[eligible]/budget)))
    attacked=clean.copy()
    attacked[mutable]=changed
    if not np.allclose(attacked.loc[~mask,mutable].to_numpy(dtype=float),
                       clean.loc[~mask,mutable].to_numpy(dtype=float),equal_nan=True):
        raise AssertionError('Benign predictor values changed.')
    immutable=[c for c in clean if c not in mutable]
    if not attacked[immutable].equals(clean[immutable]):
        raise AssertionError('Immutable columns changed.')
    return attacked,max_budget_ratio

def reference_statistics(bundle,bank):
    frame=bundle['known_reference_df']
    target=bundle['train_df']['_family'].value_counts(normalize=True)
    available=frame['_family'].value_counts()
    missing=set(target.index)-set(available.index)
    if missing:
        raise ValueError(f'Reference families missing: {missing}')
    weights=np.asarray([target.get(f,0)/available[f] for f in frame['_family']])
    weights=weights/weights.sum()
    p,v=predict(bundle,bank,frame)
    y=frame.label.to_numpy()
    pd=p>bundle['primary_threshold']
    vd=v>np.asarray(bank['thresholds'])[:,None]
    confidence=np.maximum(p,1-p)
    ref_accuracy=float(np.dot(weights,pd==y))
    order=np.argsort(confidence,kind='stable')
    cumulative=np.cumsum(weights[order])
    quantile_index=min(len(order)-1,np.searchsorted(cumulative,1-ref_accuracy,side='left'))
    return {
        'reference_accuracy':ref_accuracy,
        'reference_confidence':float(np.dot(weights,confidence)),
        'atc_threshold':float(confidence[order[quantile_index]]),
        'view_accuracy':((vd==y)*weights[None,:]).sum(axis=1),
        'view_positive_rate':(vd*weights[None,:]).sum(axis=1),
        'weighted_attack_fraction':float(np.dot(weights,y)),
    }

def estimate_windows(bundle,bank,p,v,reference):
    n=len(p)//WINDOW_SIZE
    p=p.reshape(n,WINDOW_SIZE)
    v=v.reshape(len(v),n,WINDOW_SIZE)
    pd=p>bundle['primary_threshold']
    vd=v>np.asarray(bank['thresholds'])[:,None,None]
    confidence=np.maximum(p,1-p)
    competence=np.clip(reference['view_accuracy'],.51,.99)
    competence_weights=np.maximum(np.log(competence/(1-competence)),.05)
    outputs={key:np.empty(n) for key in ESTIMATORS}
    outputs['AC']=confidence.mean(axis=1)
    outputs['DoC']=np.clip(reference['reference_accuracy']+confidence.mean(axis=1)
                           -reference['reference_confidence'],0,1)
    outputs['ATC']=(confidence>=reference['atc_threshold']).mean(axis=1)
    outputs['primary_view_agreement_proxy']=(vd==pd[None,:,:]).mean(axis=(0,2))
    for wid in range(n):
        drift=reference['view_positive_rate']-vd[:,wid].mean(axis=1)
        lower=drift[drift<=np.median(drift)]
        tau=max(.02,2*1.4826*np.median(np.abs(lower-np.median(lower))))
        excess=np.maximum(drift-np.quantile(drift,.2),0)
        drift_weights=np.exp(-np.minimum((excess/tau)**2,50))
        for name,weights in [
            ('MAJ_primary_agreement',np.ones(len(v))),
            ('WACC_primary_agreement',competence_weights),
            ('DRIFTONLY_primary_agreement',drift_weights),
            ('ANCH_primary_agreement',competence_weights*drift_weights)]:
            vote=np.average(vd[:,wid].astype(float),axis=0,weights=weights)>.5
            outputs[name][wid]=(vote==pd[wid]).mean()
    return outputs

all_summary,all_coverage,all_attribution,failures=[],[],[],[]
record_count=0
for dataset in DATASETS:
    bundle=None
    try:
        bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
        bundle=joblib.load(bundle_path);bundle_hash=sha(bundle_path)
        if bundle.get('run_kind')!='fresh_development_v1':raise ValueError('Unexpected bundle version.')
        if list(bundle['primary_model'].classes_)!=[0,1]:raise ValueError('Primary class order mismatch.')
        source=bundle['source_test_df'].copy();source['_row_id']=source['_row_id'].astype(str)
        if source['_row_id'].duplicated().any():raise ValueError('Duplicate source IDs.')
        source_index=source.set_index('_row_id',drop=False)
        for family,seed in CONFIGURATIONS:
            bank=None
            try:
                bank_path=BASE/'reference_mixture_calibration_audit_v1'/dataset/f'{family}_seed_{seed}'/'aligned_view_bank.joblib'
                bank=joblib.load(bank_path);bank_hash=sha(bank_path)
                views=list(bundle['semantic_views'])
                for view in views:
                    model=bank['models'][view]
                    if list(model.classes_)!=[0,1]:raise ValueError('View class ordering mismatch.')
                    if hasattr(model,'feature_names_in_') and list(model.feature_names_in_)!=list(bundle['semantic_views'][view]):
                        raise ValueError('Predictor order mismatch: '+view)
                reference=reference_statistics(bundle,bank)
                profile_values={name:[np.asarray(v).tolist() for v in bank['profiles'][name]] for name in ['normal','known']}
                config={'dataset':dataset,'family':family,'view_seed':seed,'window_size':WINDOW_SIZE,
                    'classifier_comparison':'>','vote_comparison':'>0.5','gate_comparison':'<=1',
                    'schema':bundle['semantic_views'],'bundle_sha256':bundle_hash,'bank_sha256':bank_hash,
                    'profiles':profile_values,'reference_statistics':{k:np.asarray(v).tolist() for k,v in reference.items()},
                    'monitor_version':'EXISTING_ANCH_PRIMARY_AGREEMENT_WITH_ALIGNED_SUPPORT',
                    'accuracy_estimate_is_conditional_agreement_proxy':True,'source_provenance_approval':False}
                configuration_hash=canonical_hash(config)
                directory=OUT/dataset/f'{family}_seed_{seed}';directory.mkdir(parents=True)
                (directory/'monitor_configuration.json').write_text(json.dumps(config,indent=2))
                windows_rows=[];estimator_rows=[];attribution_rows=[];seen=set()
                evidence_file=(directory/'integrity_records.jsonl').open('w')

                def evaluate(frame,condition,epsilon=None,clean=None,eligible=None):
                    global record_count
                    if len(frame)%WINDOW_SIZE:raise ValueError('Frame is not complete windows.')
                    if frame['label'].isna().any() or not set(frame.label.unique()).issubset({0,1}):
                        raise ValueError('Invalid labels in offline evaluation.')
                    if clean is not None:
                        if not np.array_equal(frame['_row_id'].astype(str),clean['_row_id'].astype(str)):raise ValueError('Row alignment mismatch.')
                        if not np.array_equal(frame.label.to_numpy(),clean.label.to_numpy()):raise ValueError('Labels changed.')
                    p,v=predict(bundle,bank,frame);score,matrix=gate(bundle,bank,p,v)
                    estimates=estimate_windows(bundle,bank,p,v,reference)
                    n=len(p)//WINDOW_SIZE
                    if not np.isfinite(score).all() or any(not np.isfinite(x).all() for x in estimates.values()):
                        raise ValueError('Nonfinite monitor output.')
                    y=frame.label.to_numpy();actual=accuracy(bundle,p,y)
                    pv=p.reshape(n,WINDOW_SIZE);vv=v.reshape(len(v),n,WINDOW_SIZE)
                    vd=vv>np.asarray(bank['thresholds'])[:,None,None]
                    clean_actual=clean_estimates=None
                    if clean is not None:
                        cp,cv=predict(bundle,bank,clean)
                        clean_actual=accuracy(bundle,cp,clean.label.to_numpy())
                        clean_estimates=estimate_windows(bundle,bank,cp,cv,reference)
                    competence=np.clip(reference['view_accuracy'],.51,.99)
                    competence_weights=np.maximum(np.log(competence/(1-competence)),.05)
                    for wid in range(n):
                        if eligible is not None and not bool(eligible[wid]):continue
                        start=wid*WINDOW_SIZE;stop=start+WINDOW_SIZE
                        frame_part=frame.iloc[start:stop]
                        row_hash=hashlib.sha256('\n'.join(frame_part['_row_id'].astype(str)).encode()).hexdigest()
                        predictor_hash=hashlib.sha256(frame_part[bundle['primary_features']].to_numpy(dtype=np.float64).tobytes()).hexdigest()
                        witness=hashlib.sha256((row_hash+predictor_hash).encode()).hexdigest()
                        key=(condition,epsilon,witness)
                        if key in seen:continue
                        seen.add(key)
                        drift=reference['view_positive_rate']-vd[:,wid].mean(axis=1)
                        lower=drift[drift<=np.median(drift)]
                        tau=max(.02,2*1.4826*np.median(np.abs(lower-np.median(lower))))
                        excess=np.maximum(drift-np.quantile(drift,.2),0)
                        drift_weight=np.exp(-np.minimum((excess/tau)**2,50))
                        weight=competence_weights*drift_weight
                        normalized=weight/weight.sum()
                        suspects=[views[i] for i in range(len(views)) if excess[i]>0]
                        accepted=bool(score[wid]<=1)
                        a_hat=float(estimates['ANCH_primary_agreement'][wid])
                        integrity={
                            'processing_timestamp_utc':datetime.now(timezone.utc).isoformat(),
                            'timestamp_is_not_capture_time':True,
                            'dataset':dataset,'family':family,'view_seed':seed,
                            'window_content_sha256':witness,'configuration_sha256':configuration_hash,
                            'conditional_accuracy_estimate':a_hat if accepted else None,
                            'unfiltered_agreement_estimate':a_hat,
                            'estimate_semantics':'weighted_vote_agreement_with_primary_not_accuracy_certificate',
                            'view_weights':{name:float(normalized[i]) for i,name in enumerate(views)},
                            'view_drift':{name:float(drift[i]) for i,name in enumerate(views)},
                            'suspect_channels_diagnostic':suspects,
                            'rho_support_score':float(score[wid]),
                            'state':'ACCEPT_ESTIMATE' if accepted else 'ABSTAIN',
                            'reference_and_schema_sha256':configuration_hash,
                            'packet_validity_established':False,
                        }
                        # Deployment-like record contains no current labels, accuracy, or damage.
                        evidence_file.write(json.dumps(integrity,allow_nan=False)+'\n');record_count+=1
                        damage=float(clean_actual[wid]-actual[wid]) if clean is not None else np.nan
                        pairwise=np.mean([np.mean(vd[i,wid]==vd[j,wid]) for i in range(len(views)) for j in range(i+1,len(views))])
                        windows_rows.append({'dataset':dataset,'family':family,'view_seed':seed,
                            'condition':condition,'epsilon':epsilon,'witness_sha256':witness,
                            'accuracy':float(actual[wid]),'support_score':float(score[wid]),
                            'confidence':float(np.maximum(pv[wid],1-pv[wid]).mean()),
                            'view_agreement':float(pairwise),'accepted':accepted,'true_damage':damage,
                            'accepted_collapse':accepted and np.isfinite(damage) and damage>=DAMAGE_THRESHOLD})
                        for estimator in ESTIMATORS:
                            estimate=float(estimates[estimator][wid])
                            differential=(abs((estimate-actual[wid])-(float(clean_estimates[estimator][wid])-clean_actual[wid]))
                                if clean is not None else np.nan)
                            estimator_rows.append({'dataset':dataset,'family':family,'view_seed':seed,
                                'condition':condition,'epsilon':epsilon,'witness_sha256':witness,
                                'estimator':estimator,'estimated_accuracy':estimate,'actual_accuracy':float(actual[wid]),
                                'absolute_error':abs(estimate-actual[wid]),'differential_error':differential,
                                'accepted':accepted,'true_damage':damage})
                        if clean is not None:
                            truth=set()
                            for name,columns in bundle['semantic_views'].items():
                                a=frame.iloc[start:stop][columns].to_numpy(float)
                                b=clean.iloc[start:stop][columns].to_numpy(float)
                                if not np.allclose(a,b,rtol=0,atol=ATOL,equal_nan=True):truth.add(name)
                            predicted=set(suspects);tp=len(truth&predicted);fp=len(predicted-truth);fn=len(truth-predicted)
                            attribution_rows.append({'dataset':dataset,'family':family,'view_seed':seed,
                                'epsilon':epsilon,'witness_sha256':witness,'changed_channel_count':len(truth),
                                'TP':tp,'FP':fp,'FN':fn,
                                'truth':'changed_encoded_feature_channel_membership_not_causal_packet_source'})

                try:
                    for condition,full in [('source_test',bundle['source_test_df'])]+list(bundle['evaluation_domains'].items()):
                        order=np.random.default_rng(1002).permutation(len(full))
                        usable=len(full)//WINDOW_SIZE*WINDOW_SIZE
                        if not usable:raise ValueError('No full windows in '+condition)
                        evaluate(full.iloc[order[:usable]].reset_index(drop=True),condition)
                    attack_dir=BASE/'aligned_gate_adaptive_evaluation_v1'/dataset/f'{family}_seed_{seed}'
                    fingerprint=json.loads((attack_dir/'artifact_fingerprint.json').read_text())
                    if fingerprint['bundle_sha256']!=bundle_hash or fingerprint['bank_sha256']!=bank_hash:
                        raise ValueError('Attack/bank fingerprint mismatch.')
                    artifacts=sorted(attack_dir.glob('eps_*_search_*_lambda_*.npz'))
                    if len(artifacts)!=12:raise ValueError('Expected 12 saved settings, got '+str(len(artifacts)))
                    for artifact in artifacts:
                        table=pd.read_csv(artifact.with_suffix('.csv')).sort_values('window')
                        with np.load(artifact,allow_pickle=False) as saved:
                            ids=saved['source_row_ids'].astype(str)
                            mutable=saved['mutable_columns'].astype(str).tolist()
                            objective=saved['objective_selected_offsets'].copy()
                            trusted=saved['best_trusted_offsets'].copy()
                            found=saved['trusted_candidate_found'].astype(bool)
                        if mutable!=list(bundle['mutable_columns']):raise ValueError('Mutable order mismatch.')
                        clean=source_index.loc[ids].reset_index(drop=True).copy()
                        if len(clean)%WINDOW_SIZE or len(table)!=len(clean)//WINDOW_SIZE:raise ValueError('Saved attack dimension mismatch.')
                        epsilon=float(table.epsilon.iloc[0])
                        for offsets,eligible in [(objective,None),(trusted,found)]:
                            attacked,ratio=replay(bundle,clean,mutable,offsets,epsilon)
                            evaluate(attacked,'saved_adaptive_candidate',epsilon,clean,eligible)
                finally:evidence_file.close()
                windows_df=pd.DataFrame(windows_rows);estimates_df=pd.DataFrame(estimator_rows)
                windows_df.to_csv(directory/'unique_window_evaluation.csv',index=False)
                estimates_df.to_csv(directory/'estimator_results.csv',index=False)
                save(attribution_rows,directory/'attribution_cases.csv')
                groupkeys=['condition','epsilon']
                for keys,g in windows_df.groupby(groupkeys,dropna=False):
                    condition,epsilon=keys
                    g=g.sort_values('witness_sha256',kind='stable')
                    for target_coverage in COVERAGES:
                        k=max(1,min(len(g),int(np.ceil(target_coverage*len(g)))))
                        for selector,column,ascending in [('support','support_score',True),('confidence','confidence',False),('agreement','view_agreement',False)]:
                            selected=g.sort_values(column,ascending=ascending,kind='stable').iloc[:k]
                            all_coverage.append({'dataset':dataset,'family':family,'view_seed':seed,
                                'condition':condition,'epsilon':epsilon,'selector':selector,
                                'target_coverage':target_coverage,'achieved_coverage':k/len(g),
                                'selected_windows':k,'total_unique_windows':len(g),
                                'selected_detector_error':float(1-selected.accuracy.mean()),
                                'uniform_random_expected_error':float(1-g.accuracy.mean()),
                                'selected_mean_damage':float(selected.true_damage.mean()),
                                'scope':'descriptive_target_ranking_at_matched_coverage_not_deployment_threshold_tuning'})
                    for estimator,eg in estimates_df[(estimates_df.condition==condition)&(estimates_df.epsilon.isna() if pd.isna(epsilon) else estimates_df.epsilon.eq(epsilon))].groupby('estimator'):
                        all_summary.append({'dataset':dataset,'family':family,'view_seed':seed,'condition':condition,'epsilon':epsilon,
                            'estimator':estimator,'unique_windows':len(eg),
                            'mean_absolute_error':float(eg.absolute_error.mean()),
                            'mean_differential_error':float(eg.differential_error.mean()),
                            'accepted_coverage':float(eg.accepted.mean()),
                            'accepted_absolute_error':float(eg.loc[eg.accepted,'absolute_error'].mean()),
                            'confirmatory':False})
                if attribution_rows:
                    at=pd.DataFrame(attribution_rows)
                    for epsilon,ag in at.groupby('epsilon'):
                        tp,fp,fn=ag[['TP','FP','FN']].sum()
                        precision=tp/(tp+fp) if tp+fp else np.nan
                        recall=tp/(tp+fn) if tp+fn else np.nan
                        all_attribution.append({'dataset':dataset,'family':family,'view_seed':seed,'epsilon':epsilon,
                            'unique_cases':len(ag),'TP':int(tp),'FP':int(fp),'FN':int(fn),
                            'precision':precision,'recall':recall,'F1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else np.nan,
                            'scope':'diagnostic_feature_channel_attribution_not_causal_attribution'})
                print(dataset,family,seed,'INTEGRITY / MATCHED COVERAGE / ATTRIBUTION COMPUTED',flush=True)
            except Exception as error:
                failures.append({'dataset':dataset,'family':family,'view_seed':seed,'error':f'{type(error).__name__}: {error}'})
                print(dataset,family,seed,'FAILED',str(error),flush=True)
            finally:
                bank=None;gc.collect()
                save(all_summary,OUT/'estimation_summary.csv')
                save(all_coverage,OUT/'matched_risk_coverage.csv')
                save(all_attribution,OUT/'attribution_summary.csv')
                save(failures,OUT/'failures.csv',['dataset','family','view_seed','error'])
    except Exception as error:
        failures.append({'dataset':dataset,'family':'bundle','view_seed':None,'error':f'{type(error).__name__}: {error}'})
    finally:bundle=None;gc.collect()

# Separate unlabeled MD3 warnings from label-assisted confirmation.
md3_files=list((BASE/'md3_library_and_identifiability_bounds_v1').glob('*/md3_results.csv'))
if md3_files:
    md3=pd.concat([pd.read_csv(p) for p in md3_files],ignore_index=True)
    needed=['dataset','case_kind','unlabeled_first_warning','oracle_confirmed_drift','oracle_labels_consumed']
    if set(needed).issubset(md3):
        report=md3.groupby(['dataset','case_kind']).agg(cases=('dataset','size'),
            unlabeled_warning_rate=('unlabeled_first_warning','mean'),
            label_assisted_confirmation_rate=('oracle_confirmed_drift','mean'),
            mean_confirmation_labels=('oracle_labels_consumed','mean')).reset_index()
        report.to_csv(OUT/'md3_stage_separated_summary.csv',index=False)
    else:
        failures.append({'dataset':'MD3','family':'summary','view_seed':None,'error':'Missing expected MD3 columns; no interpretation invented.'})
else:failures.append({'dataset':'MD3','family':'summary','view_seed':None,'error':'No per-dataset MD3 results found.'})

save(failures,OUT/'failures.csv',['dataset','family','view_seed','error'])
receipt={'output_directory':str(OUT),'integrity_records_emitted':record_count,
    'estimation_summary_rows':len(all_summary),'matched_coverage_rows':len(all_coverage),
    'attribution_summary_rows':len(all_attribution),'explicit_failures':len(failures),
    'new_models_trained':False,'new_attacks_optimized':False,'NF_records_inspected':False,
    'unique_witnesses_independent':False,'confirmation_performed':False,
    'source_provenance_approval_inferred':False,'packet_validity_inferred':False,
    'original_A_to_G_complete':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print('\nFAILURES')
print(pd.DataFrame(failures).to_string(index=False) if failures else 'None')
