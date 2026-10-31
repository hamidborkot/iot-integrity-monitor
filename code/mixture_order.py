"""Two real-record stress experiments; no training or gate tuning.
1. Controlled class-mixture sampling of existing source-test records.
2. Random-window versus raw-file-order evaluation on identical record pools.
Labels are never changed. File order is NOT claimed to be chronological.
No experimental results are produced when this file is merely imported.
"""
import hashlib
import json
import traceback
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
CAL=BASE/'reference_mixture_calibration_audit_v1'
AUDIT=BASE/'verified_witness_and_estimator_blindness_v1'
OUT=BASE/'real_record_mixture_and_order_stress_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
CONFIGURATIONS=[('logistic_existing',10)]+[('MLP',s) for s in [10,11,12]]+[('GBDT',s) for s in [10,11,12]]
WINDOW_SIZE=128
TARGET_ATTACK_FRACTIONS=[0.0,0.10,0.25,0.50,0.75,0.90,1.0]
SAMPLING_SEEDS=[701,702,703]
MAX_WINDOWS_PER_MIXTURE=20
ESTIMATORS=['AC','DoC','ATC','MAJ_primary_agreement','WACC_primary_agreement',
            'DRIFTONLY_primary_agreement','ANCH_primary_agreement']
SETTINGS={
    'datasets':DATASETS,'configurations':CONFIGURATIONS,'window_size':WINDOW_SIZE,
    'target_attack_fractions':TARGET_ATTACK_FRACTIONS,'sampling_seeds':SAMPLING_SEEDS,
    'max_windows_per_mixture':MAX_WINDOWS_PER_MIXTURE,
    'ordering_modes':['random_record_order','raw_file_record_order'],
    'estimator_names':ESTIMATORS,
    'interpretation':'Controlled resampling/order stress of actual recorded data; not population prevalence or chronological streams'}
SETTINGS_HASH=hashlib.sha256(json.dumps(SETTINGS,sort_keys=True).encode()).hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def predict(bundle,bank,frame):
    p=bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:,1]
    v=np.vstack([bank['models'][view].predict_proba(frame[columns])[:,1]
                 for view,columns in bundle['semantic_views'].items()])
    return p,v


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
    for left in range(len(v)):
        for right in range(left+1,len(v)):
            columns.append((vd[left]==vd[right]).mean(axis=1))
    return np.column_stack(columns)


def gate(bundle,bank,p,v):
    matrix=signature_matrix(bundle,bank,p,v)
    values=[]
    for name in ['normal','known']:
        center,scale,threshold=bank['profiles'][name]
        values.append(np.abs((matrix-center)/scale).mean(axis=1)/threshold)
    return np.min(np.vstack(values),axis=0)


def reference_stats(bundle,bank):
    frame=bundle['known_reference_df']
    target=bundle['train_df']['_family'].value_counts(normalize=True)
    available=frame['_family'].value_counts()
    missing=set(target.index)-set(available.index)
    if missing:
        raise ValueError(f'Missing training families in reference: {missing}')
    weights=np.asarray([target.get(f,0)/available[f] for f in frame['_family']],dtype=float)
    weights/=weights.sum()
    p,v=predict(bundle,bank,frame)
    y=frame.label.to_numpy()
    pd=p>bundle['primary_threshold']
    vd=v>np.asarray(bank['thresholds'])[:,None]
    confidence=np.maximum(p,1-p)
    reference_accuracy=float(np.dot(weights,pd==y))
    order=np.argsort(confidence,kind='stable')
    index=min(len(order)-1,np.searchsorted(np.cumsum(weights[order]),1-reference_accuracy))
    return {
        'accuracy':reference_accuracy,'confidence':float(np.dot(weights,confidence)),
        'atc_threshold':float(confidence[order[index]]),
        'view_accuracy':((vd==y)*weights[None,:]).sum(axis=1),
        'view_positive_rate':(vd*weights[None,:]).sum(axis=1)}


def estimated_accuracies(bundle,bank,p,v,reference):
    n=len(p)//WINDOW_SIZE
    p=p.reshape(n,WINDOW_SIZE)
    v=v.reshape(len(v),n,WINDOW_SIZE)
    pd=p>bundle['primary_threshold']
    vd=v>np.asarray(bank['thresholds'])[:,None,None]
    confidence=np.maximum(p,1-p)
    competence=np.clip(reference['view_accuracy'],.51,.99)
    competence_weights=np.maximum(np.log(competence/(1-competence)),.05)
    result={
        'AC':confidence.mean(axis=1),
        'DoC':np.clip(reference['accuracy']+confidence.mean(axis=1)-reference['confidence'],0,1),
        'ATC':(confidence>=reference['atc_threshold']).mean(axis=1)}
    for name in ESTIMATORS[3:]:
        result[name]=np.empty(n)
    for wid in range(n):
        drift=reference['view_positive_rate']-vd[:,wid].mean(axis=1)
        lower=drift[drift<=np.median(drift)]
        tau=max(.02,2*1.4826*np.median(np.abs(lower-np.median(lower))))
        excess=np.maximum(drift-np.quantile(drift,.2),0)
        dw=np.exp(-np.minimum((excess/tau)**2,50))
        for name,weights in [
            ('MAJ_primary_agreement',np.ones(len(v))),
            ('WACC_primary_agreement',competence_weights),
            ('DRIFTONLY_primary_agreement',dw),
            ('ANCH_primary_agreement',competence_weights*dw)]:
            voted=np.average(vd[:,wid].astype(float),axis=0,weights=weights)>.5
            result[name][wid]=(voted==pd[wid]).mean()
    return result


def mixture_windows(frame,target,seed):
    normal=np.flatnonzero(frame.label.to_numpy()==0)
    attack=np.flatnonzero(frame.label.to_numpy()==1)
    attack_per_window=int(round(target*WINDOW_SIZE))
    normal_per_window=WINDOW_SIZE-attack_per_window
    limits=[MAX_WINDOWS_PER_MIXTURE]
    if attack_per_window:
        limits.append(len(attack)//attack_per_window)
    if normal_per_window:
        limits.append(len(normal)//normal_per_window)
    count=min(limits)
    if count<1:
        raise ValueError(f'Insufficient actual rows for target class fraction {target}')
    rng=np.random.default_rng(seed)
    normal=rng.permutation(normal)
    attack=rng.permutation(attack)
    windows=[]
    for i in range(count):
        indices=np.r_[normal[i*normal_per_window:(i+1)*normal_per_window],
                      attack[i*attack_per_window:(i+1)*attack_per_window]]
        indices=rng.permutation(indices)
        if len(indices)!=WINDOW_SIZE or len(set(indices))!=WINDOW_SIZE:
            raise AssertionError('Invalid real-record stress window.')
        windows.append(indices)
    if len(set(np.concatenate(windows)))!=count*WINDOW_SIZE:
        raise AssertionError('Record repeated within one mixture/seed condition.')
    return windows


def order_windows(frame,mode):
    # First select the same complete record pool for BOTH ordering conditions.
    usable=len(frame)//WINDOW_SIZE*WINDOW_SIZE
    selected=np.random.default_rng(1002).permutation(len(frame))[:usable]
    if mode=='raw_file_record_order':
        locations=frame.iloc[selected]['_row_id'].astype(str).str.rsplit(':',n=1,expand=True)
        positions=pd.to_numeric(locations.iloc[:,1],errors='raise').to_numpy()
        filenames=locations.iloc[:,0].to_numpy(dtype=str)
        selected=selected[np.lexsort((positions,filenames))]
    elif mode!='random_record_order':
        raise ValueError(mode)
    return [selected[start:start+WINDOW_SIZE] for start in range(0,usable,WINDOW_SIZE)]


def evaluate_windows(bundle,bank,frame,all_p,all_v,windows,reference,common):
    if not windows:
        raise ValueError('No complete windows in this condition.')
    indices=np.concatenate(windows)
    p=all_p[indices]
    v=all_v[:,indices]
    y=frame.label.to_numpy()[indices].reshape(-1,WINDOW_SIZE)
    pd=(p>bundle['primary_threshold']).reshape(-1,WINDOW_SIZE)
    vd=(v>np.asarray(bank['thresholds'])[:,None]).reshape(len(v),-1,WINDOW_SIZE)
    accuracy=(pd==y).mean(axis=1)
    view_accuracy=(vd==y[None,:,:]).mean(axis=2)
    scores=gate(bundle,bank,p,v)
    estimates=estimated_accuracies(bundle,bank,p,v,reference)
    rows=[]
    errors=[]
    ids=frame['_row_id'].astype(str).to_numpy()
    for wid,index in enumerate(windows):
        row_ids=ids[index]
        window_hash=hashlib.sha256('\n'.join(row_ids).encode()).hexdigest()
        accepted=bool(scores[wid]<=1)
        base={**common,'window':wid,'window_row_sha256':window_hash}
        rows.append({**base,
            'records':WINDOW_SIZE,'observed_attack_fraction':float(y[wid].mean()),
            'primary_accuracy':float(accuracy[wid]),
            'mean_view_accuracy':float(view_accuracy[:,wid].mean()),
            'minimum_view_accuracy':float(view_accuracy[:,wid].min()),
            'view_quality_ge_0_80':int(view_accuracy[:,wid].mean()>=.80),
            'support_score':float(scores[wid]),'accepted':int(accepted),
            'abstained':int(not accepted),
            'accepted_primary_error':float(1-accuracy[wid]) if accepted else np.nan,
            'feature_perturbation_performed':False})
        for estimator in ESTIMATORS:
            estimate=float(estimates[estimator][wid])
            errors.append({**base,'estimator':estimator,
                'actual_accuracy':float(accuracy[wid]),'estimated_accuracy':estimate,
                'signed_error':estimate-float(accuracy[wid]),
                'absolute_error':abs(estimate-float(accuracy[wid])),
                'accepted':int(accepted)})
    return rows,errors,indices


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    settings_file=OUT/'settings.json'
    if settings_file.exists() and json.loads(settings_file.read_text())['settings_sha256']!=SETTINGS_HASH:
        raise RuntimeError('Settings changed; use a new OUT directory.')
    settings_file.write_text(json.dumps({'settings_sha256':SETTINGS_HASH,'settings':SETTINGS},indent=2))
    audit_status=pd.read_csv(AUDIT/'dataset_status.csv')
    verified=set(audit_status.loc[audit_status.status=='VERIFIED_AND_AUDITED','dataset'])
    statuses=[]
    for dataset in DATASETS:
        dataset_dir=OUT/dataset
        dataset_dir.mkdir(parents=True,exist_ok=True)
        try:
            if dataset not in verified:
                raise RuntimeError('Previous real-witness audit did not succeed for this dataset.')
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            source=bundle['source_test_df']
            for family,view_seed in CONFIGURATIONS:
                bank_path=CAL/dataset/f'{family}_seed_{view_seed}'/'aligned_view_bank.joblib'
                bank=joblib.load(bank_path)
                directory=dataset_dir/f'{family}_seed_{view_seed}'
                directory.mkdir(parents=True,exist_ok=True)
                fingerprint={
                    'bundle_sha256':hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                    'bank_sha256':hashlib.sha256(bank_path.read_bytes()).hexdigest(),
                    'settings_sha256':SETTINGS_HASH}
                completion=directory/'completion.json'
                required=['window_results.csv','estimator_results.csv','row_selection_manifest.csv']
                if completion.exists():
                    if json.loads(completion.read_text())!=fingerprint:
                        raise RuntimeError('Frozen inputs changed; use a new output directory.')
                    if all((directory/name).exists() for name in required):
                        print(dataset,family,f'view_seed={view_seed}','already complete',flush=True)
                        continue
                reference=reference_stats(bundle,bank)
                rows=[]
                errors=[]
                selections=[]
                p,v=predict(bundle,bank,source)
                # EXPERIMENT 1: actual-record class-mixture stress.
                for seed in SAMPLING_SEEDS:
                    for target in TARGET_ATTACK_FRACTIONS:
                        windows=mixture_windows(source,target,seed)
                        common={
                            'dataset':dataset,'family':family,'view_seed':view_seed,
                            'experiment':'real_record_class_mixture',
                            'domain':'clean_source','ordering':'controlled_real_record_sampling',
                            'target_attack_fraction':target,'sampling_seed':seed}
                        a,b,indices=evaluate_windows(bundle,bank,source,p,v,windows,reference,common)
                        rows.extend(a);errors.extend(b)
                        selections.extend([{**common,'window':wid,'position_in_window':j,
                            'row_id':str(source.iloc[int(index)]['_row_id'])}
                            for wid,index_array in enumerate(windows) for j,index in enumerate(index_array)])
                print(dataset,family,f'view_seed={view_seed}','REAL-MIXTURE STRESS COMPLETE',flush=True)
                # EXPERIMENT 2: same actual rows, different ordering.
                domains={'clean_source':source,**bundle['evaluation_domains']}
                for domain,frame in domains.items():
                    if len(frame)<WINDOW_SIZE:
                        raise ValueError(f'{domain}: no complete real-record windows.')
                    domain_p,domain_v=(p,v) if domain=='clean_source' else predict(bundle,bank,frame)
                    random_windows=order_windows(frame,'random_record_order')
                    file_windows=order_windows(frame,'raw_file_record_order')
                    if set(np.concatenate(random_windows))!=set(np.concatenate(file_windows)):
                        raise AssertionError('Ordering comparison used different record pools.')
                    for mode,windows in [('random_record_order',random_windows),
                                         ('raw_file_record_order',file_windows)]:
                        common={
                            'dataset':dataset,'family':family,'view_seed':view_seed,
                            'experiment':'real_record_order_stress',
                            'domain':domain,'ordering':mode,
                            'target_attack_fraction':np.nan,'sampling_seed':1002}
                        a,b,indices=evaluate_windows(bundle,bank,frame,domain_p,domain_v,windows,reference,common)
                        rows.extend(a);errors.extend(b)
                        selections.extend([{**common,'window':wid,'position_in_window':j,
                            'row_id':str(frame.iloc[int(index)]['_row_id'])}
                            for wid,index_array in enumerate(windows) for j,index in enumerate(index_array)])
                save_csv(rows,directory/'window_results.csv')
                save_csv(errors,directory/'estimator_results.csv')
                save_csv(selections,directory/'row_selection_manifest.csv')
                completion.write_text(json.dumps(fingerprint,indent=2))
                print(dataset,family,f'view_seed={view_seed}','REAL-ORDER STRESS COMPLETE',flush=True)
            statuses.append({'dataset':dataset,'status':'BOTH_REAL_RECORD_STRESS_EXPERIMENTS_COMPLETE','detail':''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','detail':str(error)})
            (dataset_dir/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    successful={row['dataset'] for row in statuses if row['status']=='BOTH_REAL_RECORD_STRESS_EXPERIMENTS_COMPLETE'}
    window_tables=[];error_tables=[]
    for dataset in sorted(successful):
        for family,seed in CONFIGURATIONS:
            directory=OUT/dataset/f'{family}_seed_{seed}'
            window_tables.append(pd.read_csv(directory/'window_results.csv'))
            error_tables.append(pd.read_csv(directory/'estimator_results.csv'))
    grouping=['dataset','family','view_seed','experiment','domain','ordering','target_attack_fraction']
    if window_tables:
        windows=pd.concat(window_tables,ignore_index=True)
        save_csv(windows,OUT/'all_datasets_window_results.csv')
        summary=windows.groupby(grouping,dropna=False).agg(
            evaluated_windows=('window','size'),
            observed_attack_fraction=('observed_attack_fraction','mean'),
            primary_accuracy=('primary_accuracy','mean'),
            mean_view_accuracy=('mean_view_accuracy','mean'),
            trusted_coverage=('accepted','mean'),
            clean_abstain_rate=('abstained','mean'),
            trusted_primary_risk=('accepted_primary_error','mean'),
            mean_support_score=('support_score','mean')).reset_index()
        save_csv(summary,OUT/'all_datasets_stress_summary.csv')
        # Development quality-boundary diagnostic; not the untouched fifth-dataset test.
        boundary=windows.groupby(['dataset','family','experiment','view_quality_ge_0_80']).agg(
            evaluated_windows=('window','size'),primary_accuracy=('primary_accuracy','mean'),
            trusted_coverage=('accepted','mean'),
            trusted_primary_risk=('accepted_primary_error','mean')).reset_index()
        save_csv(boundary,OUT/'retrospective_view_quality_boundary.csv')
        print('\nREAL-RECORD STRESS SUMMARY\n'+summary.round(4).to_string(index=False),flush=True)
    if error_tables:
        errors=pd.concat(error_tables,ignore_index=True)
        save_csv(errors,OUT/'all_datasets_estimator_results.csv')
        error_summary=errors.groupby(grouping+['estimator'],dropna=False).agg(
            actual_accuracy=('actual_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean'),
            signed_error=('signed_error','mean'),absolute_error=('absolute_error','mean')).reset_index()
        save_csv(error_summary,OUT/'all_datasets_estimator_stress_summary.csv')
    # Surface the numerical results from the previous audit, not just its completion log.
    previous_summary=AUDIT/'all_datasets_estimator_summary.csv'
    if previous_summary.exists():
        prior=pd.read_csv(previous_summary)
        accepted=prior[(prior.panel=='accepted_collapses')&(prior.candidate_kind=='objective_selected')]
        save_csv(accepted,OUT/'previous_verified_objective_collapse_estimator_summary.csv')
        if not accepted.empty:
            print('\nPREVIOUS VERIFIED ACCEPTED-COLLAPSE ESTIMATOR RESULTS\n'+
                  accepted.round(4).to_string(index=False),flush=True)
    protocol={
        'data':'Existing real records only; original predictors and labels unchanged',
        'experiments':['Controlled real-record class-mixture stress','Same-pool raw-file-order stress'],
        'models_and_thresholds':'Frozen aligned banks; no refitting or tuning',
        'statistical_status':'Descriptive repeated stress conditions; no independent-replication p-values',
        'limitations':[
            'Controlled class proportions are constructed benchmark conditions, not measured deployment prevalence',
            'Records are reused across different conditions and sampling seeds',
            'Within each mixture/seed condition, records are not repeated',
            'Raw-file ordering is not asserted to be chronological',
            'Unperturbed abstention is not automatically an incorrect integrity decision',
            'Agreement estimators are named proxies, not published-method reproductions',
            'View-quality boundary is retrospective development, not an untouched-dataset confirmation',
            'No new defense, packet validity, universal identifiability proof, or submission-readiness claim']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses


if __name__=='__main__':
    STRESS_STATUS=main()