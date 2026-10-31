"""Real-data witness verification and conditional-estimator blindness audit.
No training, generated feature records, generated labels, or threshold tuning.
Both objective-selected and best-trusted saved candidates are replayed.
Search repetitions are not treated as independent data/model replications.
"""
import hashlib
import json
import traceback
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

BASE = Path('/kaggle/working/fresh_all_datasets_v1')
ATTACK_ROOT = BASE/'aligned_gate_adaptive_evaluation_v1'
CAL_ROOT = BASE/'reference_mixture_calibration_audit_v1'
OUT = BASE/'verified_witness_and_estimator_blindness_v1'
DATASETS = ['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
CONFIGURATIONS = [('logistic_existing',10)] + [('MLP',s) for s in [10,11,12]] + [('GBDT',s) for s in [10,11,12]]
WINDOW_SIZE = 128
DAMAGE_THRESHOLD = .05
ATOL = 1e-7
ESTIMATORS = ['AC','DoC','ATC','primary_view_agreement_proxy','MAJ_primary_agreement',
              'WACC_primary_agreement','DRIFTONLY_primary_agreement','ANCH_primary_agreement']


def save_csv(rows,path):
    frame = rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


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


def matching(values,expected,name):
    if not np.allclose(values,expected,atol=ATOL,rtol=ATOL,equal_nan=True):
        difference=np.nanmax(np.abs(np.asarray(values)-np.asarray(expected)))
        raise AssertionError(f'{name}: replay mismatch; maximum difference {difference}')


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    statuses=[]
    for dataset in DATASETS:
        dataset_out=OUT/dataset
        dataset_out.mkdir(parents=True,exist_ok=True)
        try:
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            bundle_hash=hashlib.sha256(bundle_path.read_bytes()).hexdigest()
            source=bundle['source_test_df'].copy()
            source['_row_id']=source['_row_id'].astype(str)
            if source['_row_id'].duplicated().any():
                raise ValueError('Duplicated source row IDs.')
            source_index=source.set_index('_row_id',drop=False)
            for family,view_seed in CONFIGURATIONS:
                bank_path=CAL_ROOT/dataset/f'{family}_seed_{view_seed}'/'aligned_view_bank.joblib'
                bank=joblib.load(bank_path)
                bank_hash=hashlib.sha256(bank_path.read_bytes()).hexdigest()
                attack_dir=ATTACK_ROOT/dataset/f'{family}_seed_{view_seed}'
                fingerprint=json.loads((attack_dir/'artifact_fingerprint.json').read_text())
                if fingerprint['bundle_sha256']!=bundle_hash or fingerprint['bank_sha256']!=bank_hash:
                    raise AssertionError('Saved attack inputs no longer match the frozen artifacts.')
                directory=dataset_out/f'{family}_seed_{view_seed}'
                directory.mkdir(parents=True,exist_ok=True)
                reference=reference_statistics(bundle,bank)
                verification_rows=[]
                witness_rows=[]
                estimator_rows=[]
                artifacts=sorted(attack_dir.glob('eps_*_search_*_lambda_*.npz'))
                if len(artifacts)!=12:
                    raise ValueError(f'Expected 12 settings for this bank, found {len(artifacts)}')
                for artifact in artifacts:
                    table=pd.read_csv(artifact.with_suffix('.csv')).sort_values('window')
                    with np.load(artifact,allow_pickle=False) as saved:
                        row_ids=saved['source_row_ids'].astype(str)
                        mutable=saved['mutable_columns'].astype(str).tolist()
                        objective_offsets=saved['objective_selected_offsets'].copy()
                        trusted_offsets=saved['best_trusted_offsets'].copy()
                        trusted_found=saved['trusted_candidate_found'].astype(bool)
                    if mutable!=list(bundle['mutable_columns']):
                        raise ValueError('Mutable-feature order mismatch.')
                    clean=source_index.loc[row_ids].reset_index(drop=True).copy()
                    expected_windows=len(clean)//WINDOW_SIZE
                    if len(clean)%WINDOW_SIZE or len(table)!=expected_windows:
                        raise ValueError('Window/record alignment mismatch.')
                    if not np.array_equal(table.window.to_numpy(),np.arange(expected_windows)):
                        raise ValueError('Saved window numbering mismatch.')
                    epsilon=float(table.epsilon.iloc[0])
                    search_seed=int(table.search_seed.iloc[0])
                    lambda_value=float(table['lambda'].iloc[0])
                    clean_p,clean_v=predict(bundle,bank,clean)
                    clean_accuracy=accuracy(bundle,clean_p,clean.label.to_numpy())
                    clean_gate,clean_signature=gate(bundle,bank,clean_p,clean_v)
                    clean_estimates=estimate_windows(bundle,bank,clean_p,clean_v,reference)
                    matching(clean_accuracy,table.clean_accuracy.to_numpy(),'clean accuracy')
                    row_hash=hashlib.sha256('\n'.join(row_ids).encode()).hexdigest()
                    for candidate_kind,offsets in [('objective_selected',objective_offsets),
                                                   ('best_trusted',trusted_offsets)]:
                        attacked,budget_ratio=replay(bundle,clean,mutable,offsets,epsilon)
                        p,v=predict(bundle,bank,attacked)
                        attacked_accuracy=accuracy(bundle,p,attacked.label.to_numpy())
                        support,signature=gate(bundle,bank,p,v)
                        damage=clean_accuracy-attacked_accuracy
                        selected=(np.ones(expected_windows,dtype=bool)
                                  if candidate_kind=='objective_selected' else trusted_found)
                        if candidate_kind=='objective_selected':
                            matching(attacked_accuracy,table.attacked_accuracy.to_numpy(),'attacked accuracy')
                            matching(damage,table.objective_selected_damage.to_numpy(),'objective damage')
                            matching(support,table.objective_selected_support.to_numpy(),'objective gate score')
                        else:
                            matching(trusted_found.astype(int),table.trusted_candidate_found.to_numpy(),
                                     'trusted candidate flags')
                            matching(damage[selected],table.best_observed_trusted_damage.to_numpy()[selected],
                                     'best-trusted damage')
                            if np.any(support[selected]>1+ATOL):
                                raise AssertionError('Saved best-trusted witness is not accepted on replay.')
                            matching(((damage>=DAMAGE_THRESHOLD)&selected).astype(int),
                                     table.hidden_collapse_found.to_numpy(),'hidden-collapse flags')
                        candidates=estimate_windows(bundle,bank,p,v,reference)
                        offset_hash=hashlib.sha256(offsets.tobytes()+row_hash.encode()).hexdigest()
                        verification_rows.append({
                            'dataset':dataset,'family':family,'view_seed':view_seed,
                            'artifact':artifact.name,'candidate_kind':candidate_kind,
                            'epsilon':epsilon,'search_seed':search_seed,'lambda':lambda_value,
                            'status':'REPLAY_VERIFIED','eligible_windows':int(selected.sum()),
                            'max_budget_ratio':budget_ratio,'candidate_offset_sha256':offset_hash})
                        for wid in np.flatnonzero(selected):
                            accepted=support[wid]<=1
                            collapsed=damage[wid]>=DAMAGE_THRESHOLD
                            witness_id=hashlib.sha256(
                                row_ids[wid*WINDOW_SIZE:(wid+1)*WINDOW_SIZE].tobytes()
                                +offsets[wid].tobytes()).hexdigest()
                            common={
                                'dataset':dataset,'family':family,'view_seed':view_seed,
                                'epsilon':epsilon,'search_seed':search_seed,'lambda':lambda_value,
                                'candidate_kind':candidate_kind,'window':int(wid),
                                'witness_sha256':witness_id,
                                'clean_calibration_pass':int(table.clean_calibration_pass.iloc[0])}
                            witness_rows.append({**common,
                                'clean_accuracy':float(clean_accuracy[wid]),
                                'attacked_accuracy':float(attacked_accuracy[wid]),
                                'true_damage':float(damage[wid]),
                                'clean_support_score':float(clean_gate[wid]),
                                'attacked_support_score':float(support[wid]),
                                'accepted':int(accepted),'collapsed':int(collapsed),
                                'accepted_collapse':int(accepted and collapsed),
                                'max_signature_coordinate_change':float(
                                    np.max(np.abs(signature[wid]-clean_signature[wid]))),
                                'box_type_damage_upper_bound':float(table.box_type_damage_upper_bound.iloc[wid]),
                                'collapse_unreachable_under_box_bound':int(
                                    table.collapse_unreachable_under_box_bound.iloc[wid]),
                                'spsa_search_performed':int(table.spsa_search_performed.iloc[wid])})
                            for estimator in ESTIMATORS:
                                clean_estimate=float(clean_estimates[estimator][wid])
                                attacked_estimate=float(candidates[estimator][wid])
                                estimated_damage=clean_estimate-attacked_estimate
                                clean_error=clean_estimate-clean_accuracy[wid]
                                attack_error=attacked_estimate-attacked_accuracy[wid]
                                estimator_rows.append({**common,'estimator':estimator,
                                    'true_damage':float(damage[wid]),
                                    'estimated_damage':estimated_damage,
                                    'damage_underestimation':float(damage[wid]-estimated_damage),
                                    'clean_estimated_accuracy':clean_estimate,
                                    'attacked_estimated_accuracy':attacked_estimate,
                                    'differential_absolute_error':float(abs(attack_error-clean_error)),
                                    'accepted':int(accepted),'collapsed':int(collapsed),
                                    'accepted_collapse':int(accepted and collapsed)})
                save_csv(verification_rows,directory/'replay_verification.csv')
                witnesses=pd.DataFrame(witness_rows)
                estimator_frame=pd.DataFrame(estimator_rows)
                save_csv(witnesses,directory/'witness_windows.csv')
                save_csv(estimator_frame,directory/'estimator_windows.csv')
                # Identical saved candidates are counted once within a bank and epsilon.
                unique=witnesses.drop_duplicates(['epsilon','witness_sha256'])
                save_csv(unique,directory/'unique_witness_windows.csv')
                summaries=[]
                for (epsilon,kind),group in witnesses.groupby(['epsilon','candidate_kind']):
                    summaries.append({
                        'dataset':dataset,'family':family,'view_seed':view_seed,
                        'epsilon':epsilon,'candidate_kind':kind,
                        'saved_candidate_windows':len(group),
                        'unique_saved_witnesses':group.witness_sha256.nunique(),
                        'mean_true_damage':group.true_damage.mean(),
                        'accepted_fraction':group.accepted.mean(),
                        'accepted_collapse_fraction':group.accepted_collapse.mean(),
                        'clean_calibration_pass':group.clean_calibration_pass.iloc[0],
                        'interpretation':'Descriptive search repetitions; not independent observations'})
                save_csv(summaries,directory/'witness_summary.csv')
                summary_rows=[]
                for panel,subset in [('all_saved_candidates',estimator_frame),
                                     ('accepted_collapses',estimator_frame[estimator_frame.accepted_collapse==1])]:
                    for (epsilon,kind,estimator),group in subset.groupby(['epsilon','candidate_kind','estimator']):
                        summary_rows.append({
                            'dataset':dataset,'family':family,'view_seed':view_seed,
                            'epsilon':epsilon,'candidate_kind':kind,'panel':panel,'estimator':estimator,
                            'candidate_windows':len(group),'mean_true_damage':group.true_damage.mean(),
                            'mean_estimated_damage':group.estimated_damage.mean(),
                            'mean_damage_underestimation':group.damage_underestimation.mean(),
                            'mean_differential_absolute_error':group.differential_absolute_error.mean()})
                save_csv(summary_rows,directory/'estimator_summary.csv')
                (directory/'reference_statistics.json').write_text(json.dumps(
                    {key:(value.tolist() if isinstance(value,np.ndarray) else value)
                     for key,value in reference.items()},indent=2))
                print(dataset,family,f'view_seed={view_seed}','VERIFIED + BLINDNESS AUDITED',flush=True)
            statuses.append({'dataset':dataset,'status':'VERIFIED_AND_AUDITED','detail':''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','detail':str(error)})
            (dataset_out/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    successful={row['dataset'] for row in statuses if row['status']=='VERIFIED_AND_AUDITED'}
    for filename in ['replay_verification.csv','witness_summary.csv','estimator_summary.csv']:
        tables=[]
        for dataset in successful:
            for family,seed in CONFIGURATIONS:
                path=OUT/dataset/f'{family}_seed_{seed}'/filename
                if path.exists(): tables.append(pd.read_csv(path))
        if tables: save_csv(pd.concat(tables,ignore_index=True),OUT/f'all_datasets_{filename}')
    protocol={
        'data':'Existing saved real records and saved attack offsets only',
        'experiments':['Exact failure-witness replay verification','Conditional-estimator damage blindness'],
        'reference_statistics':'Training-family-weighted trusted reference only',
        'agreement_estimators':'Named proxies, not published GDE/ALine reproductions',
        'selection':'All saved settings, both candidate policies; no best-baseline selection',
        'statistical_status':'Descriptive; no p-values or independent-model claims',
        'limitations':[
            'Best-trusted policy has a different denominator from objective-selected policy',
            'Offset deduplication does not create independent dataset replications',
            'Absent accepted collapses on box-unreachable controls are not defense successes',
            'Replay proves the saved feature-space witness, not packet-semantic validity',
            'Accepted signatures are not necessarily identical to clean signatures',
            'This analysis does not prove formal output-only non-identifiability',
            'A universal defense or publication-readiness claim is not supported']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nSTATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses


if __name__=='__main__':
    AUDIT_STATUS=main()
