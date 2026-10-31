"""Saved-attack algebraic-consistency screen and restoration damage-retention audit.
No training, optimization, fabricated records/labels, or provenance approvals.
Rules are CANDIDATE mathematical screens whose feature/extractor mapping needs review.
Passing them is not proof of packet-semantic validity.
Restoration copies newly violating rows from their own real clean counterparts;
it is an offline diagnostic, NOT a deployable defense or primitive recomputation.
"""
import hashlib
import json
import re
import traceback
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
NEURAL=BASE/'neural_target_and_coordinated_attacks_v1'
SHARED=BASE/'aligned_gate_adaptive_evaluation_v1'
CAL=BASE/'reference_mixture_calibration_audit_v1'
OUT=BASE/'saved_attack_algebraic_screen_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
WINDOW_SIZE=128
TARGET_NAMES=[f'MLP32_16_seed_{s}' for s in [901,902,903]]
BANKS=[('logistic_existing',10)]+[('MLP',s) for s in [10,11,12]]+[('GBDT',s) for s in [10,11,12]]
ATOL=1e-7
RTOL=1e-10


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def norm(value): return ''.join(c for c in str(value).lower() if c.isalnum())


def number(value):
    parsed=pd.to_numeric(pd.Series([value]),errors='coerce').iloc[0]
    return np.nan if pd.isna(parsed) else float(parsed)


def column(aliases,columns):
    lookup={norm(c):c for c in columns}
    return next((lookup[norm(alias)] for alias in aliases if norm(alias) in lookup),None)


def make_rules(bundle):
    columns=bundle['primary_features'];rules=[]
    # Explicit candidate mappings. Missing columns are NOT inferred or generated.
    groups=[
      ('generic_packet_size',['Min'],['AVG','Avg'],['Max'],['Std']),
      ('forward_packet_length',['Fwd Packet Length Min','Fwd Pkt Len Min'],
       ['Fwd Packet Length Mean','Fwd Pkt Len Mean'],['Fwd Packet Length Max','Fwd Pkt Len Max'],
       ['Fwd Packet Length Std','Fwd Pkt Len Std']),
      ('backward_packet_length',['Bwd Packet Length Min','Bwd Pkt Len Min'],
       ['Bwd Packet Length Mean','Bwd Pkt Len Mean'],['Bwd Packet Length Max','Bwd Pkt Len Max'],
       ['Bwd Packet Length Std','Bwd Pkt Len Std']),
      ('bidirectional_packet_length',['Packet Length Min','Min Packet Length','Pkt Len Min'],
       ['Packet Length Mean','Pkt Len Mean'],['Packet Length Max','Max Packet Length','Pkt Len Max'],
       ['Packet Length Std','Pkt Len Std'])]
    for group,min_alias,mean_alias,max_alias,std_alias in groups:
        minimum=column(min_alias,columns);mean=column(mean_alias,columns)
        maximum=column(max_alias,columns);std=column(std_alias,columns)
        if minimum and maximum:
            rules.append({'name':group+'_min_le_max','kind':'le','columns':[minimum,maximum]})
        if minimum and mean:
            rules.append({'name':group+'_min_le_mean','kind':'le','columns':[minimum,mean]})
        if mean and maximum:
            rules.append({'name':group+'_mean_le_max','kind':'le','columns':[mean,maximum]})
        if std:
            rules.append({'name':group+'_std_nonnegative','kind':'nonnegative','columns':[std]})
        if minimum and maximum and std:
            # Conservative range bound for usual population/sample standard deviation.
            # Requires all three statistics to describe the same observation set.
            rules.append({'name':group+'_std_le_range_candidate','kind':'std_range','columns':[minimum,maximum,std]})
    for feature in bundle['mutable_columns']:
        # Candidate dimensional screen only; name alone does not prove semantics.
        rules.append({'name':'candidate_nonnegative_'+feature,'kind':'nonnegative','columns':[feature]})
    unique={rule['name']:rule for rule in rules}
    return list(unique.values())


def screen(frame,rules):
    checked=[];passed=[]
    for rule in rules:
        values=frame[rule['columns']].to_numpy(dtype=float)
        observed=np.isfinite(values).all(axis=1)
        tolerance=ATOL+RTOL*np.maximum(1,np.nan_to_num(np.abs(values),nan=0).max(axis=1))
        if rule['kind']=='le': valid=values[:,0]<=values[:,1]+tolerance
        elif rule['kind']=='nonnegative': valid=values[:,0]>=-tolerance
        elif rule['kind']=='std_range': valid=values[:,2]<=values[:,1]-values[:,0]+tolerance
        else: raise ValueError(rule['kind'])
        checked.append(observed);passed.append(observed&valid)
    if not rules:
        return np.zeros((len(frame),0),dtype=bool),np.zeros((len(frame),0),dtype=bool)
    return np.column_stack(checked),np.column_stack(passed)


def preprocess(bundle,frame):
    primary=bundle['primary_model']
    imputed=primary.named_steps['imputer'].transform(frame[bundle['primary_features']])
    return imputed,primary.named_steps['scaler'].transform(imputed)


def original_neural_bank(dataset,fingerprint):
    candidates=[]
    for root in BASE.glob('aline_gde_published_equations_v1*'):
        directory=root/dataset
        files={name:directory/f'{name}.joblib' for name in fingerprint['model_sha256']}
        if all(path.exists() and sha(path)==fingerprint['model_sha256'][name] for name,path in files.items()):
            candidates.append(directory)
    if not candidates: raise FileNotFoundError(f'{dataset}: saved neural-model fingerprints do not match.')
    return min(candidates,key=lambda p:len(str(p)))


def reconstruct(bundle,artifact,kind):
    with np.load(artifact,allow_pickle=False) as saved:
        ids=saved['source_row_ids'].astype(str)
        mutable=saved['mutable_columns'].astype(str).tolist()
        offsets=(saved['objective_selected_offsets'].copy() if kind=='shared_logistic_target'
                 else saved['per_record_delta_standardized'].copy())
    source=bundle['source_test_df'].copy();source['_row_id']=source['_row_id'].astype(str)
    if source['_row_id'].duplicated().any(): raise ValueError('Duplicate source record IDs.')
    clean=source.set_index('_row_id',drop=False).loc[ids].reset_index(drop=True).copy()
    if mutable!=list(bundle['mutable_columns']): raise ValueError('Mutable feature order changed.')
    parsed=re.search(r'(?:^|_)eps_([0-9]+(?:\.[0-9]+)?)',artifact.stem)
    if parsed is None: raise ValueError('Missing recorded epsilon in artifact name.')
    epsilon=float(parsed.group(1))
    if kind=='shared_logistic_target':
        if offsets.shape!=(len(clean)//WINDOW_SIZE,len(mutable)): raise ValueError('Shared offset shape mismatch.')
        delta=np.repeat(offsets,WINDOW_SIZE,axis=0)
    else:
        if offsets.shape!=(len(clean),len(mutable)): raise ValueError('Per-record offset shape mismatch.')
        delta=offsets
    positions=[list(bundle['primary_features']).index(c) for c in mutable]
    scales=bundle['primary_model'].named_steps['scaler'].scale_[positions]
    original=clean[mutable].to_numpy(dtype=float)
    imputed,_=preprocess(bundle,clean)
    base=original if kind=='shared_logistic_target' else imputed[:,positions]
    proposed=base+delta*scales[None,:]
    eligible=(clean.label.to_numpy()==1)[:,None]&np.isfinite(original)
    attacked=clean.copy()
    for j,feature in enumerate(mutable):
        training=bundle['train_df'][feature].dropna().to_numpy(dtype=float)
        training=training[np.isfinite(training)]
        qlow,qhigh=np.quantile(training,[.001,.999])
        budget=epsilon*scales[j]
        low=np.maximum(original[:,j]-budget,np.minimum(original[:,j],qlow))
        high=np.minimum(original[:,j]+budget,np.maximum(original[:,j],qhigh))
        candidate=np.clip(proposed[:,j],low,high)
        if kind=='shared_logistic_target' and np.all(np.isclose(training,np.round(training),atol=1e-8)):
            rounded=np.round(candidate)
            candidate=np.where((rounded>=low)&(rounded<=high),rounded,original[:,j])
        # Per-record artifacts already contain the typed projection; do not
        # round them a second time into a different attack.
        if kind=='per_record_neural_target': candidate=proposed[:,j]
        changed=np.where(eligible[:,j],candidate,original[:,j])
        tolerance=ATOL+RTOL*max(1,budget)
        if np.any(eligible[:,j]&(np.abs(changed-original[:,j])>budget+tolerance)):
            raise AssertionError('Saved attack budget exceeded.')
        if np.any(eligible[:,j]&((changed<low-tolerance)|(changed>high+tolerance))):
            raise AssertionError('Saved attack box violation.')
        attacked[feature]=changed
    benign=clean.label.to_numpy()==0
    if not np.allclose(attacked.loc[benign,mutable].to_numpy(dtype=float),original[benign],equal_nan=True):
        raise AssertionError('Benign values changed.')
    immutable=[c for c in clean if c not in mutable]
    if not attacked[immutable].equals(clean[immutable]): raise AssertionError('Immutable columns changed.')
    return clean,attacked,epsilon


def model_accuracy(bundle,model,frame,neural):
    if neural:
        _,X=preprocess(bundle,frame)
        prediction=model.predict(X)
    else:
        prediction=model.predict_proba(frame[bundle['primary_features']])[:,1]>bundle['primary_threshold']
    correct=prediction==frame.label.to_numpy(dtype=int)
    return float(correct.mean()),correct.reshape(-1,WINDOW_SIZE).mean(axis=1)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    statuses=[];summaries=[];rule_totals=[];manifests=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        try:
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            rules=make_rules(bundle)
            save_csv([{'dataset':dataset,**rule,'columns':'|'.join(rule['columns']),
                       'status':'CANDIDATE_ALGEBRAIC_SCREEN_NOT_PACKET_APPROVAL',
                       'requires_extractor_definition_review':True} for rule in rules],directory/'candidate_rules.csv')
            neural_fingerprint=json.loads((NEURAL/dataset/'input_fingerprint.json').read_text())
            if sha(bundle_path)!=neural_fingerprint['bundle_sha256']: raise AssertionError('Frozen bundle changed.')
            bank_directory=original_neural_bank(dataset,neural_fingerprint)
            neural_models={name:joblib.load(bank_directory/f'{name}.joblib') for name in TARGET_NAMES}
            jobs=[]
            neural_artifacts=sorted((NEURAL/dataset).glob('*_eps_*_seed_*.npz'))
            if len(neural_artifacts)!=30: raise ValueError('Expected 30 saved neural attack cases.')
            for artifact in neural_artifacts:
                target_match=re.match(r'single_target_pgd_(MLP32_16_seed_\d+)_eps_',artifact.stem)
                targets=([target_match.group(1)] if target_match else TARGET_NAMES)
                jobs.append((artifact,'per_record_neural_target',[(name,neural_models[name],True) for name in targets]))
            for family,seed in BANKS:
                root=SHARED/dataset/f'{family}_seed_{seed}'
                fingerprint=json.loads((root/'artifact_fingerprint.json').read_text())
                if fingerprint['bundle_sha256']!=sha(bundle_path): raise AssertionError('Shared-attack bundle hash changed.')
                bank_path=CAL/dataset/f'{family}_seed_{seed}'/'aligned_view_bank.joblib'
                if fingerprint['bank_sha256']!=sha(bank_path): raise AssertionError('Aligned bank changed.')
                artifacts=sorted(root.glob('eps_*_search_*_lambda_*.npz'))
                if len(artifacts)!=12: raise ValueError('Expected 12 shared attack settings per bank.')
                jobs.extend((artifact,'shared_logistic_target',[('frozen_logistic_primary',bundle['primary_model'],False)])
                            for artifact in artifacts)
            window_rows=[];record_rows=[]
            for artifact,kind,targets in jobs:
                clean,attacked,epsilon=reconstruct(bundle,artifact,kind)
                c_checked,c_pass=screen(clean,rules)
                a_checked,a_pass=screen(attacked,rules)
                newly_bad=c_pass&a_checked&~a_pass
                restore=newly_bad.any(axis=1)
                restored=attacked.copy()
                restored.loc[restore,bundle['primary_features']]=clean.loc[restore,bundle['primary_features']]
                original_values=clean[bundle['mutable_columns']].to_numpy(dtype=float)
                attacked_values=attacked[bundle['mutable_columns']].to_numpy(dtype=float)
                modified=~np.isclose(original_values,attacked_values,atol=ATOL,rtol=RTOL,equal_nan=True).all(axis=1)
                observed=a_checked.sum(axis=1)
                violations=(a_checked&~a_pass).sum(axis=1)
                screened_pass=(observed>0)&(violations==0)
                case=f'{artifact.parent.name}/{artifact.stem}'
                for j,rule in enumerate(rules):
                    rule_totals.append({'dataset':dataset,'attack_kind':kind,'case':case,'epsilon':epsilon,
                        'rule':rule['name'],'clean_checked_records':int(c_checked[:,j].sum()),
                        'clean_violating_records':int((c_checked[:,j]&~c_pass[:,j]).sum()),
                        'attack_checked_records':int(a_checked[:,j].sum()),
                        'attack_violating_records':int((a_checked[:,j]&~a_pass[:,j]).sum()),
                        'new_violating_records':int(newly_bad[:,j].sum())})
                for index in range(len(clean)):
                    record_rows.append({'dataset':dataset,'attack_kind':kind,'case':case,'epsilon':epsilon,
                        'row_id':str(clean['_row_id'].iloc[index]),'actually_modified':int(modified[index]),
                        'observed_candidate_checks':int(observed[index]),
                        'candidate_violations':int(violations[index]),
                        'new_violation_restored':int(restore[index]),
                        'candidate_screen_pass':int(screened_pass[index]),
                        'packet_semantic_validity':'NOT_ESTABLISHED'})
                for target_name,model,neural in targets:
                    clean_accuracy,clean_windows=model_accuracy(bundle,model,clean,neural)
                    before,before_windows=model_accuracy(bundle,model,attacked,neural)
                    after,after_windows=model_accuracy(bundle,model,restored,neural)
                    damage_before=clean_accuracy-before;damage_after=clean_accuracy-after
                    summaries.append({'dataset':dataset,'attack_kind':kind,'case':case,'target_model':target_name,
                        'epsilon':epsilon,'records':len(clean),'actually_modified_records':int(modified.sum()),
                        'newly_violating_records_restored':int(restore.sum()),
                        'new_violation_fraction_of_modified':number(restore.sum()/modified.sum()) if modified.any() else np.nan,
                        'candidate_checked_row_fraction':float((observed>0).mean()),
                        'candidate_screen_pass_fraction':number(screened_pass[observed>0].mean()) if (observed>0).any() else np.nan,
                        'clean_accuracy':clean_accuracy,'accuracy_before_restoration':before,
                        'accuracy_after_restoration':after,'damage_before_restoration':damage_before,
                        'damage_after_restoration':damage_after,
                        'damage_retention_ratio':number(damage_after/damage_before) if damage_before>0 else np.nan,
                        'packet_semantic_validity':'NOT_ESTABLISHED','restoration_is_a_defense':False})
                    for wid in range(len(clean_windows)):
                        window_rows.append({'dataset':dataset,'attack_kind':kind,'case':case,'target_model':target_name,
                            'epsilon':epsilon,'window':wid,'clean_accuracy':float(clean_windows[wid]),
                            'damage_before_restoration':float(clean_windows[wid]-before_windows[wid]),
                            'damage_after_restoration':float(clean_windows[wid]-after_windows[wid])})
                save_csv([row for row in summaries if row['dataset']==dataset],directory/'damage_retention_results.csv')
                print(dataset,case,'ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED',flush=True)
            save_csv(window_rows,directory/'window_damage_retention.csv')
            save_csv(record_rows,directory/'record_screen_results.csv')
            statuses.append({'dataset':dataset,'status':'CANDIDATE_SCREEN_AND_RESTORATION_COMPUTED',
                             'saved_cases':len(jobs),'packet_validity_status':'NOT_ESTABLISHED','detail':''})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','saved_cases':0,
                             'packet_validity_status':'NOT_ESTABLISHED','detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    if summaries:
        results=pd.DataFrame(summaries);save_csv(results,OUT/'all_damage_retention_results.csv')
        # Descriptive averages only. Cases include repeated optimization seeds/banks.
        overview=results.groupby(['dataset','attack_kind','target_model','epsilon']).agg(
            recorded_cases=('case','size'),new_violation_fraction_of_modified=('new_violation_fraction_of_modified','mean'),
            clean_accuracy=('clean_accuracy','mean'),damage_before=('damage_before_restoration','mean'),
            damage_after=('damage_after_restoration','mean'),retention_ratio=('damage_retention_ratio','mean')).reset_index()
        save_csv(overview,OUT/'damage_retention_overview.csv')
        print('\nDAMAGE RETENTION AFTER OFFLINE RESTORATION\n'+overview.round(4).to_string(index=False),flush=True)
    save_csv(pd.DataFrame(rule_totals),OUT/'all_rule_violation_results.csv')
    captures=[]
    for root in [Path('/kaggle/input'),Path('/kaggle/working')]:
        if root.exists():
            for path in root.rglob('*'):
                if path.is_file() and any(str(path).lower().endswith(suffix) for suffix in ['.pcap','.pcapng','.pcap.gz','.pcapng.gz']):
                    captures.append({'path':str(path),'bytes':path.stat().st_size,
                                     'record_mapping_to_model_CSV':'NOT_VERIFIED'})
    save_csv(pd.DataFrame(captures,columns=['path','bytes','record_mapping_to_model_CSV']),OUT/'available_packet_capture_inventory.csv')
    protocol={
       'computations':['Candidate algebraic consistency screens','Offline restoration damage retention'],
       'rules':'Nonnegativity and same-statistic-set ordering/range candidates; official mapping review remains necessary',
       'no_synthetic_records_or_labels':True,'optimization_or_training_rerun':False,
       'restoration':'Whole predictor row restored from its own real clean counterpart only when a newly violated observed candidate rule is found',
       'not_a_defense':'Uses the known clean counterpart; not deployable label-free mitigation',
       'not_a_validity_rate':'Candidate-screen pass rate is not a packet-semantic validity rate',
       'limitations':['Missing rule values are unchecked, not valid','Pre-existing clean violations are separately counted',
                      'Some datasets expose too few dependencies for an informative screen',
                      'Derived features are not recomputed from packets','Attack cases sharing data are not independent replications',
                      'PCAP presence alone does not provide mapping or validated extraction'],
       'remaining_physical_requirements':['Approved feature/extractor provenance','Raw trace/CSV record mapping',
                                          'Primitive traffic transformation','Consistent re-extraction and physical validity validation']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    CONSISTENCY_AUDIT_STATUS=main()