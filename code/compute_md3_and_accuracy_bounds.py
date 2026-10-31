"""Actual computations on existing real data: library MD3 and sharp accuracy bounds.
No provenance approval flag, feature fabrication, label fabrication, gate tuning,
or packet-validity claims. Internet is required only for installing Menelaus if absent.
"""
import copy
import hashlib
import importlib.metadata
import inspect
import json
import subprocess
import sys
import traceback
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.svm import SVC

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
CAL=BASE/'reference_mixture_calibration_audit_v1'
ATTACKS=BASE/'aligned_gate_adaptive_evaluation_v1'
OUT=BASE/'md3_library_and_identifiability_bounds_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
BANKS=[('logistic_existing',10)]+[('MLP',s) for s in [10,11,12]]+[('GBDT',s) for s in [10,11,12]]
WINDOW_SIZE=128
REFERENCE_CAP_PER_CLASS=2000
SENSITIVITY=2
CV_FOLDS=10
ORACLE_LABEL_BUDGET=128
INSTALL_MISSING_MENELAUS=True


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get_md3():
    try:
        from menelaus.concept_drift.md3 import MD3
    except ImportError:
        if not INSTALL_MISSING_MENELAUS:
            raise RuntimeError('Menelaus is absent; install it or enable INSTALL_MISSING_MENELAUS.')
        subprocess.check_call([sys.executable,'-m','pip','install','--quiet','menelaus'])
        from menelaus.concept_drift.md3 import MD3
    return MD3


def scale_frame(bundle,frame):
    features=bundle['primary_features']
    imputed=bundle['primary_model'].named_steps['imputer'].transform(frame[features])
    scaled=bundle['primary_model'].named_steps['scaler'].transform(imputed)
    if scaled.shape[1]!=len(features) or not np.isfinite(scaled).all():
        raise ValueError('Frozen primary preprocessing is inconsistent.')
    return pd.DataFrame(scaled,columns=[f'x_{i}' for i in range(len(features))])


def ordered_source(bundle):
    frame=bundle['source_test_df']
    order=np.random.default_rng(1002).permutation(len(frame))
    count=len(frame)//WINDOW_SIZE*WINDOW_SIZE
    return frame.iloc[order[:count]].reset_index(drop=True).copy()


def replay(bundle,source_index,artifact):
    table=pd.read_csv(artifact.with_suffix('.csv')).sort_values('window')
    with np.load(artifact,allow_pickle=False) as saved:
        ids=saved['source_row_ids'].astype(str)
        columns=saved['mutable_columns'].astype(str).tolist()
        offsets=saved['objective_selected_offsets'].copy()
    frame=source_index.loc[ids].reset_index(drop=True).copy()
    if columns!=list(bundle['mutable_columns']):
        raise ValueError('Mutable schema mismatch.')
    if offsets.shape!=(len(frame)//WINDOW_SIZE,len(columns)):
        raise ValueError('Saved attack dimensions mismatch.')
    epsilon=float(table.epsilon.iloc[0])
    features=list(bundle['primary_features'])
    all_scales=bundle['primary_model'].named_steps['scaler'].scale_
    scales=np.asarray([all_scales[features.index(c)] for c in columns])
    origin=frame[columns].to_numpy(dtype=float)
    proposal=origin+np.repeat(offsets,WINDOW_SIZE,axis=0)*scales[None,:]
    malicious=frame.label.to_numpy()==1
    for index,column in enumerate(columns):
        values=bundle['train_df'][column].dropna().to_numpy(dtype=float)
        values=values[np.isfinite(values)]
        qlow,qhigh=np.quantile(values,[.001,.999])
        budget=epsilon*scales[index]
        low=np.maximum(origin[:,index]-budget,np.minimum(origin[:,index],qlow))
        high=np.minimum(origin[:,index]+budget,np.maximum(origin[:,index],qhigh))
        candidate=np.clip(proposal[:,index],low,high)
        if np.all(np.isclose(values,np.round(values),atol=1e-8)):
            rounded=np.round(candidate)
            candidate=np.where((rounded>=low)&(rounded<=high),rounded,origin[:,index])
        eligible=malicious&np.isfinite(origin[:,index])
        changed=np.where(eligible,candidate,origin[:,index])
        if np.any(eligible&(np.abs(changed-origin[:,index])>budget+1e-7)):
            raise AssertionError('Replayed budget violation.')
        frame[column]=changed
    p=bundle['primary_model'].predict_proba(frame[features])[:,1]
    accuracy=((p>bundle['primary_threshold'])==frame.label.to_numpy()).reshape(-1,WINDOW_SIZE).mean(axis=1)
    if not np.allclose(accuracy,table.attacked_accuracy.to_numpy(),atol=1e-7,rtol=1e-7):
        raise AssertionError('Objective-candidate replay accuracy mismatch.')
    return frame,table


def cases(bundle,dataset):
    yield {'dataset':dataset,'case_kind':'unperturbed','case':'clean_source'},ordered_source(bundle)
    for name,frame in bundle['evaluation_domains'].items():
        yield {'dataset':dataset,'case_kind':'unperturbed_natural_shift','case':name},frame.reset_index(drop=True)
    source=bundle['source_test_df'].copy()
    source['_row_id']=source['_row_id'].astype(str)
    if source['_row_id'].duplicated().any():
        raise ValueError('Duplicate real source record IDs.')
    source_index=source.set_index('_row_id',drop=False)
    for family,view_seed in BANKS:
        directory=ATTACKS/dataset/f'{family}_seed_{view_seed}'
        bank_path=CAL/dataset/f'{family}_seed_{view_seed}'/'aligned_view_bank.joblib'
        fingerprint=json.loads((directory/'artifact_fingerprint.json').read_text())
        if fingerprint['bundle_sha256']!=sha256(BASE/dataset/f'{dataset}_bundle.joblib'):
            raise AssertionError('Changed frozen bundle.')
        if fingerprint['bank_sha256']!=sha256(bank_path):
            raise AssertionError('Changed aligned view bank.')
        artifacts=sorted(directory.glob('eps_*_search_*_lambda_*.npz'))
        if len(artifacts)!=12:
            raise ValueError(f'{dataset}/{family}/{view_seed}: expected 12 saved settings.')
        for artifact in artifacts:
            frame,table=replay(bundle,source_index,artifact)
            yield {'dataset':dataset,'case_kind':'verified_feature_space_attack',
                   'case':f'{family}_view_{view_seed}_{artifact.stem}',
                   'attacked_monitor_family':family,'attacked_monitor_view_seed':view_seed,
                   'epsilon':float(table.epsilon.iloc[0]),
                   'search_seed':int(table.search_seed.iloc[0]),
                   'lambda':float(table['lambda'].iloc[0])},frame


def accuracy_bounds(bundle,frame,metadata):
    p=bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:,1]
    predicted=p>bundle['primary_threshold']
    rows=[]
    for wid,start in enumerate(range(0,len(frame)-WINDOW_SIZE+1,WINDOW_SIZE)):
        end=start+WINDOW_SIZE
        labels=frame.label.to_numpy()[start:end]
        prediction=predicted[start:end]
        n=WINDOW_SIZE
        positive=int(prediction.sum())
        actual_positive=int(labels.sum())
        # Target-positive count is ORACLE information used only to tighten
        # an offline analytical bound. It is not available to the monitor.
        min_true_positive=max(0,positive+actual_positive-n)
        max_true_positive=min(positive,actual_positive)
        lower=(n-positive-actual_positive+2*min_true_positive)/n
        upper=(n-positive-actual_positive+2*max_true_positive)/n
        true_accuracy=float((prediction==labels).mean())
        if not lower-1e-12<=true_accuracy<=upper+1e-12:
            raise AssertionError('True observed accuracy lies outside the exact count-constrained bounds.')
        rows.append({**metadata,'window':wid,'records':n,
                     'predicted_positive_count':positive,
                     'oracle_actual_positive_count':actual_positive,
                     'observed_true_accuracy':true_accuracy,
                     'count_constrained_accuracy_lower':lower,
                     'count_constrained_accuracy_upper':upper,
                     'count_constrained_ambiguity_width':upper-lower,
                     'count_constrained_minimax_absolute_error_lower_bound':(upper-lower)/2,
                     'no_target_label_assumptions_accuracy_lower':0.,
                     'no_target_label_assumptions_accuracy_upper':1.,
                     'bound_uses_oracle_target_count':True,
                     'new_feature_vectors_generated':False,
                     'new_labels_generated':False})
    return rows


def evaluate_md3(MD3,prototype,bundle,frame,metadata):
    detector=copy.deepcopy(prototype)
    X=scale_frame(bundle,frame)
    primary_p=bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:,1]
    primary_accuracy=float(((primary_p>bundle['primary_threshold'])==frame.label.to_numpy()).mean())
    first_warning=None
    updates=0
    # The unlabeled stage stops at the FIRST request for oracle labels.
    # Continuing without labels would not reproduce the documented lifecycle.
    for i in range(len(X)):
        detector.update(X=X.iloc[[i]].reset_index(drop=True))
        updates+=1
        state=detector.drift_state
        if state in ['warning','drift']:
            first_warning=i
            break
    labels_given=0
    oracle_state=None
    oracle_status='NOT_REQUESTED'
    if first_warning is not None:
        first=first_warning+1
        last=first+ORACLE_LABEL_BUDGET
        if last<=len(frame):
            oracle_status='LABEL_ASSISTED_CONFIRMATION_RUN'
            for i in range(first,last):
                labeled=X.iloc[[i]].reset_index(drop=True).copy()
                labeled['label']=int(frame.label.iloc[i])
                detector.give_oracle_label(labeled)
                labels_given+=1
            oracle_state=detector.drift_state
        else:
            oracle_status='INSUFFICIENT_FUTURE_REAL_LABELS'
    return {**metadata,'records':len(frame),'primary_accuracy':primary_accuracy,
            'monitor':'Menelaus_MD3_separate_linear_SVM',
            'unlabeled_first_warning':int(first_warning is not None),
            'first_warning_record_zero_based':first_warning,
            'first_warning_window_zero_based':None if first_warning is None else first_warning//WINDOW_SIZE,
            'unlabeled_updates':updates,'oracle_labels_consumed':labels_given,
            'oracle_status':oracle_status,'oracle_final_drift_state':oracle_state,
            'oracle_confirmed_drift':int(oracle_state=='drift') if labels_given==ORACLE_LABEL_BUDGET else np.nan,
            'primary_detector_retrained':False,
            'full_method_labels_required':True,
            'stream_order':'Existing case record order; not asserted chronological'}


def write_theory_note():
    note=r"""# Analytical identifiability statements

These are mathematical statements, not experiments with generated labels.
No artificial observations, feature vectors, or label vectors are produced.
The unrestricted result is a basic impossibility lemma, not a novelty claim.

## 1. Output-only worst-case accuracy ambiguity

Fix a finite evaluation window and its observable model-output matrix P,
a frozen primary classifier's binary decisions d, and any identical trusted
source reference information R. Suppose there is no restriction on the
unobserved target binary labels beyond membership in {0,1}^n.

The logical assignments y=d and y=1-d leave (P,R) unchanged, but give primary
accuracy 1 and 0, respectively. For any estimate a(P,R), the triangle inequality
implies |a-1|+|a-0| >= 1. Consequently the maximum absolute error over admissible
label assignments is at least 1/2. The constant estimate 1/2 attains that bound.

This does NOT establish physical realizability of both assignments under an IDS
threat model. Restricting admissible label worlds can narrow the identified set.
Accepted real attack witnesses do not prove identical complete output matrices.

## 2. Sharp bounds when the target-positive count is known

For n records, let a be the number of predicted positives and b the number of
true positives in the target labels (the true-positive CLASS COUNT, not the
confusion-matrix true-positive intersection). Let t be the intersection count.
Then max(0,a+b-n) <= t <= min(a,b), and accuracy is (n-a-b+2t)/n.

Therefore:
  A_min = (n-a-b+2 max(0,a+b-n))/n,
  A_max = (n-a-b+2 min(a,b))/n.

These endpoints are attainable under arbitrary binary label assignments with
exactly b positives, so the identified accuracy interval is sharp in that model.
The minimax absolute estimation error over that interval is its half-width;
the midpoint attains the upper bound and endpoint indistinguishability gives
the matching lower bound.

In the CSV computation, b comes from the real offline evaluation labels.
It is oracle information, not a label-free monitor input. Actual labels are never
changed, and no counterfactual label-vector experiment is run.

## 3. Correct scope of the proposed weighted-integrity condition

With fixed nonnegative weights, correctness signs S_g in {-1,+1}, clean views C,
and attacked views A, a clean-view error rate e_g implies E[S_g]=1-2e_g.
The adversarial-view worst case is E[S_g]>=-1. Thus the expected signed vote
margin is at least sum_C w_g(1-2e_g)-sum_A w_g.

Positivity of this bound establishes positive EXPECTED signed margin. It does
not by itself establish pointwise correctness, >50% majority-vote accuracy,
or an unconditional confidence bound. Those require stronger assumptions,
for example a pointwise clean-margin bound or a justified variance/tail bound.
Training-reference error rates cannot be substituted for target error rates
without a transfer/stability assumption.

Status: theory note and exact finite-window bounds computed. Independent proof
review, physical admissibility assumptions, and originality review remain open.
"""
    (OUT/'analytical_identifiability_note.md').write_text(note)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    md3_class=None
    md3_dependency_error=None
    try:
        md3_class=get_md3()
        source_file=Path(inspect.getsourcefile(md3_class))
        source_bytes=source_file.read_bytes()
        manifest={
            'implementation':'Menelaus MD3, third-party implementation',
            'menelaus_version':importlib.metadata.version('menelaus'),
            'module_source_sha256':hashlib.sha256(source_bytes).hexdigest(),
            'sensitivity':SENSITIVITY,'k':CV_FOLDS,
            'oracle_data_length_required':ORACLE_LABEL_BUDGET,
            'margin_classifier':'sklearn SVC, linear kernel, C=1, balanced classes',
            'lifecycle':'First unlabeled warning followed by separate label-assisted confirmation',
            'not_claimed':'Author-code reproduction or entirely unlabeled full confirmation'}
        previous=OUT/'md3_implementation_manifest.json'
        if previous.exists() and json.loads(previous.read_text())!=manifest:
            raise RuntimeError('MD3 implementation changed. Use a new output directory.')
        previous.write_text(json.dumps(manifest,indent=2))
        (OUT/'menelaus_md3_source_snapshot.py').write_bytes(source_bytes)
    except Exception as error:
        md3_dependency_error=str(error)
        (OUT/'md3_dependency_error.txt').write_text(traceback.format_exc())
    # Pandas 2 removed append; restore its documented concat-equivalent API
    # only if required by this third-party version. Record this compatibility shim.
    compatibility=False
    if md3_class is not None and '.append(' in inspect.getsource(md3_class) and not hasattr(pd.DataFrame,'append'):
        def legacy_append(self,other,ignore_index=False,verify_integrity=False,sort=False):
            if isinstance(other,pd.Series): other=other.to_frame().T
            if isinstance(other,dict): other=pd.DataFrame([other])
            pieces=[self]+(list(other) if isinstance(other,list) and all(isinstance(x,pd.DataFrame) for x in other) else [other])
            return pd.concat(pieces,ignore_index=ignore_index,verify_integrity=verify_integrity,sort=sort)
        pd.DataFrame.append=legacy_append
        compatibility=True
    (OUT/'compatibility.json').write_text(json.dumps({'pandas_legacy_append_shim':compatibility},indent=2))
    write_theory_note()
    statuses=[]
    for dataset in DATASETS:
        directory=OUT/dataset
        directory.mkdir(parents=True,exist_ok=True)
        try:
            bundle=joblib.load(BASE/dataset/f'{dataset}_bundle.joblib')
            reference=bundle['known_reference_df']
            normal=reference[reference.label==0]
            attack=reference[reference.label==1]
            count=min(len(normal),len(attack),REFERENCE_CAP_PER_CLASS)
            if count<CV_FOLDS:
                raise ValueError('Too few real reference rows for the fixed MD3 CV protocol.')
            balanced_reference=pd.concat([normal.sample(count,random_state=8101),
                                         attack.sample(count,random_state=8102)],ignore_index=True).sample(frac=1,random_state=8103).reset_index(drop=True)
            if set(balanced_reference._row_id)&set(bundle['source_test_df']._row_id):
                raise AssertionError('Reference/test record overlap.')
            prototype=None
            prototype_error=md3_dependency_error
            if md3_class is not None:
                try:
                    classifier=SVC(kernel='linear',C=1,class_weight='balanced',random_state=8104)
                    train_X=scale_frame(bundle,bundle['train_df'])
                    classifier.fit(train_X,bundle['train_df'].label)
                    prototype=md3_class(classifier,sensitivity=SENSITIVITY,k=CV_FOLDS,
                                        oracle_data_length_required=ORACLE_LABEL_BUDGET)
                    reference_X=scale_frame(bundle,balanced_reference)
                    reference_X['label']=balanced_reference.label.to_numpy(dtype=int)
                    prototype.set_reference(reference_X,target_name='label')
                    joblib.dump(prototype,directory/'md3_reference_detector.joblib',compress=3)
                    joblib.dump(classifier,directory/'md3_auxiliary_svm.joblib',compress=3)
                except Exception as error:
                    prototype_error=str(error)
                    prototype=None
                    (directory/'md3_initialization_error.txt').write_text(traceback.format_exc())
            bound_rows=[];md3_rows=[];md3_errors=[]
            for metadata,frame in cases(bundle,dataset):
                bound_rows.extend(accuracy_bounds(bundle,frame,metadata))
                if prototype is not None:
                    try:
                        md3_rows.append(evaluate_md3(md3_class,prototype,bundle,frame,metadata))
                    except Exception as error:
                        md3_errors.append({**metadata,'status':'FAILED','error':str(error)})
                save_csv(bound_rows,directory/'accuracy_identifiability_bounds.csv')
                if md3_rows: save_csv(md3_rows,directory/'md3_results.csv')
                if md3_errors: save_csv(md3_errors,directory/'md3_case_errors.csv')
                print(dataset,metadata['case'],'BOUNDS COMPUTED',
                      'MD3 COMPUTED' if prototype is not None and not (md3_errors and md3_errors[-1]['case']==metadata['case']) else 'MD3 NOT COMPLETE',flush=True)
            statuses.append({'dataset':dataset,'task':'analytical_bounds', 'status':'COMPUTED_ON_REAL_PREDICTIONS','detail':''})
            statuses.append({'dataset':dataset,'task':'Menelaus_MD3_baseline',
                             'status':'COMPUTED' if prototype is not None and not md3_errors else 'FAILED_OR_INCOMPLETE',
                             'detail':prototype_error or (f'{len(md3_errors)} case errors' if md3_errors else '')})
        except Exception as error:
            statuses.append({'dataset':dataset,'task':'dataset_batch','status':'FAILED','detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'task_status.csv')
    for filename in ['accuracy_identifiability_bounds.csv','md3_results.csv','md3_case_errors.csv']:
        tables=[pd.read_csv(OUT/dataset/filename) for dataset in DATASETS if (OUT/dataset/filename).exists()]
        if tables: save_csv(pd.concat(tables,ignore_index=True),OUT/f'all_datasets_{filename}')
    bounds_file=OUT/'all_datasets_accuracy_identifiability_bounds.csv'
    if bounds_file.exists():
        bounds=pd.read_csv(bounds_file)
        summary=bounds.groupby(['dataset','case_kind']).agg(
            recorded_windows=('window','size'),observed_accuracy=('observed_true_accuracy','mean'),
            mean_oracle_count_accuracy_interval_width=('count_constrained_ambiguity_width','mean'),
            mean_oracle_count_minimax_error_bound=('count_constrained_minimax_absolute_error_lower_bound','mean')).reset_index()
        save_csv(summary,OUT/'bounds_summary.csv')
        print('\nBOUNDS SUMMARY\n'+summary.round(4).to_string(index=False),flush=True)
    protocol={
      'tasks':['Menelaus MD3 implementation baseline','Sharp analytical accuracy bounds'],
      'data':'Existing real rows and real labels; no generated features or labels',
      'MD3_scope':'Separate linear-SVM margin classifier; full confirmation consumes labels',
      'MD3_stage_comparison':'Unlabeled first warnings and label-assisted confirmation kept separate',
      'theory_scope':'Label-unrestricted/count-constrained mathematical model, not a packet-realizability theorem',
      'remaining':['Provenance-approved primitive transformations','Packet/derived-statistic validity',
                   'GDE/ALine author-code conformance','Fresh independent confirmation/statistics',
                   'Untouched boundary data','External proof/originality review'],
      'no_claims':['all research complete','packet validity','confirmatory significance','universal defense',
                   'author-code MD3 reproduction','all-method label-free confirmation']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nTASK STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    COMPUTATION_STATUS=main()
