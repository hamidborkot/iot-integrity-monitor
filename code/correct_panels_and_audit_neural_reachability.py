"""Correct neural attack aggregation and audit sampled real-record reachability.
No model retraining, new threshold selection, synthetic examples, or inflated
replication counts. MILP results are numerical, conditional on the stated
feature box and frozen network, not packet-validity certificates.
"""
import hashlib
import json
import traceback
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from scipy.optimize import Bounds,LinearConstraint,milp

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
ATTACK_ROOT=BASE/'neural_target_and_coordinated_attacks_v1'
OUT=BASE/'corrected_neural_panels_and_reachability_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
TARGETS=[f'MLP32_16_seed_{seed}' for seed in [901,902,903]]
EPSILONS=[.25,.50]
WINDOW_SIZE=128
MAX_RECORDS_PER_TARGET=32
COHORT_SEED=9201
SOLVER_TIME_LIMIT_SECONDS=2.
MARGIN_SAFETY=1e-4
CHECK_TOLERANCE=1e-5
SETTINGS={'datasets':DATASETS,'targets':TARGETS,'epsilons':EPSILONS,
          'window_size':WINDOW_SIZE,'max_records_per_target':MAX_RECORDS_PER_TARGET,
          'cohort_seed':COHORT_SEED,'solver_time_limit_seconds':SOLVER_TIME_LIMIT_SECONDS,
          'margin_safety':MARGIN_SAFETY,'scope':'Numerical sampled continuous-box reachability audit',
          'not_claimed':'Full-corpus robustness, packet semantics, or confirmatory significance'}
SETTINGS_HASH=hashlib.sha256(json.dumps(SETTINGS,sort_keys=True).encode()).hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False)
    temporary.replace(path)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preprocessing(bundle,frame):
    imputed=bundle['primary_model'].named_steps['imputer'].transform(frame[bundle['primary_features']])
    scaled=bundle['primary_model'].named_steps['scaler'].transform(imputed)
    if not np.isfinite(scaled).all():
        raise ValueError('Nonfinite frozen preprocessing.')
    return imputed,scaled


def logit(model,x):
    a=np.asarray(x,dtype=float)
    for W,b in zip(model.coefs_[:-1],model.intercepts_[:-1]):
        a=np.maximum(a@W+b,0)
    return float(np.asarray(a@model.coefs_[-1]+model.intercepts_[-1]).reshape(-1)[0])


def pick_model_directory(dataset,fingerprint):
    valid=[]
    for root in BASE.glob('aline_gde_published_equations_v1*'):
        folder=root/dataset
        if all((folder/f'{name}.joblib').exists() and
               file_hash(folder/f'{name}.joblib')==fingerprint['model_sha256'][name]
               for name in TARGETS):
            valid.append(folder)
    if not valid:
        raise FileNotFoundError('No saved target-model directory matches the attack fingerprints.')
    return min(valid,key=lambda p:(len(str(p)),str(p)))


def raw_box(bundle,row,epsilon):
    features=list(bundle['primary_features'])
    imputed,x=preprocessing(bundle,row)
    indices=[];raw_low=[];raw_high=[];integer=[];columns=[]
    for column in bundle['mutable_columns']:
        origin=float(row[column].iloc[0])
        if not np.isfinite(origin):
            continue
        k=features.index(column)
        values=bundle['train_df'][column].dropna().to_numpy(dtype=float)
        values=values[np.isfinite(values)]
        qlow,qhigh=np.quantile(values,[.001,.999])
        scale=bundle['primary_model'].named_steps['scaler'].scale_[k]
        raw_low.append(max(origin-epsilon*scale,min(origin,qlow)))
        raw_high.append(min(origin+epsilon*scale,max(origin,qhigh)))
        indices.append(k);columns.append(column)
        integer.append(bool(np.all(np.isclose(values,np.round(values),atol=1e-8))))
    indices=np.asarray(indices,dtype=int)
    scales=bundle['primary_model'].named_steps['scaler'].scale_[indices]
    original=np.asarray([float(row[c].iloc[0]) for c in columns])
    return {'x':x[0],'indices':indices,'columns':columns,'original':original,'scales':scales,
            'raw_low':np.asarray(raw_low),'raw_high':np.asarray(raw_high),'integer':integer,
            'delta_low':(np.asarray(raw_low)-original)/scales,
            'delta_high':(np.asarray(raw_high)-original)/scales}


def solve_relu_box(model,box,time_limit):
    if model.activation!='relu' or model.out_activation_!='logistic' or list(model.classes_)!=[0,1]:
        raise ValueError('Expected binary ReLU/logistic MLP.')
    if len(model.coefs_)<2:
        raise ValueError('Expected at least one hidden layer.')
    low=list(box['delta_low']);high=list(box['delta_high']);integrality=[0]*len(low)
    constraints=[];constraint_low=[];constraint_high=[]
    previous=list(range(len(low)))
    def add(coefs,lb,ub):
        constraints.append(coefs);constraint_low.append(lb);constraint_high.append(ub)
    def allocate(lb,ub,integer=False):
        index=len(low);low.append(float(lb));high.append(float(ub));integrality.append(int(integer))
        return index
    for layer,(W,b) in enumerate(zip(model.coefs_[:-1],model.intercepts_[:-1])):
        if layer==0:
            coefficients=W[box['indices'],:]
            constants=box['x']@W+b
        else:
            coefficients=W
            constants=b
        previous_low=np.asarray([low[i] for i in previous])
        previous_high=np.asarray([high[i] for i in previous])
        positive=np.maximum(coefficients,0)
        negative=np.minimum(coefficients,0)
        L=constants+previous_low@positive+previous_high@negative
        U=constants+previous_high@positive+previous_low@negative
        padding=1e-8*(1+np.maximum(np.abs(L),np.abs(U)))
        L=L-padding;U=U+padding
        current=[allocate(max(0,L[j]),max(0,U[j])) for j in range(W.shape[1])]
        for j,activation in enumerate(current):
            affine={activation:1.}
            for k,var in enumerate(previous):
                coefficient=float(coefficients[k,j])
                if coefficient!=0:
                    affine[var]=affine.get(var,0)-coefficient
            constant=float(constants[j])
            if U[j]<=0:
                continue
            if L[j]>=0:
                add(affine,constant,constant)
            else:
                binary=allocate(0,1,True)
                add(affine,constant,np.inf)
                upper=dict(affine);upper[binary]=-float(L[j])
                add(upper,-np.inf,constant-float(L[j]))
                add({activation:1.,binary:-float(U[j])},-np.inf,0.)
        previous=current
    objective=np.zeros(len(low))
    objective[previous]=model.coefs_[-1][:,0]
    bias=float(model.intercepts_[-1][0])
    A=np.zeros((len(constraints),len(low)))
    for i,row in enumerate(constraints):
        for j,value in row.items(): A[i,j]=value
    result=milp(objective,integrality=np.asarray(integrality),
                bounds=Bounds(np.asarray(low),np.asarray(high)),
                constraints=LinearConstraint(A,np.asarray(constraint_low),np.asarray(constraint_high)),
                options={'time_limit':time_limit,'mip_rel_gap':0.,'presolve':True})
    value=getattr(result,'mip_dual_bound',None)
    lower_bound=float(value)+bias if value is not None and np.isfinite(value) else np.nan
    if result.status==0 and result.fun is not None and np.isfinite(result.fun):
        lower_bound=float(result.fun)+bias
    candidate=None
    primal_margin=np.nan
    if result.x is not None and np.isfinite(result.x).all():
        candidate=np.asarray(result.x[:len(box['indices'])],dtype=float)
        x=box['x'].copy();x[box['indices']]+=candidate
        primal_margin=logit(model,x)
        expected=float(result.fun)+bias
        if not np.isclose(primal_margin,expected,atol=CHECK_TOLERANCE,rtol=1e-7):
            raise AssertionError('Solver primal margin disagrees with native network evaluation.')
    return {'status':int(result.status),'message':str(result.message),
            'lower_bound':lower_bound,'candidate':candidate,'primal_margin':primal_margin,
            'integer_relu_variables':int(np.sum(integrality)),
            'mip_gap':float(getattr(result,'mip_gap',np.nan))}


def candidate_row(row,box,delta):
    proposed=box['original']+delta*box['scales']
    values=np.clip(proposed,box['raw_low'],box['raw_high'])
    for j,integer in enumerate(box['integer']):
        if integer:
            rounded=np.round(values[j])
            values[j]=(rounded if box['raw_low'][j]<=rounded<=box['raw_high'][j]
                       else box['original'][j])
    result=row.copy()
    for column,value in zip(box['columns'],values): result[column]=value
    immutable=[c for c in row if c not in box['columns']]
    if not result[immutable].equals(row[immutable]):
        raise AssertionError('Solver witness changed immutable fields.')
    if np.any(values<box['raw_low']-1e-7) or np.any(values>box['raw_high']+1e-7):
        raise AssertionError('Solver witness violates the raw box.')
    return result


def corrected_panels(dataset,directory):
    source_file=ATTACK_ROOT/dataset/'neural_accuracy_estimator_results.csv'
    frame=pd.read_csv(source_file)
    required=['case','attack_family','scope','target_model','estimator','actual_accuracy','estimated_accuracy',
              'true_damage','estimated_damage','differential_absolute_error','epsilon','attack_target']
    missing=set(required)-set(frame.columns)
    if missing: raise ValueError(f'Raw result columns missing: {missing}')
    frame['case_kind_corrected']=np.where(frame['case'].eq('clean_source'),'clean_source',
         np.where(frame['attack_family'].eq('none'),'natural_shift','feature_space_attack'))
    frame['domain_corrected']=np.where(frame['attack_family'].eq('none'),frame['case'],'source_test')
    frame['preselected_neural_primary']=frame['target_model'].isin(TARGETS)
    direct=frame['target_model'].eq(frame['attack_target'])
    keep=frame['preselected_neural_primary']&(~frame['attack_family'].eq('single_target_pgd')|direct)
    panel=frame[keep].copy()
    actual=(panel['true_damage']-panel['estimated_damage']).abs()
    if not np.allclose(actual,panel['differential_absolute_error'],atol=1e-7,rtol=1e-7,equal_nan=True):
        raise AssertionError('Reported differential error does not match the paired damage error.')
    save_csv(panel,directory/'corrected_primary_panel_rows.csv')
    keys=['dataset','case_kind_corrected','domain_corrected','attack_family','epsilon','scope','estimator']
    summary=panel.groupby(keys,dropna=False).agg(
        reported_rows=('target_model','size'),distinct_trained_targets=('target_model','nunique'),
        actual_accuracy=('actual_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean'),
        absolute_accuracy_error=('absolute_accuracy_error','mean'),true_damage=('true_damage','mean'),
        estimated_damage=('estimated_damage','mean'),differential_absolute_error=('differential_absolute_error','mean')).reset_index()
    save_csv(summary,directory/'corrected_primary_panel_summary.csv')
    target_summary=panel.groupby(keys+['target_model'],dropna=False).agg(
        actual_accuracy=('actual_accuracy','mean'),estimated_accuracy=('estimated_accuracy','mean'),
        true_damage=('true_damage','mean'),estimated_damage=('estimated_damage','mean'),
        differential_absolute_error=('differential_absolute_error','mean')).reset_index()
    save_csv(target_summary,directory/'individual_target_summary.csv')
    return summary


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    settings=OUT/'settings.json'
    frozen={'settings_sha256':SETTINGS_HASH,'settings':SETTINGS}
    if settings.exists() and json.loads(settings.read_text())!=frozen:
        raise RuntimeError('Settings changed. Use a new OUT directory.')
    settings.write_text(json.dumps(frozen,indent=2))
    statuses=[];all_audit=[];all_summary=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        try:
            all_summary.append(corrected_panels(dataset,directory))
            print(dataset,'TARGET / DOMAIN / EPSILON AGGREGATION CORRECTED',flush=True)
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            fingerprint=json.loads((ATTACK_ROOT/dataset/'input_fingerprint.json').read_text())
            if file_hash(bundle_path)!=fingerprint['bundle_sha256']:
                raise AssertionError('The bundle changed after neural attack evaluation.')
            model_directory=pick_model_directory(dataset,fingerprint)
            original=bundle['source_test_df']
            order=np.random.default_rng(1002).permutation(len(original))
            count=len(original)//WINDOW_SIZE*WINDOW_SIZE
            source=original.iloc[order[:count]].reset_index(drop=True).copy()
            _,source_X=preprocessing(bundle,source)
            rows=[];cohort=[];zero_checks=[]
            for target_number,target in enumerate(TARGETS):
                model=joblib.load(model_directory/f'{target}.joblib')
                predicted=model.predict(source_X)
                eligible=np.flatnonzero((source.label.to_numpy()==1)&(predicted==1))
                if not len(eligible): raise ValueError(f'{target}: no correctly classified malicious source records.')
                rng=np.random.default_rng(COHORT_SEED+target_number)
                selected=np.sort(rng.choice(eligible,min(MAX_RECORDS_PER_TARGET,len(eligible)),replace=False))
                for source_position in selected:
                    cohort.append({'dataset':dataset,'target':target,'source_position':int(source_position),
                                   'row_id':str(source.iloc[source_position]['_row_id'])})
                # Real-record identity check, not a synthetic-network test.
                first=source.iloc[[selected[0]]].copy()
                zero_box=raw_box(bundle,first,0.)
                zero_result=solve_relu_box(model,zero_box,SOLVER_TIME_LIMIT_SECONDS)
                original_margin=logit(model,zero_box['x'])
                if zero_result['status']!=0 or not np.isclose(
                    zero_result['primal_margin'],original_margin,atol=CHECK_TOLERANCE,rtol=1e-7):
                    raise AssertionError('Zero-budget real-record MILP identity failed.')
                zero_checks.append({'dataset':dataset,'target':target,'row_id':str(first['_row_id'].iloc[0]),
                                    'native_margin':original_margin,'solver_margin':zero_result['primal_margin'],
                                    'status':'REAL_RECORD_IDENTITY_PASSED'})
                for epsilon in EPSILONS:
                    # Audit the actual previous PGD candidates on the SAME sampled records.
                    previous=[]
                    for attack_seed in [1101,1102,1103]:
                        artifact=ATTACK_ROOT/dataset/f'single_target_pgd_{target}_eps_{epsilon:.2f}_seed_{attack_seed}.npz'
                        with np.load(artifact,allow_pickle=False) as saved:
                            if not np.array_equal(saved['source_row_ids'].astype(str),source['_row_id'].to_numpy(dtype=str)):
                                raise AssertionError('Previous PGD source order changed.')
                            columns=saved['mutable_columns'].astype(str).tolist()
                            delta=saved['per_record_delta_standardized'].copy()
                        if columns!=list(bundle['mutable_columns']): raise ValueError('Previous PGD mutable schema changed.')
                        previous.append(delta)
                    for source_position in selected:
                        row=source.iloc[[source_position]].copy()
                        common={'dataset':dataset,'target':target,'epsilon':epsilon,
                                'source_position':int(source_position),'row_id':str(row['_row_id'].iloc[0])}
                        try:
                            box=raw_box(bundle,row,epsilon)
                            native_original=logit(model,box['x'])
                            previous_margins=[]
                            for delta in previous:
                                # Decode exactly the previous stored standardized per-record offsets.
                                imputed,_=preprocessing(bundle,row)
                                features=list(bundle['primary_features'])
                                candidate=row.copy()
                                for j,column in enumerate(bundle['mutable_columns']):
                                    origin=float(row[column].iloc[0])
                                    if np.isfinite(origin):
                                        k=features.index(column)
                                        scale=bundle['primary_model'].named_steps['scaler'].scale_[k]
                                        candidate[column]=float(imputed[0,k]+delta[source_position,j]*scale)
                                _,x=preprocessing(bundle,candidate)
                                previous_margins.append(logit(model,x[0]))
                            best_pgd_margin=min(previous_margins)
                            result=solve_relu_box(model,box,SOLVER_TIME_LIMIT_SECONDS)
                            solver_witness_found=False
                            solver_projected_margin=np.nan
                            witness_values=None
                            if result['candidate'] is not None:
                                witness=candidate_row(row,box,result['candidate'])
                                _,witness_X=preprocessing(bundle,witness)
                                solver_projected_margin=logit(model,witness_X[0])
                                solver_witness_found=bool(model.predict(witness_X)[0]==0)
                                if solver_witness_found:
                                    witness_values=witness[bundle['primary_features']].iloc[0].to_dict()
                            lower=result['lower_bound']
                            if np.isfinite(lower) and lower>min(native_original,best_pgd_margin,solver_projected_margin
                                    if np.isfinite(solver_projected_margin) else np.inf)+MARGIN_SAFETY:
                                raise AssertionError('Solver lower bound contradicts a native feasible margin.')
                            if solver_witness_found:
                                audit_status='VERIFIED_SOLVER_EVASION_WITNESS'
                            elif best_pgd_margin<=0:
                                audit_status='VERIFIED_EXISTING_PGD_WITNESS'
                            elif np.isfinite(lower) and lower>MARGIN_SAFETY:
                                audit_status='POSITIVE_SOLVER_BOUND_IN_CONTINUOUS_BOX'
                            else:
                                audit_status='UNRESOLVED_TYPE_CONSTRAINED_REACHABILITY'
                            record={**common,'audit_status':audit_status,'native_original_margin':native_original,
                                    'best_previous_PGD_margin':best_pgd_margin,'previous_PGD_evasion_found':int(best_pgd_margin<=0),
                                    'solver_projected_witness_found':int(solver_witness_found),
                                    'new_solver_witness_not_found_by_PGD':int(solver_witness_found and best_pgd_margin>0),
                                    'solver_margin_lower_bound':lower,'solver_projected_margin':solver_projected_margin,
                                    'solver_status':result['status'],'solver_message':result['message'],
                                    'relu_binary_variables':result['integer_relu_variables'],
                                    'numerical_conditional_no_evasion_bound':int(audit_status=='POSITIVE_SOLVER_BOUND_IN_CONTINUOUS_BOX')}
                            if witness_values is not None:
                                name=f'{target}_eps_{epsilon:.2f}_source_{source_position}_witness.json'
                                (directory/name).write_text(json.dumps({**common,'predictors':witness_values,
                                    'label_unchanged':int(row.label.iloc[0]),'scope':'Verified range/type feature-space witness only'},indent=2))
                        except Exception as error:
                            record={**common,'audit_status':'FORMULATION_OR_NUMERICAL_ERROR','error':str(error)}
                        rows.append(record)
                        save_csv(rows,directory/'reachability_records.csv')
                    print(dataset,target,f'epsilon={epsilon}','SAMPLED REACHABILITY COMPUTED',flush=True)
            save_csv(cohort,directory/'real_record_cohort.csv')
            save_csv(zero_checks,directory/'zero_budget_real_record_checks.csv')
            all_audit.extend(rows)
            statuses.append({'dataset':dataset,'status':'PANELS_CORRECTED_AND_SAMPLED_REACHABILITY_COMPUTED',
                             'detail':f"{sum(r['audit_status']=='FORMULATION_OR_NUMERICAL_ERROR' for r in rows)} record-level errors retained"})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    if all_summary:
        summary=pd.concat(all_summary,ignore_index=True)
        save_csv(summary,OUT/'all_datasets_corrected_primary_summary.csv')
        print('\nCORRECTED DIRECT-TARGET RESULTS\n'+summary.round(4).to_string(index=False),flush=True)
    if all_audit:
        audit=pd.DataFrame(all_audit)
        save_csv(audit,OUT/'all_datasets_reachability_records.csv')
        summary=audit.groupby(['dataset','target','epsilon','audit_status']).size().rename('sampled_records').reset_index()
        save_csv(summary,OUT/'sampled_reachability_summary.csv')
        print('\nSAMPLED REAL-RECORD REACHABILITY\n'+summary.to_string(index=False),flush=True)
    protocol={
        'tasks':['Correct direct-target/domain/epsilon aggregation','Sampled real-record MILP reachability audit'],
        'solver':'SciPy milp / HiGHS with exact ReLU mixed-integer encoding and floating-point tolerances',
        'optimization_domain':'Continuous mutable-feature box; a superset of the existing integer-projection policy',
        'positive_bound_scope':'Numerical conditional bound for a particular saved network and sampled record only',
        'witness_validation':'Round/project and re-evaluate with the original sklearn model',
        'sample':'Up to 32 initially correct malicious source records per target, same cohort across epsilons',
        'selection':'Fixed RNG; not chosen for attack success',
        'limitations':['No packet semantics or derived-statistic consistency guarantee',
                       'No full-corpus robustness claim','A negative continuous bound does not prove an integer-valid attack',
                       'Timeouts/unresolved cases are not classified as robust',
                       'Repeated targets/windows/attack seeds are not independent dataset replications',
                       'No confirmatory p-values or confidence-coverage claim',
                       'No changes to saved models, thresholds, datasets, or previous results']}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    REACHABILITY_STATUS=main()
