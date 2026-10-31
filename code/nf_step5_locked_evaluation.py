"""NF Step 5: locked same-parent target evaluation.
Natural shift + exact linear white-box timing-report box attack + fixed sensitivity budgets.
No training, calibration changes, target tuning, independent-corpus inference or packet claims.
"""
import hashlib,json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix,roc_auc_score

MODEL=Path('/kaggle/working/nf_step3_calibration_v1/NF_calibrated_source_bundle.joblib')
STEP4=Path('/kaggle/working/nf_step4_target_contract_v2')
TARGET=STEP4/'NF_target_panels.joblib'
OUT=Path('/kaggle/working/nf_step5_locked_evaluation_v1');OUT.mkdir(parents=True,exist_ok=True)
MODEL_SHA='888e9783643a06792283f128403eda2e88309c6f162f0037e61dc6c907a39268'
TARGET_SHA='c9ad50e812246b29251587b0f85ba1aaa9b09749685f774e67580994ee609b5c'
CONTRACT_SHA='fd9b9dd591fcc0ee701b006bab32211978c2e6f711575966ccdf200cd172a54c'
ATOL=1e-7
ESTIMATORS=['AC','DoC','ATC','primary_view_agreement_proxy','MAJ_primary_agreement',
 'WACC_primary_agreement','DRIFTONLY_primary_agreement','ANCH_primary_agreement']

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def object_hash(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def write_json(path,value):
 tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2),encoding='utf-8');tmp.replace(path)
def predict(bundle,frame):
 models=[bundle['primary_model']]+list(bundle['view_models'].values())
 if any(list(model.classes_)!=[0,1] for model in models):raise ValueError('Unexpected classifier class order.')
 primary=bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:,1]
 views=np.vstack([bundle['view_models'][view].predict_proba(frame[columns])[:,1]
  for view,columns in bundle['semantic_views'].items()])
 if not np.isfinite(primary).all() or not np.isfinite(views).all():raise ValueError('Nonfinite probabilities.')
 return primary,views

def outcomes(bundle,p,v,y,window_size):
 if len(p)%window_size:raise ValueError('Incomplete evaluation windows.')
 n=len(p)//window_size;ps=p.reshape(n,window_size);vs=v.reshape(len(v),n,window_size)
 pdn=ps>bundle['primary_threshold'];vd=vs>np.asarray(bundle['view_thresholds'])[:,None,None]
 ref=bundle['reference_statistics'];confidence=np.maximum(ps,1-ps)
 estimates={name:np.empty(n) for name in ESTIMATORS}
 estimates['AC']=confidence.mean(axis=1)
 estimates['DoC']=np.clip(ref['reference_accuracy']+confidence.mean(axis=1)-ref['reference_confidence'],0,1)
 estimates['ATC']=(confidence>=ref['atc_threshold']).mean(axis=1)
 estimates['primary_view_agreement_proxy']=(vd==pdn[None,:,:]).mean(axis=(0,2))
 competence=np.clip(ref['view_accuracy'],.51,.99)
 cw=np.maximum(np.log(competence/(1-competence)),.05)
 columns=[pdn.mean(axis=1),confidence.mean(axis=1)]
 for i in range(len(v)):
  columns.extend([vd[i].mean(axis=1),np.maximum(vs[i],1-vs[i]).mean(axis=1),(vd[i]==pdn).mean(axis=1)])
 for i in range(len(v)):
  for j in range(i+1,len(v)):columns.append((vd[i]==vd[j]).mean(axis=1))
 matrix=np.column_stack(columns)
 scores=np.min(np.vstack([np.abs((matrix-center)/scale).mean(axis=1)/cutoff
  for center,scale,cutoff in bundle['profiles'].values()]),axis=0)
 if not np.isfinite(scores).all():raise ValueError('Nonfinite support scores.')
 for wid in range(n):
  drift=ref['view_positive_rate']-vd[:,wid].mean(axis=1)
  lower=drift[drift<=np.median(drift)]
  tau=max(.02,2*1.4826*np.median(np.abs(lower-np.median(lower))))
  excess=np.maximum(drift-np.quantile(drift,.2),0)
  dw=np.exp(-np.minimum((excess/tau)**2,50))
  for name,weights in [('MAJ_primary_agreement',np.ones(len(v))),('WACC_primary_agreement',cw),
   ('DRIFTONLY_primary_agreement',dw),('ANCH_primary_agreement',cw*dw)]:
   vote=np.average(vd[:,wid].astype(float),axis=0,weights=weights)>.5
   estimates[name][wid]=(vote==pdn[wid]).mean()
 actual=(pdn==y.reshape(n,window_size)).mean(axis=1)
 return actual,scores,estimates

def choose_endpoints(origin,low,high,gamma,integer,active):
 changed=origin.copy()
 for j,g in enumerate(gamma):
  if g==0:continue
  candidate=low[:,j].copy() if g>0 else high[:,j].copy()
  if integer[j]:
   candidate=np.ceil(candidate) if g>0 else np.floor(candidate)
  feasible=np.isfinite(candidate)&(candidate>=low[:,j]-ATOL)&(candidate<=high[:,j]+ATOL)
  eligible=active&np.isfinite(origin[:,j])&feasible
  changed[:,j]=np.where(eligible,candidate,origin[:,j])
 return changed

def attack(bundle,clean,fields,epsilon):
 features=list(bundle['primary_features']);primary=bundle['primary_model']
 if list(primary.named_steps)!=['imputer','scaler','classifier']:raise ValueError('Unexpected primary pipeline.')
 classifier=primary.named_steps['classifier'];scaler=primary.named_steps['scaler']
 if classifier.coef_.shape!=(1,len(features)):raise ValueError('Primary is not the declared binary linear model.')
 positions=[features.index(field) for field in fields]
 scales=scaler.scale_[positions];gamma=classifier.coef_[0,positions]/scales
 if not np.isfinite(gamma).all() or not np.isfinite(scales).all() or (scales<=0).any():raise ValueError('Invalid linear coefficient/scaling metadata.')
 origin=clean[fields].to_numpy(float);budget=epsilon*scales
 low=np.empty_like(origin);high=np.empty_like(origin);integer=[]
 for j,field in enumerate(fields):
  values=bundle['train_df'][field].dropna().to_numpy(float);values=values[np.isfinite(values)]
  if not len(values):raise ValueError('No finite training values: '+field)
  qlow,qhigh=np.quantile(values,[.001,.999])
  low[:,j]=np.maximum(origin[:,j]-budget[j],np.minimum(origin[:,j],qlow))
  high[:,j]=np.minimum(origin[:,j]+budget[j],np.maximum(origin[:,j],qhigh))
  integer.append(bool(np.all(np.isclose(values,np.round(values),atol=1e-8))))
 active=clean.label.to_numpy()==1
 changed=choose_endpoints(origin,low,high,gamma,integer,active)
 attacked=clean.copy();attacked[fields]=changed
 if not attacked[[c for c in clean if c not in fields]].equals(clean[[c for c in clean if c not in fields]]):raise AssertionError('Immutable fields changed.')
 if not attacked.loc[~active].equals(clean.loc[~active]):raise AssertionError('Benign records changed.')
 finite=np.isfinite(origin);delta=np.where(finite,np.abs(changed-origin),0)
 valid=np.all(~finite|((changed>=low-ATOL)&(changed<=high+ATOL)&(delta<=budget[None,:]+ATOL)),axis=1)
 for j,is_integer in enumerate(integer):
  modified=finite[:,j]&(delta[:,j]>ATOL)
  if is_integer:valid&=~modified|np.isclose(changed[:,j],np.round(changed[:,j]),atol=1e-8)
 if not valid.all():raise AssertionError('Declared range/type/budget checks failed.')
 return attacked,valid,np.any(delta>ATOL,axis=1)

if sha(MODEL)!=MODEL_SHA or sha(TARGET)!=TARGET_SHA:raise RuntimeError('Locked model/target checksum mismatch.')
record=json.loads((STEP4/'boundary_contract.json').read_text());contract=record['contract']
if record['contract_sha256']!=CONTRACT_SHA or object_hash(contract)!=CONTRACT_SHA:raise RuntimeError('Target contract changed.')
if contract['derived_cross_field_relationships_preserved'] is not False or contract['packet_validity_claim_allowed'] is not False:
 raise RuntimeError('This runner implements only the declared report-corruption scope.')
WINDOW_SIZE=int(contract['window_size']);primary_epsilon=float(contract['primary_attack']['epsilon'])
EPSILONS=sorted(set([primary_epsilon]+contract['primary_attack']['sensitivity_epsilons']))
FIELDS=list(contract['primary_attack']['controlled_fields'])
FAMILIES=list(contract['heldout_attack_families'])
settings={'runner_version':'NF-locked-target-evaluation-v1','contract_sha256':CONTRACT_SHA,
 'model_sha256':MODEL_SHA,'target_sha256':TARGET_SHA,'epsilons':EPSILONS,
 'primary_epsilon':primary_epsilon,'fields':FIELDS,'estimators':ESTIMATORS,
 'optimizer':'exact coordinate endpoints for linear detector in declared independent-coordinate box',
 'covariate_shift_metrics':'equal family weighting','independent_confirmation':False}
settings_hash=object_hash(settings);settings_path=OUT/'evaluation_settings.json'
if settings_path.exists():
 if json.loads(settings_path.read_text())['settings_sha256']!=settings_hash:raise RuntimeError('Evaluation settings changed; original outputs preserved.')
else:write_json(settings_path,{'settings':settings,'settings_sha256':settings_hash})
DONE=OUT/'evaluation_receipt.json'
if DONE.exists():
 completed=json.loads(DONE.read_text())
 if completed['settings_sha256']!=settings_hash:raise RuntimeError('Completion receipt settings mismatch.')
 for filename,digest in completed['output_sha256'].items():
  if sha(OUT/filename)!=digest:raise RuntimeError('Completed output changed: '+filename)
 print(json.dumps(completed,indent=2));print('VERIFIED COMPLETED TARGET EVALUATION REUSED; NO RETUNING.')
else:
 bundle=joblib.load(MODEL);stored=joblib.load(TARGET)
 if stored['contract_sha256']!=CONTRACT_SHA:raise RuntimeError('Panel container contract mismatch.')
 panels=stored['panels']
 if set(panels)!=set(FAMILIES):raise RuntimeError('Family panels differ from the frozen contract.')
 metrics=[];view_rows=[];window_rows=[];estimator_rows=[];validation=[]
 for family in FAMILIES:
  clean=panels[family]
  if clean['_row_id'].duplicated().any() or not set(clean.label.unique())=={0,1}:raise ValueError('Invalid target IDs or labels.')
  y=clean.label.to_numpy(int)
  p,v=predict(bundle,clean);clean_actual,clean_score,clean_est=outcomes(bundle,p,v,y,WINDOW_SIZE)
  decision=p>bundle['primary_threshold'];tn,fp,fn,tp=confusion_matrix(y,decision.astype(int),labels=[0,1]).ravel()
  metrics.append({'family':family,'condition':'clean','rows':len(clean),'accuracy':float(np.mean(decision==y)),
   'AUROC':float(roc_auc_score(y,p)),'normal_FPR':float(fp/(tn+fp)),
   'attack_recall':float(tp/(tp+fn)),'accepted_coverage':float((clean_score<=1).mean()),
   'accepted_detector_error':float(1-clean_actual[clean_score<=1].mean()) if np.any(clean_score<=1) else np.nan})
  for i,view in enumerate(bundle['semantic_views']):
   d=v[i]>bundle['view_thresholds'][i]
   view_rows.append({'family':family,'view':view,'rows':len(clean),'clean_accuracy':float(np.mean(d==y)),
    'clean_AUROC':float(roc_auc_score(y,v[i]))})
  conditions=[('clean',0.,clean,p,v,clean_actual,clean_score,clean_est)]
  for epsilon in EPSILONS:
   attacked,valid,modified=attack(bundle,clean,FIELDS,float(epsilon))
   ap,av=predict(bundle,attacked)
   if np.any((y==1)&(ap>p+1e-10)):raise AssertionError('Linear minimizer increased malicious-row probability.')
   aa,score,est=outcomes(bundle,ap,av,y,WINDOW_SIZE)
   if np.any(clean_actual-aa<-1e-12):raise AssertionError('Declared evasion attack improved malicious classification unexpectedly.')
   validation.append({'family':family,'epsilon':epsilon,'rows':len(clean),
    'range_type_budget_satisfaction_rate':float(valid.mean()),'modified_row_fraction':float(modified.mean()),
    'packet_validity_established':False,'NetFlow_cross_field_validity_established':False})
   ad=ap>bundle['primary_threshold'];tn,fp,fn,tp=confusion_matrix(y,ad.astype(int),labels=[0,1]).ravel()
   metrics.append({'family':family,'condition':f'report_corruption_eps_{epsilon:.2f}',
    'rows':len(clean),'accuracy':float(np.mean(ad==y)),'AUROC':float(roc_auc_score(y,ap)),
    'normal_FPR':float(fp/(tn+fp)),'attack_recall':float(tp/(tp+fn)),
    'accepted_coverage':float((score<=1).mean()),
    'accepted_detector_error':float(1-aa[score<=1].mean()) if np.any(score<=1) else np.nan})
   conditions.append((f'report_corruption_eps_{epsilon:.2f}',float(epsilon),attacked,ap,av,aa,score,est))
  for condition,epsilon,frame,cp,cv,actual,score,est in conditions:
   damage=clean_actual-actual
   for wid in range(len(actual)):
    accepted=bool(score[wid]<=1)
    window_rows.append({'family':family,'condition':condition,'epsilon':epsilon,'window':wid,
     'clean_accuracy':float(clean_actual[wid]),'accuracy':float(actual[wid]),
     'damage':float(damage[wid]),'support_score':float(score[wid]),'accepted':accepted,
     'accepted_collapse':accepted and damage[wid]>=.05})
    for estimator in ESTIMATORS:
     error=abs((est[estimator][wid]-actual[wid])-(clean_est[estimator][wid]-clean_actual[wid]))
     estimator_rows.append({'family':family,'condition':condition,'epsilon':epsilon,'window':wid,
      'estimator':estimator,'actual_accuracy':float(actual[wid]),'estimated_accuracy':float(est[estimator][wid]),
      'absolute_error':float(abs(est[estimator][wid]-actual[wid])),
      'differential_error':float(error),'damage':float(damage[wid]),'accepted':accepted})
  print(family,'LOCKED CLEAN AND REPORT-CORRUPTION EVALUATION COMPLETE',flush=True)

 metrics_df=pd.DataFrame(metrics);views_df=pd.DataFrame(view_rows)
 windows_df=pd.DataFrame(window_rows);estimates_df=pd.DataFrame(estimator_rows)
 summary=estimates_df.groupby(['family','condition','epsilon','estimator']).agg(
  windows=('window','size'),mean_damage=('damage','mean'),
  mean_estimated_accuracy=('estimated_accuracy','mean'),mean_actual_accuracy=('actual_accuracy','mean'),
  mean_absolute_error=('absolute_error','mean'),mean_differential_error=('differential_error','mean'),
  accepted_coverage=('accepted','mean')).reset_index()
 primary=summary[np.isclose(summary.epsilon,primary_epsilon)]
 paired=primary.pivot(index='family',columns='estimator',values='mean_differential_error')
 baseline=contract['primary_baseline'];monitor=contract['primary_monitor']
 if baseline not in paired or monitor not in paired or paired[[baseline,monitor]].isna().any().any():raise ValueError('Missing paired primary estimator results.')
 paired=paired[[baseline,monitor]].reset_index().rename(columns={baseline:'baseline_error',monitor:'monitor_error'})
 paired['gain']=paired.baseline_error-paired.monitor_error
 mean_view_accuracy=float(views_df.groupby('family').clean_accuracy.mean().mean())
 mean_gain=float(paired.gain.mean());threshold=float(contract['boundary_prediction_threshold'])
 boundary={'mean_semantic_view_accuracy_under_natural_shift':mean_view_accuracy,
  'precommitted_threshold':threshold,'high_competence_branch_applicable':mean_view_accuracy>=threshold,
  'primary_epsilon':primary_epsilon,'baseline':baseline,'monitor':monitor,
  'equal_family_mean_gain':mean_gain,'positive_descriptive_gain_observed':mean_gain>0,
  'positive_independent_clustered_CI_established':False,
  'hypothesis_interpretation':('High-competence branch applies; independent-CI prediction remains unestablished.'
    if mean_view_accuracy>=threshold else 'Low-competence branch observed; no independent gain claim made. This does not validate the high-competence implication.'),
  'family_panels_proven_independent':False,'same_parent_representation_scope':True,
  'packet_validity_established':False,'NetFlow_semantic_validity_established':False}
 outputs={'target_classifier_metrics.csv':metrics_df,'natural_shift_view_metrics.csv':views_df,
  'target_windows.csv':windows_df,'target_estimator_windows.csv':estimates_df,
  'estimator_summary.csv':summary,'primary_paired_family_errors.csv':paired,
  'report_constraint_checks.csv':pd.DataFrame(validation)}
 for filename,frame in outputs.items():frame.to_csv(OUT/filename,index=False)
 write_json(OUT/'boundary_result.json',boundary)
 if sha(MODEL)!=MODEL_SHA or sha(TARGET)!=TARGET_SHA:raise AssertionError('Input artifacts changed.')
 completed={'output_directory':str(OUT),'settings_sha256':settings_hash,'contract_sha256':CONTRACT_SHA,
  'family_panels_evaluated':len(FAMILIES),'window_result_rows':len(windows_df),
  'estimator_window_rows':len(estimates_df),'source_models_retrained':False,
  'classifier_thresholds_changed':False,'reference_profiles_changed':False,
  'target_predictions_computed':True,'target_outcomes_now_inspected':True,
  'scoped_same_parent_boundary_evaluation_completed':True,
  'independent_corpus_claim_allowed':False,'independent_confirmation_completed':False,
  'original_A_to_G_complete':False,'boundary_result':boundary,
  'output_sha256':{name:sha(OUT/name) for name in list(outputs)+['boundary_result.json']}}
 write_json(DONE,completed)
 print(json.dumps(completed,indent=2));print('\nTARGET CLASSIFIER METRICS');print(metrics_df.to_string(index=False))
 print('\nNATURAL-SHIFT VIEW METRICS');print(views_df.to_string(index=False))
 print('\nPRIMARY PAIRED FAMILY ERRORS');print(paired.to_string(index=False))
 print('\nREPORT CONSTRAINT CHECKS');print(pd.DataFrame(validation).to_string(index=False))
 print('\nNo target-based settings changes are permitted after this evaluation.')
