"""NF Step 3: calibrate fixed source-trained classifiers and aligned profiles.
No new raw NF scan, held-out family loading, model fitting, or attacks.
Source-test metrics are descriptive and do not select any setting.
"""
import hashlib,json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

SOURCE_DIR=Path('/kaggle/working/nf_step2_source_training_v1')
INPUT=SOURCE_DIR/'NF_source_bundle.joblib'
OUT=Path('/kaggle/working/nf_step3_calibration_v1')
OUT.mkdir(parents=True,exist_ok=True)
EXPECTED_INPUT_SHA='d7dd5a584fa41419d088ac7c80c08742330677159ca35d6fd3fb3884cc5fe307'
EXPECTED_SOURCE_SETTINGS='900cffad8b5be667add89409c63e3c977354bd754a9817c1cc6d1ae21f1f9789'
WINDOW_SIZE=128
FIT_RESAMPLES=512
CALIBRATION_RESAMPLES=512
QUANTILE=.95
FIT_SEED=7101
CALIBRATION_SEED=7102
NORMAL_FPR=.05


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def object_hash(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def write_json(path,value):
 temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2),encoding='utf-8');temp.replace(path)
def check_frame(frame):
 if not isinstance(frame,pd.DataFrame) or frame.empty:raise ValueError('Missing/empty source allocation.')
 if not {'label','_family','_row_id','_feature_group_hash'}.issubset(frame.columns):raise ValueError('Allocation metadata missing.')
 if frame.label.isna().any() or not set(frame.label.unique()).issubset({0,1}):raise ValueError('Invalid labels.')
 if frame['_row_id'].astype(str).duplicated().any():raise ValueError('Duplicate row IDs within allocation.')
def probability(model,frame,columns):
 if list(model.classes_)!=[0,1]:raise ValueError('Classifier class ordering is not [0,1].')
 if hasattr(model,'feature_names_in_') and list(model.feature_names_in_)!=list(columns):raise ValueError('Predictor-order mismatch.')
 p=np.asarray(model.predict_proba(frame[list(columns)]))
 if p.shape!=(len(frame),2) or not np.isfinite(p).all() or (p<0).any() or (p>1).any() or not np.allclose(p.sum(axis=1),1,atol=1e-6):
  raise ValueError('Invalid probability matrix.')
 return p[:,1]
def calibrate(p):
 ordered=np.sort(np.asarray(p,float))
 if not len(ordered) or not np.isfinite(ordered).all():raise ValueError('Invalid normal calibration probabilities.')
 budget=int(np.floor(NORMAL_FPR*len(ordered)))
 t=float(ordered[max(0,len(ordered)-budget-1)])
 if int((ordered>t).sum())>budget:raise AssertionError('Strict-comparison calibration exceeds empirical FP budget.')
 return t,budget

def signatures(pp,vp,pt,vt,indices):
 rows=[]
 for ix in indices:
  primary=pp[ix]>pt;views=vp[:,ix]>np.asarray(vt)[:,None]
  row=[primary.mean(),np.maximum(pp[ix],1-pp[ix]).mean()]
  for j in range(len(vp)):
   row.extend([views[j].mean(),np.maximum(vp[j,ix],1-vp[j,ix]).mean(),(views[j]==primary).mean()])
  for j in range(len(vp)):
   for k in range(j+1,len(vp)):row.append((views[j]==views[k]).mean())
  rows.append(row)
 return np.asarray(rows,float)
def probabilities(bundle,frame):
 pp=probability(bundle['primary_model'],frame,bundle['primary_features'])
 vp=np.vstack([probability(bundle['view_models'][view],frame,columns) for view,columns in bundle['semantic_views'].items()])
 return pp,vp

def mixture_weights(train,frame,normal_only):
 if normal_only:
  if not frame.label.eq(0).all():raise ValueError('Normal profile contains malicious labels.')
  return np.full(len(frame),1/len(frame))
 target=train['_family'].value_counts(normalize=True);available=frame['_family'].value_counts()
 if set(target.index)-set(available.index):raise ValueError('Reference misses training families.')
 w=np.asarray([target.get(f,0)/available[f] for f in frame['_family']],float)
 if not np.isfinite(w).all() or w.sum()<=0:raise ValueError('Invalid reference weights.')
 return w/w.sum()
def resamples(n,w,count,seed):
 rng=np.random.default_rng(seed)
 return [rng.choice(n,size=WINDOW_SIZE,replace=True,p=w) for _ in range(count)]
def parameter_hash(model):
 h=hashlib.sha256()
 for stage,attributes in [('imputer',['statistics_']),('scaler',['mean_','scale_']),('classifier',['coef_','intercept_','classes_'])]:
  for attribute in attributes:
   value=np.asarray(getattr(model.named_steps[stage],attribute))
   h.update((stage+attribute+str(value.dtype)+str(value.shape)).encode());h.update(value.tobytes())
 return h.hexdigest()

if not INPUT.is_file():raise FileNotFoundError(INPUT)
if sha(INPUT)!=EXPECTED_INPUT_SHA:raise RuntimeError('Step 2 source bundle differs from verified receipt.')
source_receipt=json.loads((SOURCE_DIR/'source_training_receipt.json').read_text())
if source_receipt['settings_sha256']!=EXPECTED_SOURCE_SETTINGS:raise RuntimeError('Step 2 settings changed.')
settings={'version':'NF-source-calibration-v1','input_bundle_sha256':EXPECTED_INPUT_SHA,
 'source_settings_sha256':EXPECTED_SOURCE_SETTINGS,'window_size':WINDOW_SIZE,
 'fit_resamples':FIT_RESAMPLES,'calibration_resamples':CALIBRATION_RESAMPLES,
 'fit_seed':FIT_SEED,'calibration_seed':CALIBRATION_SEED,
 'score_quantile':QUANTILE,'quantile_method':'higher','classifier_comparison':'>',
 'normal_calibration_FPR_target':NORMAL_FPR,'MAD_scale_multiplier':1.4826,
 'scale_floor':1/WINDOW_SIZE,'support_cutoff_floor':1e-12,
 'profile_mixture':'training-family proportions','source_test_order_seed':1002,
 'settings_selected_from_target_outcomes':False}
settings_hash=object_hash(settings)
settings_path=OUT/'calibration_settings.json'
if settings_path.exists():
 if json.loads(settings_path.read_text())['settings_sha256']!=settings_hash:raise RuntimeError('Existing calibration settings differ; no overwrite.')
else:write_json(settings_path,{'settings':settings,'settings_sha256':settings_hash})
output_bundle=OUT/'NF_calibrated_source_bundle.joblib';output_receipt=OUT/'calibration_receipt.json'
if output_bundle.exists() or output_receipt.exists():
 if not (output_bundle.exists() and output_receipt.exists()):raise RuntimeError('Incomplete earlier output; preserve it before retrying.')
 prior=json.loads(output_receipt.read_text())
 if prior['calibration_settings_sha256']!=settings_hash or sha(output_bundle)!=prior['calibrated_bundle_sha256']:
  raise RuntimeError('Existing completed calibration does not match receipt.')
 print(json.dumps(prior,indent=2));print('COMPLETED CALIBRATION REUSED; NOT RECOMPUTED.')
else:
 bundle=joblib.load(INPUT)
 keys=['train_df','primary_calibration_df','view_threshold_df','normal_profile_fit_df',
  'normal_profile_calibration_df','known_reference_df','known_profile_calibration_df','source_test_df']
 ids={};groups={}
 for key in keys:
  check_frame(bundle[key]);ids[key]=set(bundle[key]['_row_id'].astype(str));groups[key]=set(bundle[key]['_feature_group_hash'])
 for i,left in enumerate(keys):
  for right in keys[i+1:]:
   if ids[left]&ids[right] or groups[left]&groups[right]:raise AssertionError('Allocation overlap: '+left+'/'+right)
 models={'primary':bundle['primary_model'],**bundle['view_models']}
 before={name:parameter_hash(model) for name,model in models.items()}
 calibration_rows=[]
 frame=bundle['primary_calibration_df']
 if not frame.label.eq(0).all():raise ValueError('Primary calibration is not normal-only.')
 p=probability(bundle['primary_model'],frame,bundle['primary_features'])
 primary_t,budget=calibrate(p)
 bundle['primary_threshold']=primary_t
 calibration_rows.append({'model':'primary','normal_records':len(p),'threshold':primary_t,
  'threshold_ties':int((p==primary_t).sum()),'FP_strict':int((p>primary_t).sum()),
  'FPR_strict':float((p>primary_t).mean()),'FP_budget':budget})
 frame=bundle['view_threshold_df']
 if not frame.label.eq(0).all():raise ValueError('View calibration is not normal-only.')
 thresholds=[]
 for view,columns in bundle['semantic_views'].items():
  p=probability(bundle['view_models'][view],frame,columns);t,budget=calibrate(p);thresholds.append(t)
  calibration_rows.append({'model':view,'normal_records':len(p),'threshold':t,
   'threshold_ties':int((p==t).sum()),'FP_strict':int((p>t).sum()),
   'FPR_strict':float((p>t).mean()),'FP_budget':budget})
 bundle['view_thresholds']=thresholds
 profiles={};profile_rows=[]
 for profile,fit_key,cal_key,normal_only in [
  ('normal','normal_profile_fit_df','normal_profile_calibration_df',True),
  ('known','known_reference_df','known_profile_calibration_df',False)]:
  fit_frame=bundle[fit_key];cal_frame=bundle[cal_key]
  wf=mixture_weights(bundle['train_df'],fit_frame,normal_only)
  wc=mixture_weights(bundle['train_df'],cal_frame,normal_only)
  pp,vp=probabilities(bundle,fit_frame)
  fit=signatures(pp,vp,primary_t,thresholds,resamples(len(fit_frame),wf,FIT_RESAMPLES,FIT_SEED))
  median=np.median(fit,axis=0)
  scale=np.maximum(1.4826*np.median(np.abs(fit-median),axis=0),1/WINDOW_SIZE)
  pp,vp=probabilities(bundle,cal_frame)
  cal=signatures(pp,vp,primary_t,thresholds,resamples(len(cal_frame),wc,CALIBRATION_RESAMPLES,CALIBRATION_SEED))
  score=np.abs((cal-median)/scale).mean(axis=1)
  cutoff=max(float(np.quantile(score,QUANTILE,method='higher')),1e-12)
  if not np.isfinite(median).all() or not np.isfinite(scale).all() or not np.isfinite(cutoff):raise ValueError('Invalid reference profile.')
  profiles[profile]=(median,scale,cutoff)
  profile_rows.append({'profile':profile,'fit_records':len(fit_frame),'calibration_records':len(cal_frame),
   'signature_dimension':fit.shape[1],'cutoff':cutoff,
   'weighted_calibration_attack_fraction':float(np.dot(wc,cal_frame.label)),
   'reference_resamples_are_independent_units':False})
 bundle['profiles']=profiles

 # Source-only reference statistics for the existing conditional estimators.
 frame=bundle['known_reference_df'];w=mixture_weights(bundle['train_df'],frame,False)
 pp,vp=probabilities(bundle,frame);y=frame.label.to_numpy()
 pdn=pp>primary_t;vd=vp>np.asarray(thresholds)[:,None];confidence=np.maximum(pp,1-pp)
 ref_accuracy=float(np.dot(w,pdn==y));order=np.argsort(confidence,kind='stable')
 index=min(len(order)-1,np.searchsorted(np.cumsum(w[order]),1-ref_accuracy,side='left'))
 reference={'reference_accuracy':ref_accuracy,'reference_confidence':float(np.dot(w,confidence)),
  'atc_threshold':float(confidence[order[index]]),'view_accuracy':((vd==y)*w[None,:]).sum(axis=1),
  'view_positive_rate':(vd*w[None,:]).sum(axis=1),'weighted_attack_fraction':float(np.dot(w,y))}
 bundle['reference_statistics']=reference

 # Descriptive source-test evaluation; it does not choose or alter any settings.
 frame=bundle['source_test_df'];y=frame.label.to_numpy();pp,vp=probabilities(bundle,frame)
 rows=[]
 for name,p,t in [('primary',pp,primary_t)]+[(view,vp[i],thresholds[i]) for i,view in enumerate(bundle['semantic_views'])]:
  predicted=p>t;tn,fp,fn,tp=confusion_matrix(y,predicted.astype(int),labels=[0,1]).ravel()
  rows.append({'model':name,'rows':len(y),'accuracy':float(np.mean(predicted==y)),
   'normal_FPR':fp/(tn+fp) if tn+fp else np.nan,'attack_recall':tp/(tp+fn) if tp+fn else np.nan})
 order=np.random.default_rng(1002).permutation(len(frame))
 windows=[order[i:i+WINDOW_SIZE] for i in range(0,len(frame)-WINDOW_SIZE+1,WINDOW_SIZE)]
 matrix=signatures(pp,vp,primary_t,thresholds,windows)
 scores=np.min(np.vstack([np.abs((matrix-center)/scale).mean(axis=1)/cutoff
  for center,scale,cutoff in profiles.values()]),axis=0)
 accepted=scores<=1
 window_accuracy=np.asarray([np.mean((pp[ix]>primary_t)==y[ix]) for ix in windows])
 source_gate={'complete_source_windows':len(windows),'source_records_omitted_from_window_metrics':len(frame)%WINDOW_SIZE,
  'accepted_coverage':float(accepted.mean()),'abstain_rate':float(1-accepted.mean()),
  'accepted_detector_error':float(1-window_accuracy[accepted].mean()) if accepted.any() else None,
  'source_primary_accuracy_over_full_frame':float(np.mean((pp>primary_t)==y)),
  'source_evaluation_used_for_tuning':False}
 after={name:parameter_hash(model) for name,model in models.items()}
 if before!=after:raise AssertionError('Trained model parameters changed.')
 if sha(INPUT)!=EXPECTED_INPUT_SHA:raise AssertionError('Original source bundle changed.')
 bundle['calibration_settings_sha256']=settings_hash
 bundle['comparison_rule']='>'
 temporary=output_bundle.with_suffix('.tmp');joblib.dump(bundle,temporary,compress=3);temporary.replace(output_bundle)
 pd.DataFrame(calibration_rows).to_csv(OUT/'classifier_calibration.csv',index=False)
 pd.DataFrame(profile_rows).to_csv(OUT/'profile_calibration.csv',index=False)
 pd.DataFrame(rows).to_csv(OUT/'source_test_metrics.csv',index=False)
 write_json(OUT/'source_support_gate.json',source_gate)
 result={'output_directory':str(OUT),'calibrated_bundle_path':str(output_bundle),
  'calibrated_bundle_sha256':sha(output_bundle),'calibration_settings_sha256':settings_hash,
  'classifier_thresholds_calibrated':len(calibration_rows),'reference_profiles_calibrated':len(profiles),
  'trained_model_parameters_unchanged':True,'existing_source_bundle_unchanged':True,
  'new_raw_NF_scan_performed':False,'heldout_attack_family_records_loaded':False,
  'target_model_predictions_computed':False,'target_outcomes_inspected':False,
  'new_models_trained':False,'attacks_executed':False,'boundary_experiment_completed':False,
  'physical_source_group_independence_verified':False,'independent_corpus_claim_allowed':False,
  'attack_contract_status':bundle['attack_contract_status'],
  'source_support_gate':source_gate}
 write_json(output_receipt,result)
 print(json.dumps(result,indent=2))
 print('\nCLASSIFIER CALIBRATION');print(pd.DataFrame(calibration_rows).to_string(index=False))
 print('\nPROFILE CALIBRATION');print(pd.DataFrame(profile_rows).to_string(index=False))
 print('\nSOURCE-TEST METRICS');print(pd.DataFrame(rows).to_string(index=False))
 print('\nNEXT: fix target allocation and attack specification before boundary predictions.')
