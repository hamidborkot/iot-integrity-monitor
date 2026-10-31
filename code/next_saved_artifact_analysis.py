# Saved-artifact analysis: no training, installs, PCAP reads or replays.
from pathlib import Path
from datetime import datetime,timezone
from contextlib import contextmanager
import gc,gzip,hashlib,io,json,math,os,shutil,sys,time,traceback,warnings,zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
BACKUP=Path('/kaggle/input/datasets/mdhamidborkottulla/full-working-backup')
PARENT_ID='RAW_ONLY_REMEASUREMENT_20261017T130813279947Z'
DIAG_ID='DIRECT_MOUNT_DIAGNOSTIC_20261018T024353091267Z'
DIAGNOSTIC_DIRECTORY_OVERRIDE=None  # Set only if the completed outputs were remounted elsewhere.
PARENT=BACKUP/'kaggle_working'/PARENT_ID
OUT=W/('SAVED_MODEL_FAILURE_ANALYSIS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
NUM=F[:-1]
EXPECTED={'HGB':'adb02fbe0fb4582ce931c5c5bb5d71001647c801142b8a986018ea2983c063d1',
 'LR':'d80a15e78dd076f8b1f9905a627e8a6dab16c06596b6c792498553bda94e90a2'}
R={'status':'STARTED','model_fits':0,'PCAP_reads':0,'replays':0,'installs':0,
 'model_weights_changed':False,'novelty_established':False,'output_directory':str(OUT)}
USED=[]
class Stop(Exception):pass

def js(path,obj):
 path=Path(path);tmp=path.with_name(path.name+'.tmp');tmp.write_text(json.dumps(obj,indent=2,default=str),encoding='utf-8');tmp.replace(path)
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def variants(name):return [name,name[:-3]] if name.endswith('.gz') else ([name,name+'.gz'] if name.endswith('.csv') else [name])
def locate(root,names,required=True):
 if isinstance(names,str):names=[names]
 for directory in [Path(root),Path(root)/'PRIVATE_raw_only_checkpoint']:
  for name in names:
   for v in variants(name):
    p=directory/v
    if p.is_file():return p
 if required:raise Stop('Required saved input absent: '+str(root)+' / '+str(names)+'. No old experiment will be rerun automatically.')
 return None
@contextmanager
def opened(path):
 path=Path(path)
 with path.open('rb') as f:magic=f.read(2)
 if magic==b'\x1f\x8b':
  with gzip.open(path,'rb') as f:yield f
 else:
  with path.open('rb') as f:yield f

def small_csv(path):
 with opened(path) as f:data=f.read(64*1024**2+1)
 if len(data)>64*1024**2:raise Stop('Metadata CSV unexpectedly exceeds 64 MiB: '+str(path))
 USED.append({'path':str(path),'role':'small_table','sha256':sha(path)})
 return pd.read_csv(io.BytesIO(data),dtype={'ks':str})
def metadata(root,name):
 path=locate(root,name);USED.append({'path':str(path),'role':'metadata','sha256':sha(path)})
 return json.loads(path.read_text())
def norm(df):
 df=df.copy()
 if not set(F).issubset(df):raise Stop('Feature schema lacks '+str(set(F)-set(df)))
 for c in NUM:
  df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
  if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid numeric feature '+c)
 df['proto']=df.proto.astype(str).str.lower()
 if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Protocol outside preserved encoding')
 if 'ks' in df:df['ks']=df.ks.astype(str)
 return df

def encode(df):return np.column_stack([np.log1p(df[NUM].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def metrics(y,p,threshold=.5,strict=False):
 y=np.asarray(y,int);p=np.asarray(p,float)
 if len(y)==0 or y.shape!=p.shape or not set(y).issubset({0,1}) or not np.isfinite(p).all() or ((p<0)|(p>1)).any():raise Stop('Invalid binary metric inputs')
 pred=p>threshold if strict else p>=threshold
 pos=y==1;neg=y==0;correct=pred==y
 return {'rows':len(y),'benign_rows':int(neg.sum()),'malicious_rows':int(pos.sum()),'accuracy':float(correct.mean()),
  'balanced_accuracy':float(balanced_accuracy_score(y,pred)) if pos.any() and neg.any() else np.nan,
  'AUROC':float(roc_auc_score(y,p)) if pos.any() and neg.any() else np.nan,
  'malicious_recall':float(pred[pos].mean()) if pos.any() else np.nan,
  'benign_FPR':float(pred[neg].mean()) if neg.any() else np.nan,
  'false_positives':int((pred&neg).sum()),'false_negatives':int((~pred&pos).sum()),
  'mean_confidence_when_wrong':float(np.maximum(p,1-p)[~correct].mean()) if (~correct).any() else np.nan,
  'tiny_benign_denominator_warning':int(neg.sum())<100}

def find_diagnostic():
 candidates=([Path(DIAGNOSTIC_DIRECTORY_OVERRIDE)] if DIAGNOSTIC_DIRECTORY_OVERRIDE else [])+[W/DIAG_ID,BACKUP/'kaggle_working'/DIAG_ID,BACKUP/DIAG_ID]
 for d in candidates:
  if not d.is_dir():continue
  receipt=metadata(d,'receipt.json')
  if receipt.get('status')=='MECHANISM_DIAGNOSIS_COMPLETE' and receipt.get('parent_models_and_evaluated_keys_and_decisions_reproduced') is True:return d
 raise Stop('The completed diagnostic directory is not available in working or the mounted backup. Preserve/attach its 330-MB checkpoint or saved outputs. This analysis will not repeat any replay.')

def stream_records(path,wanted):
 parts=[];scanned=0
 with opened(path) as f:
  for chunk in pd.read_csv(f,chunksize=100000,dtype={'ks':str,'uid':str},low_memory=False):
   if not set(F+['ks','uid']).issubset(chunk):raise Stop('Extracted-record schema mismatch: '+str(path))
   scanned+=len(chunk);keep=chunk[chunk.ks.isin(wanted)]
   if len(keep):parts.append(keep.copy())
 frame=pd.concat(parts,ignore_index=True) if parts else pd.DataFrame(columns=F+['ks','uid'])
 duplicate_keys=set(frame.loc[frame.ks.duplicated(keep=False),'ks'])
 unique=norm(frame[~frame.ks.isin(duplicate_keys)].copy())
 report={'path':str(path),'rows_streamed':scanned,'wanted_keys':len(wanted),'uniquely_matched_keys':len(unique),
  'ambiguous_keys':len(duplicate_keys),'missing_or_ambiguous_keys':len(set(wanted)-set(unique.ks))}
 USED.append({**report,'role':'streamed_record_inputs'})
 return unique,report

def load_inputs():
 if not PARENT.is_dir():raise Stop('Audited parent run is not mounted at '+str(PARENT))
 diag=find_diagnostic();environment=metadata(PARENT,'environment.json');binding=metadata(PARENT,'model_binding.json')
 if binding['model_sha256']!=EXPECTED:raise Stop('Parent model identities differ from supplied audited hashes')
 if __import__('sklearn').__version__!=environment['sklearn']:raise Stop('Use saved sklearn '+environment['sklearn']+'; runtime is '+__import__('sklearn').__version__+'. No installation/retraining performed.')
 from sklearn.exceptions import InconsistentVersionWarning
 models={}
 with warnings.catch_warnings():
  warnings.simplefilter('error',InconsistentVersionWarning)
  for family in ['HGB','LR']:
   p=locate(PARENT,'fresh_'+family+'.joblib')
   if sha(p)!=EXPECTED[family]:raise Stop('Saved model hash mismatch: '+family)
   models[family]=joblib.load(p);USED.append({'path':str(p),'role':'frozen_model','sha256':sha(p)})
 source=norm(small_csv(locate(PARENT,'fresh_source_panel.csv.gz')))
 if not {'source_capture','group','role','y','ks'}.issubset(source):raise Stop('Saved source metadata incomplete')
 source['y']=pd.to_numeric(source.y,errors='raise').astype(int)
 if not source.y.isin([0,1]).all():raise Stop('Source labels are not binary')
 if set(source.source_capture.astype(int))!={1,3,8} or source.duplicated(['source_capture','ks']).any():raise Stop('Source role/identity mismatch')
 train=source[source.role.eq('train')].copy();hold=source[source.role.eq('source_holdout')].copy()
 if len(train)!=9660 or len(hold)!=2340 or set(train.group)&set(hold.group):raise Stop('Parent source split did not reproduce')
 old=small_csv(locate(PARENT,'source_holdout_metrics.csv'));reproduction=[]
 with threadpool_limits(limits=2):
  for family,model in models.items():
   p=model.predict_proba(encode(hold))[:,1];m=metrics(hold.y,p);prior=old[old.family.eq(family)]
   if len(prior)!=1:raise Stop('Saved source metric row not unique')
   ok=all(np.isclose(m[k],float(prior.iloc[0][k]),atol=1e-8,rtol=0) for k in ['accuracy','balanced_accuracy','AUROC','malicious_recall','benign_FPR'])
   reproduction.append({'family':family,'reproduced':bool(ok),**m})
   if not ok:raise Stop('Source metrics fail reproduction: plain/gzip alias was not accepted as equivalent data')
 pd.DataFrame(reproduction).to_csv(OUT/'source_metric_reproduction.csv',index=False)
 units=small_csv(locate(PARENT,'experiment1_unit_decisions.csv.gz'));targets={};coverage=[]
 for cap in [7,49]:
  subset=units[units.capture.eq(cap)&units.condition_seconds.eq(0)][['ks','label']].dropna()
  if subset.groupby('ks').label.nunique().gt(1).any():raise Stop('Target labels conflict')
  reference=subset.drop_duplicates('ks').copy();reference['label']=reference.label.astype(int)
  path=locate(diag/f'capture_{cap}',['extractor_inputs_delay0_timeout5.csv.gz','extractor_records_delay0_timeout5.csv.gz'])
  frame,report=stream_records(path,set(reference.ks));coverage.append({'capture':cap,'condition':0,**report})
  if set(frame.ks)!=set(reference.ks):raise Stop('Clean target original-start coverage incomplete; investigate '+str(cap)+' without filling labels')
  frame=frame.merge(reference,on='ks',how='left',validate='one_to_one');targets[cap]=frame
 pd.DataFrame(coverage).to_csv(OUT/'matched_input_coverage.csv',index=False)
 js(OUT/'input_manifest.json',USED)
 return diag,models,train,hold,targets,units

def pattern_key(row):
 vals=[float(x) for x in row[:-1]]
 vals=[0. if x==0 else x for x in vals]
 return hashlib.sha256(json.dumps([*[x.hex() for x in vals],str(row[-1])],separators=(',',':')).encode()).hexdigest()
def pattern_ids(df):return [pattern_key(r) for r in df[F].itertuples(index=False,name=None)]

def experiment1(models,train,hold,targets):
 support=[];probability_rows=[];pattern_frames=[]
 source= pd.concat([train,hold],ignore_index=True)
 sp=source[['ks','y','role']+F].copy();sp['domain']='source';sp['label']=sp.y;sp['pattern']=pattern_ids(sp);pattern_frames.append(sp)
 for cap,target in targets.items():
  for feature in NUM:
   ref=train[feature].to_numpy(float);values=target[feature].to_numpy(float)
   support.append({'capture':cap,'feature':feature,'source_train_min':float(ref.min()),'source_train_max':float(ref.max()),
    'source_train_median':float(np.median(ref)),'target_median':float(np.median(values)),
    'outside_source_train_range_fraction':float(((values<ref.min())|(values>ref.max())).mean()),
    'source_zero_fraction':float((ref==0).mean()),'target_zero_fraction':float((values==0).mean()),
    'interpretation':'descriptive support/representation check, not packet validity or causal attribution'})
  tp=target[['ks','label']+F].copy();tp['domain']='capture_'+str(cap);tp['role']='target';tp['pattern']=pattern_ids(tp);pattern_frames.append(tp)
  with threadpool_limits(limits=2):
   for family,model in models.items():
    p=model.predict_proba(encode(target))[:,1];pred=p>=.5
    probability_rows.extend({'capture':cap,'family':family,'ks':str(k),'label':int(y),'probability':float(v),
     'prediction':int(d),'confidence':float(max(v,1-v)),'correct':bool(d==y)} for k,y,v,d in zip(target.ks,target.label,p,pred))
 pd.DataFrame(support).to_csv(OUT/'EXPERIMENT1_feature_support.csv',index=False)
 probabilities=pd.DataFrame(probability_rows);probabilities.to_csv(OUT/'EXPERIMENT1_clean_target_probabilities.csv',index=False)
 whole=pd.concat(pattern_frames,ignore_index=True);source_patterns=set(sp.pattern)
 counts=whole.groupby(['pattern','domain','label'],dropna=False).size().unstack(['domain','label'],fill_value=0)
 counts.columns=[domain+'_label'+str(int(label)) for domain,label in counts.columns];counts=counts.reset_index()
 numeric=[c for c in counts if c!='pattern'];counts.to_csv(OUT/'EXPERIMENT1_predictor_pattern_counts.csv',index=False)
 conflicts=[]
 for cap,target in targets.items():
  name='capture_'+str(cap);t=whole[whole.domain.eq(name)]
  sy=sp.groupby('pattern').label.agg(lambda x:set(x));opposite=0;shared=0
  for _,r in t.iterrows():
   labels=sy.get(r['pattern'],set());shared+=int(bool(labels));opposite+=int(bool(labels) and any(y!=r['label'] for y in labels))
  patterns_with_source={p for p in t.pattern if p in source_patterns}
  ty=t.groupby('pattern').label.agg(lambda x:set(x))
  conflicting_patterns={p for p in patterns_with_source if any(a!=b for a in sy[p] for b in ty[p])}
  conflicts.append({'capture':cap,'target_rows':len(t),'exact_pattern_shared_with_source_rows':shared,
   'target_rows_with_an_opposite_label_in_source':opposite,'distinct_cross_domain_conflicting_patterns':len(conflicting_patterns),
   'scope':'same recorded predictors with different published labels: representation ambiguity or label/context difference, not proof of a universal impossibility'})
  if conflicting_patterns:
   whole[whole.pattern.isin(conflicting_patterns)].to_csv(OUT/f'EXPERIMENT1_conflict_examples_capture{cap}.csv',index=False)
 pd.DataFrame(conflicts).to_csv(OUT/'EXPERIMENT1_exact_pattern_conflicts.csv',index=False)
 metrics_table=[]
 for (cap,family),g in probabilities.groupby(['capture','family']):metrics_table.append({'capture':cap,'family':family,**metrics(g.label,g.probability)})
 clean_summary=pd.DataFrame(metrics_table);clean_summary.to_csv(OUT/'EXPERIMENT1_clean_transfer_metrics.csv',index=False)
 print('\nEXPERIMENT 1 — CLEAN TRANSFER\n'+clean_summary.to_string(index=False),flush=True)
 print('\nEXACT REPRESENTATION/LABEL CONFLICTS\n'+pd.DataFrame(conflicts).to_string(index=False),flush=True)
 return probabilities

def experiment2(diag,models,train,targets):
 clean=targets[49];path=locate(diag/'capture_49',['extractor_inputs_delay10_timeout5.csv.gz','extractor_records_delay10_timeout5.csv.gz'])
 stressed,coverage=stream_records(path,set(clean.ks));js(OUT/'EXPERIMENT2_stressed_start_key_coverage.json',coverage)
 common=sorted(set(clean.ks)&set(stressed.ks));a=clean.set_index('ks').loc[common];b=stressed.set_index('ks').loc[common]
 if not common:raise Stop('No unambiguous original-start matches; do not synthesize stress rows')
 feature_rows=[]
 for c in NUM:
  changed=~np.isclose(a[c].to_numpy(float),b[c].to_numpy(float),atol=1e-9,rtol=1e-9)
  scale=float(np.log1p(train[c]).std(ddof=0));difference=np.log1p(b[c].to_numpy(float))-np.log1p(a[c].to_numpy(float))
  feature_rows.append({'feature':c,'matched_original_start_keys':len(common),'changed_start_records':int(changed.sum()),
   'mean_log1p_difference':float(difference.mean()),'source_train_log1p_SD':scale,
   'mean_abs_log1p_change_in_source_SD':float(np.abs(difference).mean()/scale) if scale>1e-12 else np.nan,
   'scope':'observed paired feature change; no independent feature edits or causal proof'})
 pd.DataFrame(feature_rows).to_csv(OUT/'EXPERIMENT2_paired_feature_changes.csv',index=False)
 transitions=[]
 with threadpool_limits(limits=2):
  for family,model in models.items():
   p0=model.predict_proba(encode(a))[:,1];p1=model.predict_proba(encode(b))[:,1];d0=p0>=.5;d1=p1>=.5
   pd.DataFrame({'ks':common,'reference_original_unit_label':a.label.to_numpy(),
    'clean_probability':p0,'stressed_start_record_probability':p1,'clean_prediction':d0,'stressed_start_record_prediction':d1,
    'scope':'original-start-key response only; not all-descendant detection or automatic label assignment to mixed transformed records'}).to_csv(OUT/f'EXPERIMENT2_start_response_{family}.csv',index=False)
   transitions.append({'family':family,'clean_reference_units':len(clean),'matched_start_records':len(common),
    'start_response_positive_to_negative':int((d0&~d1).sum()),'start_response_negative_to_positive':int((~d0&d1).sum()),
    'mean_probability_change':float((p1-p0).mean()),'scope':'start-key response diagnostic, not corrected original-unit recall'})
 result=pd.DataFrame(transitions);result.to_csv(OUT/'EXPERIMENT2_response_summary.csv',index=False)
 print('\nEXPERIMENT 2 — PAIRED START-RECORD RESPONSE\n'+result.to_string(index=False),flush=True)


def source_FPR_cutoff(negative_probabilities,alpha):
 negative=np.sort(np.asarray(negative_probabilities,float));n=len(negative)
 if not n:raise Stop('No source benign records for threshold')
 budget=int(math.floor(alpha*n))
 return float(negative[n-budget-1]),budget

def experiment3(models,hold,targets):
 thresholds=[];rows=[]
 with threadpool_limits(limits=2):
  for family,model in models.items():
   source_p=model.predict_proba(encode(hold))[:,1];y=hold.y.to_numpy();negative=source_p[y==0]
   settings=[('PARENT_0_5',.5,False,None,None)]
   for alpha in [.01,.05]:
    cut,budget=source_FPR_cutoff(negative,alpha);settings.append((f'SOURCE_FPR_{int(100*alpha)}PCT',cut,True,alpha,budget))
   for name,cut,strict,alpha,budget in settings:
    actual=float(((negative>cut) if strict else (negative>=cut)).mean())
    if alpha is not None and actual>alpha+1e-12:raise Stop('Tie-safe source FPR budget exceeded')
    thresholds.append({'family':family,'operating_point':name,'threshold':cut,'comparison':'>' if strict else '>=',
     'source_benign_rows':len(negative),'requested_source_FPR':alpha,'source_false_positive_budget':budget,'achieved_source_FPR':actual,
     'source_reference_reuses_previously_exposed_holdout':True,'target_labels_used_for_cutoff':False})
    rows.append({'domain':'source_reference_used_for_threshold','family':family,'operating_point':name,**metrics(y,source_p,cut,strict)})
    for cap,target in targets.items():
     p=model.predict_proba(encode(target))[:,1]
     rows.append({'domain':'capture_'+str(cap)+'_clean_original_records','family':family,'operating_point':name,**metrics(target.label,p,cut,strict)})
 pd.DataFrame(thresholds).to_csv(OUT/'EXPERIMENT3_source_only_thresholds.csv',index=False)
 result=pd.DataFrame(rows);result.to_csv(OUT/'EXPERIMENT3_clean_operating_point_comparison.csv',index=False)
 print('\nEXPERIMENT 3 — SOURCE-FIXED OPERATING POINTS, CLEAN TARGETS ONLY\n'+result.to_string(index=False),flush=True)
 return result


def main():
 diag,models,train,hold,targets,units=load_inputs()
 js(OUT/'analysis_protocol.json',{'source_panel_original_gzip_byte_hash_not_claimed':True,'source_identity_check':'audited model bytes, preserved roles/counts/groups and source metric reproduction','parent_run':PARENT_ID,'diagnostic_run':DIAG_ID,'models':EXPECTED,
  'experiment1':'source-support and exact predictor/label pattern audit',
  'experiment2':'observed clean-to-stressed original-start response, NOT re-labeling transformed records or claiming descendant recall',
  'experiment3':'fixed 0.5 and source-derived 1%/5% FPR operating points, clean targets only',
  'new_model_fits':0,'new_replays':0,'thresholds_selected_from_targets':False,
  'post_exposure_analysis':True,'independent_confirmation':False,
  'data_labels_not_invented':True,'exact_pattern_conflicts_are_not_a_new_theorem':True})
 experiment1(models,train,hold,targets);js(OUT/'progress.json',{'completed':[1]})
 experiment2(diag,models,train,targets);js(OUT/'progress.json',{'completed':[1,2]})
 result=experiment3(models,hold,targets)
 R.update({'status':'THREE_SAVED_ARTIFACT_ANALYSES_COMPLETE','source_thresholds_derived':True,
  'new_calibrated_probability_model_fits':0,'models_and_source_split_reproduced':True,
  'primary_remeasurement_negative_result_preserved':True,'new_defense_validated':False,
  'limits':['Only tested stored panels; one/two target benign units cannot establish robust false-alarm performance.',
   'Source holdout is reused for threshold derivation, not a fresh calibration confirmation.',
   'Exact predictor/label conflicts can reflect missing context or annotation differences; not proof the corpus is bad.',
   'Start-key stress responses do not replace packet-attributed original-unit detection.',
   'No deployment model/threshold is selected from these target diagnostics.']})

try:main()
except Exception as e:
 R.update({'status':'STOPPED_WITH_EXACT_REASON','reason':str(e)})
 (OUT/'error.txt').write_text(traceback.format_exc());print('\nSTOPPED:',e,flush=True)
finally:
 js(OUT/'input_manifest.json',USED);js(OUT/'receipt.json',R)
 try:
  package=OUT/'PRIVATE_saved_artifact_analysis.zip'
  with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
   for p in sorted(OUT.iterdir()):
    if p.is_file() and p!=package:z.write(p,p.name)
  with zipfile.ZipFile(package) as z:
   if z.testzip():raise Stop('ZIP CRC failed')
  print('PRIVATE RESULT PACKAGE:',package,'SHA256:',sha(package),flush=True)
 except Exception as e:print('Packaging issue:',e,flush=True)
 print('\nANALYSIS RECEIPT\n'+json.dumps(R,indent=2),flush=True)
