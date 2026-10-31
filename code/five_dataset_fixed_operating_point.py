# Five-dataset extension using canonical saved bundles. No training or PCAP work.
from pathlib import Path
from datetime import datetime,timezone
import gc,hashlib,json,math,os,shutil,sys,traceback,warnings,zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');OWNER=Path('/kaggle/input/datasets/mdhamidborkottulla')
ROOT=W/'FIVE_DATASET_FIXED_OP_V1';ROOT.mkdir(parents=True,exist_ok=True)
DATA={
 'CICIoT2023':{'features':46,'sha256':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88'},
 'CICIoMT2024':{'features':45,'sha256':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473'},
 'CSE':{'features':77,'sha256':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3'},
 'NSL':{'features':112,'sha256':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29'},
 'TONIoT':{'features':75,'sha256':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf'}}
BACKUPS=[OWNER/name for name in ['all-kaggle-work','complete-backup','full-backup','the-last-update','whole-in-one','one-last','batch5','full-working-backup','ran-files','the-last-days-backup','last-day-backup']]
SETTINGS={'version':'five_dataset_fixed_op_v1','source_FPR_levels':[.01,.05],
 'source_reference_resamples':200,'resampling_seed':99301,'prediction_batch_rows':2048,
 'warning_drop':.05,'monitor_comparison_operating_point':'RAW_0_5_ONLY',
 'bootstrap_scope':'conditional benign-calibration-row sensitivity; not cluster-independent inference',
 'source_calibration_role':'primary_calibration_df','source_monitor_reference_role':'source_test_df',
 'saved_threshold_decision':'>','raw_0_5_decision':'>='}
class Stop(Exception):pass

def js(path,value):
 path=Path(path);tmp=path.with_name(path.name+'.tmp');tmp.write_text(json.dumps(value,indent=2,default=str),encoding='utf-8');tmp.replace(path)
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def inventory():
 bundles={d:[] for d in DATA};receipts=[];seen=set();files=0
 names={d+'_bundle.joblib':d for d in DATA}
 for root in [W]+BACKUPS:
  if not root.is_dir():continue
  for current,dirs,fs in os.walk(root,followlinks=False):
   dirs[:]=[d for d in dirs if d not in {'.git','__pycache__'}]
   for name in fs:
    p=Path(current)/name
    if p.is_symlink() or str(p) in seen:continue
    seen.add(str(p));files+=1
    if name in names:bundles[names[name]].append(p)
    if name=='receipt.json' and any(part=='FIVE_DATASET_FIXED_OP_V1' for part in p.parts):receipts.append(p)
 js(ROOT/'bundle_locations.json',{d:[str(p) for p in ps] for d,ps in bundles.items()})
 print('Indexed',files,'saved files; exact bundle-name candidates:',{d:len(ps) for d,ps in bundles.items()},flush=True)
 return bundles,receipts

def canonical_bundle(dataset,paths):
 expected=DATA[dataset]['sha256'];audit=[]
 ordered=sorted(paths,key=lambda p:('fresh_all_datasets_v1' not in p.parts,len(p.parts),str(p)))
 for path in ordered:
  size=path.stat().st_size
  if size>128*1024**2:audit.append({'path':str(path),'status':'OVER_128_MIB_LIMIT'});continue
  h=sha(path);audit.append({'path':str(path),'sha256':h,'canonical':h==expected})
  if h==expected:return path,audit
 raise Stop('Exact canonical '+dataset+' bundle not found among mounted saved files. Expected SHA256 '+expected+'. No different model or new training substituted.')

def validate_frame(frame,features,name):
 if not isinstance(frame,pd.DataFrame) or frame.empty:raise Stop(name+' is not a nonempty saved DataFrame')
 if not set(features+['label']).issubset(frame):raise Stop(name+' lacks preserved features/label')
 labels=pd.to_numeric(frame['label'],errors='raise').to_numpy()
 if not np.isin(labels,[0,1]).all():raise Stop(name+' has nonbinary labels')
 cols=[c for c in ['row_id','_row_id'] if c in frame]
 if not cols:raise Stop(name+' lacks a real saved row identifier; no fabricated row IDs')
 ids=frame[cols[0]].astype(str).to_numpy()
 if len(cols)>1 and not np.array_equal(ids,frame[cols[1]].astype(str).to_numpy()):raise Stop(name+' contains conflicting ID aliases')
 if len(set(ids))!=len(ids):raise Stop(name+' contains duplicated row IDs')
 return labels.astype(int),ids,cols[0]

def predict(model,frame,features):
 parts=[]
 with threadpool_limits(limits=2):
  for start in range(0,len(frame),SETTINGS['prediction_batch_rows']):
   p=model.predict_proba(frame.iloc[start:start+SETTINGS['prediction_batch_rows']][features])[:,1]
   if not np.isfinite(p).all() or ((p<0)|(p>1)).any():raise Stop('Nonfinite/out-of-range probabilities')
   parts.append(p)
 return np.concatenate(parts)

def metrics(y,p,cut,strict):
 y=np.asarray(y,int);p=np.asarray(p,float);pred=p>cut if strict else p>=cut;neg=y==0;pos=y==1
 if len(y)==0:raise Stop('Empty metric population')
 return {'records':len(y),'benign':int(neg.sum()),'malicious':int(pos.sum()),
 'FP':int((pred&neg).sum()),'FN':int((~pred&pos).sum()),'accuracy':float((pred==y).mean()),
 'balanced_accuracy':float(balanced_accuracy_score(y,pred)) if neg.any() and pos.any() else np.nan,
 'AUROC':float(roc_auc_score(y,p)) if neg.any() and pos.any() else np.nan,
 'recall':float(pred[pos].mean()) if pos.any() else np.nan,'FPR':float(pred[neg].mean()) if neg.any() else np.nan,
 'small_benign_denominator':int(neg.sum())<100}

def cutoff(negative,alpha):
 p=np.sort(np.asarray(negative,float));n=len(p)
 if n==0 or not 0<=alpha<1:raise Stop('Invalid calibration cutoff inputs')
 budget=int(math.floor(alpha*n));return float(p[n-budget-1]),budget

def atc_fit(confidence,correct):
 c=np.asarray(confidence,float);n=int(np.asarray(correct,bool).sum())
 if n==0:return float(np.nextafter(c.max(),np.inf)),0.
 t=float(np.sort(c)[::-1][n-1]);above=int((c>t).sum());ties=int((c==t).sum())
 alpha=(n-above)/ties
 if not 0<=alpha<=1:raise Stop('ATC source-tie calculation invalid')
 return t,float(alpha)

def verify_job(job,signature):
 receipt=job/'receipt.json'
 if not receipt.is_file():return False
 r=json.loads(receipt.read_text())
 if r.get('status')!='DATASET_EXTENSION_COMPLETE' or r.get('experiment_signature')!=signature:return False
 for name,h in r.get('artifact_sha256',{}).items():
  p=job/name
  if not p.is_file() or sha(p)!=h:raise Stop('Completed cache artifact is missing/changed: '+str(p)+'. Old job not overwritten.')
 if not r.get('artifact_sha256'):raise Stop('Completed cache has no artifact manifest')
 return True

def reuse(job,signature,receipts):
 if verify_job(job,signature):return job
 for p in receipts:
  if p.parent.name!=job.name:continue
  if verify_job(p.parent,signature):
   if job.exists():raise Stop('Partial local job conflicts with a completed mounted job; no overwrite')
   shutil.copytree(p.parent,job)
   if not verify_job(job,signature):raise Stop('Copied result cache did not verify')
   return job
 return None


def run_dataset(dataset,path,job,signature,identity):
 job.mkdir(parents=True,exist_ok=True)
 source_before=sha(path)
 from sklearn.exceptions import InconsistentVersionWarning
 with warnings.catch_warnings():
  warnings.simplefilter('error',InconsistentVersionWarning);bundle=joblib.load(path)
 required={'primary_model','primary_features','primary_threshold','primary_calibration_df','source_test_df','train_df','evaluation_domains'}
 if not isinstance(bundle,dict) or not required.issubset(bundle):raise Stop('Canonical bundle schema mismatch')
 features=[str(c) for c in bundle['primary_features']]
 if len(features)!=DATA[dataset]['features'] or len(set(features))!=len(features):raise Stop('Canonical feature count mismatch')
 if set(features)&{'label','row_id','_row_id'}:raise Stop('Label or record identifier in model predictors')
 model=bundle['primary_model']
 recorded_threshold=float(bundle['primary_threshold'])
 if not np.isfinite(recorded_threshold) or not 0<=recorded_threshold<=1:raise Stop('Recorded threshold is invalid')
 if list(model.classes_)!=[0,1]:raise Stop('Primary model class order mismatch')
 frames={'source_train':bundle['train_df'],'source_calibration':bundle['primary_calibration_df'],'source_reference':bundle['source_test_df']}
 targets=bundle['evaluation_domains']
 if not isinstance(targets,dict) or not targets:raise Stop('No saved natural-shift evaluation domains')
 frames.update({'target::'+str(name):frame for name,frame in targets.items()})
 arrays={};ids={};schema=[]
 for name,frame in frames.items():
  y,record_ids,id_column=validate_frame(frame,features,name);arrays[name]={'y':y};ids[name]=set(record_ids)
  schema.append({'dataset':dataset,'role':name,'records':len(frame),'benign':int((y==0).sum()),'malicious':int((y==1).sum()),'ID_column':id_column})
 overlaps=[]
 for left,right in [('source_train','source_calibration'),('source_train','source_reference'),('source_calibration','source_reference')]:
  n=len(ids[left]&ids[right]);overlaps.append({'left':left,'right':right,'shared_record_IDs':n})
  if n:raise Stop('Unexpected source allocation overlap: '+left+'/'+right)
 for name in frames:
  if not name.startswith('target::'):continue
  for source in ['source_train','source_calibration','source_reference']:
   n=len(ids[source]&ids[name]);overlaps.append({'left':source,'right':name,'shared_record_IDs':n})
   if n:raise Stop('Target/source saved row overlap: '+source+'/'+name)
 target_names=[k for k in frames if k.startswith('target::')]
 for i,a in enumerate(target_names):
  for b in target_names[i+1:]:overlaps.append({'left':a,'right':b,'shared_record_IDs':len(ids[a]&ids[b]),'note':'target-domain dependence retained, no independent-domain pooling'})
 pd.DataFrame(schema).to_csv(job/'allocation_schema.csv',index=False);pd.DataFrame(overlaps).to_csv(job/'row_ID_overlap.csv',index=False)
 if not np.all(arrays['source_calibration']['y']==0):raise Stop('Primary calibration frame is not benign-only as in the canonical generator')
 predictions=[]
 for name,frame in frames.items():
  if name=='source_train':continue
  p=predict(model,frame,features);arrays[name]['p']=p
  _,record_ids,_=validate_frame(frame,features,name)
  predictions.append(pd.DataFrame({'dataset':dataset,'domain':name,'row_id':record_ids,'label':arrays[name]['y'],'probability':p}))
  print(dataset,name,'predicted',len(frame),'saved records',flush=True)
 pd.concat(predictions,ignore_index=True).to_csv(job/'fixed_model_predictions.csv',index=False)
 negative=arrays['source_calibration']['p'];settings=[{'name':'RECORDED_THRESHOLD','cut':float(bundle['primary_threshold']),'strict':True,'alpha':None},
  {'name':'RAW_0_5','cut':.5,'strict':False,'alpha':None}]
 ties=[]
 for alpha in SETTINGS['source_FPR_levels']:
  t,budget=cutoff(negative,alpha);name=f'SOURCE_FPR_{int(alpha*100)}PCT'
  settings.append({'name':name,'cut':t,'strict':True,'alpha':alpha})
  ties.append({'dataset':dataset,'operating_point':name,'source_benign':len(negative),'threshold':t,
   'allowed_FP':budget,'below':int((negative<t).sum()),'at':int((negative==t).sum()),'above':int((negative>t).sum()),'source_FPR':float((negative>t).mean())})
 pd.DataFrame(settings).to_csv(job/'operating_points.csv',index=False);pd.DataFrame(ties).to_csv(job/'source_cutoff_ties.csv',index=False)
 metric_rows=[]
 for setting in settings:
  for name,a in arrays.items():
   if name=='source_train':continue
   metric_rows.append({'dataset':dataset,'domain':name,'operating_point':setting['name'],**metrics(a['y'],a['p'],setting['cut'],setting['strict'])})
 pd.DataFrame(metric_rows).to_csv(job/'EXPERIMENT1_threshold_transfer.csv',index=False)

 # Conditional row-resampling analysis: no fabricated physical groups.
 rng=np.random.default_rng(SETTINGS['resampling_seed']);resamples=[]
 for rep in range(SETTINGS['source_reference_resamples']):
  boot=negative[rng.integers(0,len(negative),len(negative))]
  for alpha in SETTINGS['source_FPR_levels']:
   t,_=cutoff(boot,alpha)
   for name in target_names:
    a=arrays[name];y=a['y'];decision=a['p']>t;ben=y==0;mal=y==1
    resamples.append({'dataset':dataset,'domain':name,'alpha':alpha,'replicate':rep,'threshold':t,
     'FPR':float(decision[ben].mean()) if ben.any() else np.nan,'recall':float(decision[mal].mean()) if mal.any() else np.nan})
 rs=pd.DataFrame(resamples);rs.to_csv(job/'EXPERIMENT2_conditional_calibration_resamples.csv',index=False)
 if not rs.empty:
  rs.groupby(['dataset','domain','alpha'],as_index=False).agg(threshold_min=('threshold','min'),threshold_median=('threshold','median'),threshold_max=('threshold','max'),
   FPR_min=('FPR','min'),FPR_median=('FPR','median'),FPR_max=('FPR','max'),recall_min=('recall','min'),recall_median=('recall','median'),recall_max=('recall','max')).to_csv(job/'EXPERIMENT2_sensitivity_summary.csv',index=False)

 # Conventional argmax-decision monitors only; not activity/packet recall estimators.
 ref=arrays['source_reference'];conf0=np.maximum(ref['p'],1-ref['p']);correct0=(ref['p']>=.5)==ref['y'];A0=float(correct0.mean());C0=float(conf0.mean())
 t,alpha=atc_fit(conf0,correct0)
 estimated_ref={'AC':C0,'DoC':A0,'ATC_FRACTIONAL_TIE':float(((conf0>t)+alpha*(conf0==t)).mean())}
 if not np.isclose(estimated_ref['ATC_FRACTIONAL_TIE'],A0,atol=1e-12):raise Stop('Source ATC fitted coverage failed reproduction')
 monitor_rows=[]
 for name in target_names:
  a=arrays[name];p=a['p'];confidence=np.maximum(p,1-p);truth=float(((p>=.5)==a['y']).mean())
  estimates={'AC':float(confidence.mean()),'DoC':float(np.clip(A0+confidence.mean()-C0,0,1)),
   'ATC_FRACTIONAL_TIE':float(((confidence>t)+alpha*(confidence==t)).mean())}
  for method,value in estimates.items():
   estdrop=estimated_ref[method]-value;drop=A0-truth
   monitor_rows.append({'dataset':dataset,'domain':name,'estimator':method,'operating_point':'RAW_0_5_ONLY','records':len(p),
    'source_true_accuracy':A0,'target_true_accuracy':truth,'estimated_accuracy':value,'absolute_error':abs(value-truth),
    'overestimation':value-truth,'actual_accuracy_drop':drop,'estimated_accuracy_drop':estdrop,
    'differential_error':abs((value-truth)-(estimated_ref[method]-A0)),
    'warning_at_5pp':estdrop>=SETTINGS['warning_drop'],'actual_drop_at_least_5pp':drop>=SETTINGS['warning_drop'],
    'scope':'record accuracy on exposed saved natural-shift domains; not original-unit recall, packet evasion or MD3'})
 pd.DataFrame(monitor_rows).to_csv(job/'EXPERIMENT3_unlabeled_point_monitors.csv',index=False)
 js(job/'source_monitor_fit.json',{'reference_role':'source_test_df, reused as labelled source monitor reference','accuracy':A0,'confidence_mean':C0,'ATC_cutoff':t,'tie_fraction':alpha,'reference_estimates':estimated_ref})
 if sha(path)!=source_before:raise Stop('Canonical input bundle changed while being read')
 js(job/'input_identity.json',{**identity,'selected_bundle_path':str(path),'canonical_bundle_sha256':source_before,'model_type':str(type(model)),
  'features':features,'recorded_threshold_comparison':'>','primary_model_refitted':False,
  'row_ID_disjointness_is_not_physical_source_independence':True})
 artifacts={p.name:sha(p) for p in job.iterdir() if p.is_file() and p.name not in {'receipt.json','failure.txt'}}
 receipt={'status':'DATASET_EXTENSION_COMPLETE','dataset':dataset,'experiment_signature':signature,'artifact_sha256':artifacts,
  'canonical_bundle_sha256':source_before,'model_fits':0,'replays':0,'target_domain_count':len(target_names),
  'scope':'fixed primary model, exposed tabular natural-shift data, source-only operating points and basic point-monitor extension',
  'independent_confirmation':False,'all_original_A_to_G_requirements_complete':False,'new_defense_validated':False}
 js(job/'receipt.json',receipt);gc.collect();return receipt


def package(selected):
 dest=ROOT/'PRIVATE_five_dataset_fixed_op_checkpoint.zip';tmp=ROOT/'checkpoint.tmp'
 with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in ROOT.iterdir():
   if p.is_file() and p not in [dest,tmp] and p.suffix!='.zip':z.write(p,p.name)
  for job in selected:
   if not job.is_dir():continue
   for p in job.iterdir():
    if p.is_file() and p.suffix!='.zip':z.write(p,str(p.relative_to(ROOT)))
 with zipfile.ZipFile(tmp) as z:
  if z.testzip():raise Stop('Checkpoint CRC failed')
 tmp.replace(dest);return {'path':str(dest),'bytes':dest.stat().st_size,'sha256':sha(dest)}


def main():
 if not W.is_dir():raise Stop('Run this script in Kaggle')
 source=globals().get('__file__');code_hash=sha(source) if source and Path(source).is_file() else digest(SETTINGS)
 environment={'python':sys.version.split()[0],'sklearn':__import__('sklearn').__version__,'numpy':np.__version__,'pandas':pd.__version__}
 js(ROOT/'extension_protocol.json',{'settings':SETTINGS,'canonical_bundles':DATA,'code_sha256':code_hash,'environment':environment,
  'new_model_fits':0,'new_attacks':0,'no_IoT23_module_rerun':True,
  'coverage':'CICIoT2023,CICIoMT2024,CSE,NSL,TONIoT stored primary models/natural-shift frames only',
  'not_equivalent_to_IoT23_raw_HGB_LR_bank':True,'no_packet_validity_claim':True,
  'all_target_data_are_previously_exposed':True,'one_frozen_primary_per_dataset_not_new_HGB_LR_banks':True})
 if source and Path(source).is_file():
  saved=ROOT/('runner_'+code_hash[:16]+'.py')
  if not saved.is_file():shutil.copyfile(source,saved)
 candidates,receipts=inventory();statuses=[];selected=[];allmetrics=[];allmonitors=[];allsensitivity=[]
 for dataset,info in DATA.items():
  signature=digest({'bundle':info['sha256'],'settings':SETTINGS,'code_sha256':code_hash,'environment':environment})
  job=ROOT/(dataset+'_'+signature[:16]);selected.append(job)
  try:
   cached=reuse(job,signature,receipts)
   if cached is not None:
    result=json.loads((cached/'receipt.json').read_text());state='REUSED_VERIFIED_COMPLETE'
    print(dataset,'REUSED — no model loading or predictions repeated.',flush=True)
   else:
    if job.exists() and (job/'receipt.json').is_file():
     existing=json.loads((job/'receipt.json').read_text())
     if existing.get('status')=='DATASET_EXTENSION_COMPLETE':raise Stop('Completed local job cannot be overwritten')
    path,resolution=canonical_bundle(dataset,candidates[dataset]);job.mkdir(exist_ok=True)
    js(job/'canonical_resolution.json',resolution)
    result=run_dataset(dataset,path,job,signature,{'settings':SETTINGS,'code_sha256':code_hash,'environment':environment});state='COMPUTED_COMPLETE'
   statuses.append({'dataset':dataset,'status':state,'job_directory':str(job),'signature':signature,'target_domains':result['target_domain_count']})
   allmetrics.append(pd.read_csv(job/'EXPERIMENT1_threshold_transfer.csv'))
   allmonitors.append(pd.read_csv(job/'EXPERIMENT3_unlabeled_point_monitors.csv'))
   p=job/'EXPERIMENT2_sensitivity_summary.csv'
   if p.is_file():allsensitivity.append(pd.read_csv(p))
  except Exception as e:
   job.mkdir(parents=True,exist_ok=True);(job/'failure.txt').write_text(traceback.format_exc())
   statuses.append({'dataset':dataset,'status':'EXPLICIT_GAP','job_directory':str(job),'signature':signature,'reason':str(e)})
   print(dataset,'GAP:',e,flush=True)
  pd.DataFrame(statuses).to_csv(ROOT/'dataset_completion_status.csv',index=False)
  if allmetrics:pd.concat(allmetrics,ignore_index=True).to_csv(ROOT/'ALL_threshold_transfer.csv',index=False)
  if allmonitors:pd.concat(allmonitors,ignore_index=True).to_csv(ROOT/'ALL_point_monitor_results.csv',index=False)
  if allsensitivity:pd.concat(allsensitivity,ignore_index=True).to_csv(ROOT/'ALL_conditional_sensitivity.csv',index=False)
  js(ROOT/'progress.json',{'datasets_finished_or_reported':len(statuses),'datasets':statuses})
  try:package(selected)
  except Exception as e:print('Checkpoint issue:',e,flush=True)
  gc.collect()
 complete=sum(x['status'] in ['COMPUTED_COMPLETE','REUSED_VERIFIED_COMPLETE'] for x in statuses)
 receipt={'status':'FIVE_DATASET_EXTENSION_COMPLETE' if complete==5 else 'FIVE_DATASET_EXTENSION_WITH_EXPLICIT_GAPS',
  'datasets_complete':complete,'datasets_expected':5,'datasets':statuses,'model_fits':0,'PCAP_replays':0,
  'original_IoT23_modules_repeated':False,'new_novelty_or_defense_success_claimed':False,
  'all_original_research_requirements_complete':False,'output_directory':str(ROOT)}
 js(ROOT/'receipt.json',receipt);cp=package(selected)
 print('\nDATASET COMPLETION\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
 if allmetrics:
  m=pd.concat(allmetrics,ignore_index=True)
  print('\nFIXED SOURCE OPERATING POINTS — TARGET DOMAINS\n'+m[m.domain.str.startswith('target::')].to_string(index=False),flush=True)
 if allmonitors:print('\nPOINT MONITOR RESULTS\n'+pd.concat(allmonitors,ignore_index=True).to_string(index=False),flush=True)
 print('\nFINAL RECEIPT\n'+json.dumps(receipt,indent=2),flush=True);print('PRIVATE CHECKPOINT:',json.dumps(cp,indent=2),flush=True)

try:main()
except Exception as e:
 js(ROOT/'fatal_receipt.json',{'status':'STOPPED_WITH_EXACT_REASON','reason':str(e),'model_fits':0,'replays':0})
 (ROOT/'fatal_error.txt').write_text(traceback.format_exc());print('STOPPED:',e,flush=True)
