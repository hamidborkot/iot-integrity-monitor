import gc,hashlib,itertools,json,traceback
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder,FunctionTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix,roc_auc_score
from threadpoolctl import threadpool_limits

MAX_JOBS_THIS_CALL=18

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def canonical(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()
ctx=json.loads(Path('/kaggle/working/CLOSING_CURRENT_SOURCE_DRIVER.json').read_text())
out=Path(ctx['run_directory']);cfg=json.loads(Path(ctx['configuration_path']).read_text())
if canonical(cfg)!=ctx['configuration_sha256']:raise RuntimeError('Driver configuration hash mismatch')
if sha(cfg['allocation_path'])!=cfg['allocation_sha256']:raise RuntimeError('Allocation changed')
df=pd.read_parquet(cfg['allocation_path']);role=cfg['role_column'];ident=pd.read_parquet(out/'identity_audit.parquet')
if not np.array_equal(df.record_id.astype(str),ident.record_id.astype(str)):raise ValueError('Identity-audit row order differs')
for c in ['proto','id.resp_p','service','conn_state','history']:
 df[c]=df[c].astype(str)
df['proto']=df.proto.str.lower()

def pipeline(columns,parameters):
 categories=set(['proto','id.resp_p','service','conn_state','history'])
 numeric=[c for c in columns if c not in categories];context=[c for c in columns if c in categories and c!='proto']
 transforms=[]
 if numeric:transforms.append(('numeric',FunctionTransformer(np.log1p,feature_names_out='one-to-one'),numeric))
 if 'proto' in columns:transforms.append(('protocol',OneHotEncoder(categories=[['tcp','udp','icmp']],handle_unknown='ignore',sparse_output=False),['proto']))
 if context:transforms.append(('context',OneHotEncoder(handle_unknown='ignore',min_frequency=10,max_categories=64,sparse_output=False),context))
 return Pipeline([('preprocessor',ColumnTransformer(transforms,remainder='drop',sparse_threshold=0)),('classifier',HistGradientBoostingClassifier(**parameters))])

def metric(y,p):
 d=(p>=cfg['classification_threshold']).astype(int);tn,fp,fn,tp=confusion_matrix(y,d,labels=[0,1]).ravel()
 tpr=tp/(tp+fn) if tp+fn else np.nan;fpr=fp/(fp+tn) if fp+tn else np.nan
 return {'rows':len(y),'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp),'accuracy':float((d==y).mean()),
'balanced_accuracy':float((tpr+1-fpr)/2) if np.isfinite(tpr+fpr) else np.nan,
'malicious_recall':float(tpr),'benign_FPR':float(fpr),'AUROC':float(roc_auc_score(y,p)) if len(np.unique(y))==2 else np.nan,'predicted_positive_fraction':float(d.mean())}

def verify_job(job):
 receipt=job/'receipt.json'
 if not receipt.exists():return False
 r=json.loads(receipt.read_text())
 if r.get('status')!='SOURCE_FOLD_COMPLETE' or r.get('configuration_sha256')!=ctx['configuration_sha256']:raise ValueError('Checkpoint receipt/configuration conflict: '+str(job))
 for name,digest in r['artifact_hashes'].items():
  if sha(job/name)!=digest:raise ValueError('Checkpoint hash mismatch: '+str(job/name))
 return True

jobs=list(itertools.product(cfg['schemas'],cfg['sources'],cfg['seeds']))
completed=0;executed=0;failure=None
for schema,held,seed in jobs:
 job=out/'folds'/schema/held/f'seed_{seed}'
 try:
  if verify_job(job):completed+=1;continue
  if executed>=MAX_JOBS_THIS_CALL:break
  job.mkdir(parents=True,exist_ok=True)
  train_mask=df.source_scenario.ne(held)&df[role].eq('train')
  held_mask=df.source_scenario.eq(held);test_mask=held_mask&df[role].eq('source_validation')
  train=df.loc[train_mask];test=df.loc[test_mask];evaluation=df.loc[held_mask]
  if set(train.y)!={0,1} or set(test.y)!={0,1}:raise ValueError('Missing training/evaluation class')
  fit_groups=set(ident.loc[train_mask,'allocation_group']);test_groups=set(ident.loc[test_mask,'allocation_group'])
  if fit_groups&test_groups:raise ValueError('Scoped directed group overlaps primary source-validation population')
  global_overlap=len(set(ident.loc[train_mask,'directed_group'])&set(ident.loc[test_mask,'directed_group']))
  definitions={'PRIMARY':cfg['schemas'][schema],**cfg['views'][schema]}
  models={};rows=[];feature_diagnostics=[];predictions=evaluation[['record_id','source_scenario',role,'y']].copy()
  if 'ts' in evaluation:predictions['ts']=evaluation.ts
  params=cfg['hgb_parameters'][str(seed)]
  mapping={'PRIMARY':'PRIMARY','originator':'V_orig','responder':'V_resp','timing':'V_time_proto','context':'V_time_proto'}
  with threadpool_limits(limits=cfg['thread_limit']):
   for name,columns in definitions.items():
    numeric_columns=[c for c in columns if c not in {'proto','id.resp_p','service','conn_state','history'}]
    feature_diagnostics.append({'schema':schema,'held_capture':held,'seed':seed,'model':name,
'evaluated_columns':'|'.join(columns),'postprocessing_missing_fraction':float(test[columns].isna().to_numpy().mean()),
'all_zero_numeric_fraction':float(test[numeric_columns].eq(0).all(axis=1).mean()) if numeric_columns else np.nan,
'missingness_scope':'Processed panel; original numeric missingness cannot be inferred from zero-filled values'})
    model=pipeline(columns,params[mapping[name]])
    model.fit(train[columns],train.y)
    p=model.predict_proba(evaluation[columns])[:,1]
    if not np.isfinite(p).all():raise ValueError('Nonfinite predictions')
    predictions[name+'_probability']=p
    models[name]=model
    for scope,mask in [('held_source_validation',evaluation[role].eq('source_validation').to_numpy()),('held_all_secondary',np.ones(len(evaluation),dtype=bool))]:
     rows.append({'schema':schema,'held_capture':held,'seed':seed,'model':name,'scope':scope,**metric(evaluation.y.to_numpy()[mask],p[mask])})
   if schema=='core9' and seed==cfg['seeds'][0]:
    for name,columns in {'shortcut_protocol':['proto'],'shortcut_port':['id.resp_p'],'shortcut_protocol_port':['proto','id.resp_p']}.items():
     model=pipeline(columns,params['PRIMARY']);model.fit(train[columns],train.y)
     p=model.predict_proba(evaluation[columns])[:,1];models[name]=model;predictions[name+'_probability']=p
     mask=evaluation[role].eq('source_validation').to_numpy()
     rows.append({'schema':schema,'held_capture':held,'seed':seed,'model':name,'scope':'held_source_validation',**metric(evaluation.y.to_numpy()[mask],p[mask])})
  dependencies=[];mask=evaluation[role].eq('source_validation').to_numpy();y=evaluation.y.to_numpy()[mask]
  for a,b in itertools.combinations(cfg['views'][schema],2):
   da=predictions[a+'_probability'].to_numpy()[mask]>=.5;db=predictions[b+'_probability'].to_numpy()[mask]>=.5
   ea=(da!=y).astype(float);eb=(db!=y).astype(float)
   correlation=float(np.corrcoef(ea,eb)[0,1]) if ea.std()>0 and eb.std()>0 else np.nan
   dependencies.append({'schema':schema,'held_capture':held,'seed':seed,'left':a,'right':b,'rows':len(y),
'disagreement':float((da!=db).mean()),'joint_error':float(((ea==1)&(eb==1)).mean()),'error_correlation':correlation})
  for name,obj in [('models.joblib',models)]:
   temp=job/(name+'.partial');joblib.dump(obj,temp);temp.replace(job/name)
  temp=job/'predictions.partial.parquet';predictions.to_parquet(temp,index=False);temp.replace(job/'predictions.parquet')
  pd.DataFrame(rows).to_csv(job/'metrics.csv',index=False)
  pd.DataFrame(dependencies).to_csv(job/'dependence.csv',index=False)
  pd.DataFrame(feature_diagnostics).to_csv(job/'feature_diagnostics.csv',index=False)
  artifacts=['models.joblib','predictions.parquet','metrics.csv','dependence.csv','feature_diagnostics.csv']
  r={'status':'SOURCE_FOLD_COMPLETE','configuration_sha256':ctx['configuration_sha256'],
'allocation_sha256':cfg['allocation_sha256'],'schema':schema,'held_capture':held,'seed':seed,
'fit_rows':len(train),'primary_test_rows':len(test),'held_capture_in_fit':False,
'primary_test_scoped_group_overlap':0,'primary_test_equal_cross_capture_tuples_diagnostic':global_overlap,
'group_scope':'source capture plus directed five-tuple; not a physical-device independence certificate',
'new_target_records_read':False,'source_only_development':True,'artifact_hashes':{name:sha(job/name) for name in artifacts}}
  temp=job/'receipt.json.partial';temp.write_text(json.dumps(r,indent=2));temp.replace(job/'receipt.json')
  executed+=1;completed+=1
  print('COMPLETED',schema,held,seed,'primary_test_rows',len(test),flush=True)
  del models,predictions;gc.collect()
 except Exception as error:
  failure={'schema':schema,'held_capture':held,'seed':seed,'error':f'{type(error).__name__}: {error}'}
  job.mkdir(parents=True,exist_ok=True);(job/'failure.txt').write_text(traceback.format_exc());print('STOPPED:',json.dumps(failure),flush=True);break
valid=0
for schema,held,seed in jobs:
 if verify_job(out/'folds'/schema/held/f'seed_{seed}'):valid+=1
summary={'status':'ALL_SOURCE_FOLDS_COMPLETE' if valid==len(jobs) else 'SOURCE_FOLD_BATCH_INCOMPLETE',
'run_directory':str(out),'configuration_sha256':ctx['configuration_sha256'],'jobs_expected':len(jobs),'jobs_verified':valid,
'jobs_executed_this_call':executed,'batch_limit':MAX_JOBS_THIS_CALL,'failure':failure,
'new_targets_read':False,'next_step':'Run Cell 3' if valid==len(jobs) else 'Rerun Cell 2 unchanged; completed jobs are verified and reused' if failure is None else 'Resolve the reported technical failure before continuing'}
(out/'training_progress.json').write_text(json.dumps(summary,indent=2));print('\n=== SOURCE-FOLD PROGRESS ===\n'+json.dumps(summary,indent=2))
