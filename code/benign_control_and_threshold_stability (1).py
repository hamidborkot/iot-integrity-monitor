# Benign-control and operating-point experiment: zero training / installs / replays.
from pathlib import Path
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from collections import Counter,defaultdict
from contextlib import contextmanager
import gc,gzip,hashlib,heapq,io,json,math,os,shutil,sqlite3,sys,time,traceback,warnings,zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
BACKUP=Path('/kaggle/input/datasets/mdhamidborkottulla/full-working-backup')
PARENT_ID='RAW_ONLY_REMEASUREMENT_20261017T130813279947Z'
PARENT=BACKUP/'kaggle_working'/PARENT_ID
DIAG_ID='DIRECT_MOUNT_DIAGNOSTIC_20261018T024353091267Z'
DIAGNOSTIC_DIRECTORY_OVERRIDE=None
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
OUT=W/('BENIGN_OPERATING_POINT_TEST_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto'];NUM=F[:-1]
EXPECTED={'HGB':'adb02fbe0fb4582ce931c5c5bb5d71001647c801142b8a986018ea2983c063d1',
 'LR':'d80a15e78dd076f8b1f9905a627e8a6dab16c06596b6c792498553bda94e90a2'}
CFG={'captures':[7,49],'rows_per_class_cap':1024,'minimum_benign_for_informative_control':100,
 'published_log_row_limit':4000000,'published_log_time_limit_seconds':900,
 'pool_build_time_limit_seconds':900,'tail_seconds':120,'source_FPR_levels':[.01,.05],
 'source_group_resamples':200,'resampling_seed':99281,'CSV_chunk_rows':100000}
R={'status':'STARTED','model_fits':0,'PCAP_reads':0,'replays':0,'installs':0,
 'target_labels_used_for_threshold_selection':False,'novelty_established':False,'output_directory':str(OUT)}
USED=[]
class Stop(Exception):pass

def js(path,obj):
 path=Path(path);tmp=path.with_name(path.name+'.tmp');tmp.write_text(json.dumps(obj,indent=2,default=str),encoding='utf-8');tmp.replace(path)
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))

def num(x):
    v=0. if x in ['-','',None] else float(x)
    if not math.isfinite(v) or v<0:raise ValueError('Invalid predictor')
    return v

def features(r):
    x={c:num(r[c]) for c in F[:-1]};x['proto']=r['proto'].lower()
    if x['proto'] not in ['tcp','udp','icmp']:raise ValueError('Unsupported protocol')
    return x

def record_key(r):
    x=[us(r['ts']),r['id.orig_h'],int(r['id.orig_p']),r['id.resp_h'],int(r['id.resp_p']),r['proto'].lower()]
    return hashlib.sha256(json.dumps(x,separators=(',',':')).encode()).hexdigest()

def logs(path,labelled=False):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):
                fields=line.strip().split()[1:]
                if labelled and 'label' not in fields:raise Stop('Original primary label not parsed')
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Zeek field header missing')
                values=line.rstrip().split()
                if len(values)!=len(fields):raise Stop('Zeek row width differs from header')
                yield dict(zip(fields,values))

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])

def aliases(name):return [name,name[:-3]] if name.endswith('.gz') else ([name,name+'.gz'] if name.endswith('.csv') else [name])
def locate(root,names,required=True):
 if isinstance(names,str):names=[names]
 for d in [Path(root),Path(root)/'PRIVATE_raw_only_checkpoint']:
  for name in names:
   for alias in aliases(name):
    p=d/alias
    if p.is_file():return p
 if required:raise Stop('Required existing artifact absent: '+str(root)+' / '+str(names)+'. No replay or retraining will be launched.')
 return None
@contextmanager
def opened(path):
 with open(path,'rb') as f:magic=f.read(2)
 if magic==b'\x1f\x8b':
  with gzip.open(path,'rb') as f:yield f
 else:
  with open(path,'rb') as f:yield f

def csv_small(path):
 with opened(path) as f:data=f.read(64*1024**2+1)
 if len(data)>64*1024**2:raise Stop('Small-table read cap exceeded')
 USED.append({'path':str(path),'role':'metadata_table','sha256':sha(path)})
 return pd.read_csv(io.BytesIO(data),dtype={'ks':str,'group':str})
def metadata(root,name):
 p=locate(root,name);USED.append({'path':str(p),'role':'metadata','sha256':sha(p)})
 return json.loads(p.read_text())
def norm(df):
 df=df.copy()
 if not set(F).issubset(df):raise Stop('Feature columns missing')
 for c in NUM:
  df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
  if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid '+c)
 df['proto']=df.proto.astype(str).str.lower()
 if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
 if 'ks' in df:df['ks']=df.ks.astype(str)
 return df

def metric(y,p,cut=.5,strict=False):
 y=np.asarray(y,int);p=np.asarray(p,float)
 if len(y)==0 or y.shape!=p.shape or not np.isfinite(p).all() or ((p<0)|(p>1)).any() or not set(y).issubset({0,1}):raise Stop('Invalid metric arrays')
 pred=p>cut if strict else p>=cut;neg=y==0;pos=y==1
 fp=int((pred&neg).sum());fn=int((~pred&pos).sum())
 return {'rows':len(y),'benign_rows':int(neg.sum()),'malicious_rows':int(pos.sum()),'FP':fp,'FN':fn,
 'accuracy':float((pred==y).mean()),'balanced_accuracy':float(balanced_accuracy_score(y,pred)) if neg.any() and pos.any() else np.nan,
 'AUROC':float(roc_auc_score(y,p)) if neg.any() and pos.any() else np.nan,
 'malicious_recall':float(pred[pos].mean()) if pos.any() else np.nan,'benign_FPR':float(pred[neg].mean()) if neg.any() else np.nan}

def cutoff(negative,alpha):
 p=np.sort(np.asarray(negative,float));n=len(p)
 if n==0 or not 0<=alpha<1:raise Stop('Invalid source-cutoff inputs')
 budget=int(math.floor(alpha*n));return float(p[n-budget-1]),budget

def find_diagnostic():
 paths=([Path(DIAGNOSTIC_DIRECTORY_OVERRIDE)] if DIAGNOSTIC_DIRECTORY_OVERRIDE else [])+[W/DIAG_ID,BACKUP/'kaggle_working'/DIAG_ID,BACKUP/DIAG_ID]
 for d in paths:
  if not d.is_dir():continue
  r=metadata(d,'receipt.json')
  if r.get('status')=='MECHANISM_DIAGNOSIS_COMPLETE' and r.get('parent_models_and_evaluated_keys_and_decisions_reproduced') is True:return d
 raise Stop('Completed diagnostic outputs are not available. Mount the saved diagnostic checkpoint or set DIAGNOSTIC_DIRECTORY_OVERRIDE. Raw PCAPs will NOT be replayed to replace them.')

def load_source_models():
 diag=find_diagnostic();env=metadata(PARENT,'environment.json');binding=metadata(PARENT,'model_binding.json')
 if binding['model_sha256']!=EXPECTED:raise Stop('Model identities differ from the audited parent')
 if __import__('sklearn').__version__!=env['sklearn']:raise Stop('Runtime sklearn must match saved '+env['sklearn'])
 from sklearn.exceptions import InconsistentVersionWarning
 models={}
 for family in ['HGB','LR']:
  p=locate(PARENT,'fresh_'+family+'.joblib')
  if sha(p)!=EXPECTED[family]:raise Stop('Model hash mismatch: '+family)
  with warnings.catch_warnings():
   warnings.simplefilter('error',InconsistentVersionWarning);models[family]=joblib.load(p)
  if list(models[family].classes_)!=[0,1]:raise Stop('Unexpected class order')
  USED.append({'path':str(p),'role':'frozen_model','sha256':sha(p)})
 source=norm(csv_small(locate(PARENT,'fresh_source_panel.csv.gz')));source['y']=pd.to_numeric(source.y,errors='raise').astype(int)
 train=source[source.role.eq('train')];hold=source[source.role.eq('source_holdout')].reset_index(drop=True)
 if len(train)!=9660 or len(hold)!=2340 or set(train.group)&set(hold.group) or set(source.source_capture.astype(int))!={1,3,8}:raise Stop('Source split metadata does not reproduce')
 old=csv_small(locate(PARENT,'source_holdout_metrics.csv'));prob={};checks=[]
 with threadpool_limits(limits=2):
  for family,model in models.items():
   p=model.predict_proba(encode(hold))[:,1];m=metric(hold.y,p);prior=old[old.family.eq(family)]
   if len(prior)!=1:raise Stop('Saved source metric row not unique')
   okay=all(np.isclose(m[k],float(prior.iloc[0][k]),atol=1e-8,rtol=0) for k in ['accuracy','balanced_accuracy','AUROC','malicious_recall','benign_FPR'])
   if not okay:raise Stop('Saved source metrics do not reproduce; no threshold analysis interpreted')
   prob[family]=p;checks.append({'family':family,'source_reproduced':okay,**m})
 pd.DataFrame(checks).to_csv(OUT/'source_reproduction.csv',index=False)
 return diag,models,hold,prob

class HashSample:
 def __init__(self,n):self.n=n;self.heap=[];self.keys=set()
 def wants(self,key):return key in self.keys or len(self.heap)<self.n or int(key,16)<-self.heap[0][0]
 def add(self,key,row):
  if key in self.keys:return
  v=(-int(key,16),key,row)
  if len(self.heap)<self.n:heapq.heappush(self.heap,v);self.keys.add(key)
  elif int(key,16)<-self.heap[0][0]:
   _,old,_=heapq.heapreplace(self.heap,v);self.keys.remove(old);self.keys.add(key)
 def values(self,bad):return [v[2] for v in sorted(self.heap,key=lambda z:z[1]) if v[1] not in bad]

def make_control_panel(diag,capture):
 d=OUT/f'capture_{capture}';d.mkdir();dbpath=d/'temporary_candidate_index.sqlite';db=None
 result={'capture':capture,'status':'STARTED'}
 try:
  path=locate(diag/f'capture_{capture}',['extractor_inputs_delay0_timeout5.csv.gz','extractor_records_delay0_timeout5.csv.gz'])
  db=sqlite3.connect(dbpath);db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA cache_size=-32768')
  columns=['ks TEXT PRIMARY KEY','n INTEGER','proto TEXT','ts REAL']+[c+' REAL' for c in NUM]
  db.execute('CREATE TABLE pool('+','.join(columns)+')')
  insert='INSERT INTO pool VALUES('+','.join(['?']*(4+len(NUM)))+') ON CONFLICT(ks) DO UPDATE SET n=n+1'
  streamed=0;max_start=-np.inf;start=time.monotonic()
  with opened(path) as f:
   for chunk in pd.read_csv(f,chunksize=CFG['CSV_chunk_rows'],dtype={'ks':str},low_memory=False):
    if time.monotonic()-start>CFG['pool_build_time_limit_seconds']:raise Stop('Fixed candidate-index build time budget reached; no partial pool interpreted')
    if not set(F+['ks','ts']).issubset(chunk):raise Stop('Saved clean-record schema incomplete')
    chunk=norm(chunk);chunk['ts']=pd.to_numeric(chunk.ts,errors='raise').astype(float)
    if not np.isfinite(chunk.ts).all():raise Stop('Nonfinite record start time')
    streamed+=len(chunk);max_start=max(max_start,float(chunk.ts.max()))
    batch=[(key,1,proto,float(ts),*[float(x) for x in values]) for key,proto,ts,*values in chunk[['ks','proto','ts']+NUM].itertuples(index=False,name=None)]
    db.executemany(insert,batch);db.commit()
    print('CONTROL POOL',capture,'saved records indexed:',streamed,flush=True)
  # Conservative tail exclusion using latest observed compatible record start,
  # not an invented last-packet clock.
  end_cut=max_start-CFG['tail_seconds'];db.execute('DELETE FROM pool WHERE ts+duration>?',(end_cut,));db.commit()
  keys={x[0] for x in db.execute('SELECT ks FROM pool WHERE n=1')}
  if not keys:raise Stop('No unambiguous complete-before-tail records')
  token=f'CTU-IoT-Malware-Capture-{capture}-1';published=[p for p in RAW.rglob('conn.log.labeled') if token in p.parts]
  if len(published)!=1:raise Stop('Unique original labelled log not found for '+token)
  samplers={y:HashSample(CFG['rows_per_class_cap']) for y in [0,1]};encounters=Counter();bad=set();counts=Counter();scanned=0;finished=True;reason='FULL_LOG_EXHAUSTED';t0=time.monotonic()
  for r in logs(published[0],True):
   scanned+=1
   if scanned>CFG['published_log_row_limit']:finished=False;reason='FIXED_ROW_LIMIT';break
   if scanned%250000==0:
    print('LABEL MATCH',capture,'rows',scanned,'retained benign',len(samplers[0].heap),'malicious',len(samplers[1].heap),flush=True)
   if scanned%1000==0 and time.monotonic()-t0>CFG['published_log_time_limit_seconds']:finished=False;reason='FIXED_TIME_LIMIT';break
   lab=r['label'].lower()
   if lab not in ['benign','malicious']:continue
   try:k=record_key(r)
   except (ValueError,KeyError):continue
   if k not in keys:continue
   y=int(lab=='malicious');counts['candidate_label_'+str(y)]+=1
   if not samplers[y].wants(k) and k not in encounters:continue
   hit=db.execute('SELECT n,proto,ts,'+','.join(NUM)+' FROM pool WHERE ks=?',(k,)).fetchone()
   if hit is None or hit[0]!=1:continue
   try:values=features(r)
   except (ValueError,KeyError):continue
   if values['proto']!=hit[1] or not np.allclose([values[c] for c in NUM],hit[3:],atol=1e-9,rtol=1e-9):counts['stable_feature_mismatch']+=1;continue
   encounters[k]+=1
   if encounters[k]>1:bad.add(k);continue
   row={c:float(hit[j+3]) for j,c in enumerate(NUM)};row.update({'proto':hit[1],'ts':float(hit[2]),'ks':k,'y':y,'capture':capture})
   try:
    endpoints=sorted([(r['id.orig_h'],int(r['id.orig_p'])),(r['id.resp_h'],int(r['id.resp_p']))])
    row['network_group']=hashlib.sha256(json.dumps([capture,endpoints,r['proto'].lower()],separators=(',',':')).encode()).hexdigest()
   except (ValueError,KeyError):raise Stop('Original network metadata cannot be parsed')
   # Documentary context only; NOT model predictors or routing variables.
   row['published_service']=r.get('service','');row['published_conn_state']=r.get('conn_state','');row['published_resp_port']=r.get('id.resp_p','')
   samplers[y].add(k,row)
  rows=samplers[0].values(bad)+samplers[1].values(bad)
  panel=pd.DataFrame(rows)
  if panel.empty:raise Stop('No stable-linked controls retained')
  if panel.ks.duplicated().any():raise Stop('Conflicting labels/keys in new control panel')
  panel.to_csv(d/'NEW_clean_control_panel.csv.gz',index=False,compression='gzip')
  benign=int(panel.y.eq(0).sum());malicious=int(panel.y.eq(1).sum())
  result.update({'status':'CONTROL_PANEL_COMPUTED','saved_clean_rows_streamed':streamed,
   'candidate_keys_after_tail_filter':len(keys),'published_rows_scanned':min(scanned,CFG['published_log_row_limit']),
   'full_published_log_exhausted':finished,'declared_label_scan_completed':reason!='FIXED_TIME_LIMIT','scan_stop_reason':reason,'published_scan_seconds':time.monotonic()-t0,
   'benign_rows':benign,'malicious_rows':malicious,'published_duplicate_keys_removed':len(bad),
   'benign_control_informative_by_predeclared_minimum':benign>=CFG['minimum_benign_for_informative_control'],
   'benign_network_groups':int(panel.loc[panel.y.eq(0),'network_group'].nunique()),
   'malicious_network_groups':int(panel.loc[panel.y.eq(1),'network_group'].nunique()),
   'counts':dict(counts),'scope':'new stratified exposed-data clean control panel; same saved 64-MiB prefix; not natural-prevalence estimates or independent-corpus confirmation'})
  USED.append({'path':str(path),'role':'streamed_saved_clean_records','rows':streamed})
  USED.append({'path':str(published[0]),'role':'published_label_log','rows_scanned':result['published_rows_scanned']})
  return panel,result
 except Exception as e:
  result.update({'status':'CONTROL_PANEL_FAILED','reason':str(e)});(d/'error.txt').write_text(traceback.format_exc());print('CONTROL',capture,'FAILED:',e,flush=True)
  return None,result
 finally:
  if db is not None:db.close()
  if dbpath.is_file():dbpath.unlink() # only this invocation's temporary lookup index
  js(d/'control_panel_receipt.json',result);gc.collect()

def source_operating_points(hold,prob):
 thresholds=[];ties=[]
 y=hold.y.to_numpy(int)
 for family,p in prob.items():
  thresholds.append({'family':family,'name':'PARENT_0_5','threshold':.5,'strict':False,'alpha':np.nan})
  negative=p[y==0]
  for alpha in CFG['source_FPR_levels']:
   t,budget=cutoff(negative,alpha);fpr=float((negative>t).mean())
   if fpr>alpha+1e-12:raise Stop('Source cutoff exceeded FPR budget')
   name=f'SOURCE_FPR_{int(alpha*100)}PCT'
   thresholds.append({'family':family,'name':name,'threshold':t,'strict':True,'alpha':alpha})
   for label in [0,1]:
    values=p[y==label]
    ties.append({'family':family,'operating_point':name,'source_label':label,'rows':len(values),'threshold':t,
     'below_cutoff':int((values<t).sum()),'at_cutoff':int((values==t).sum()),'above_cutoff':int((values>t).sum()),
     'allowed_source_benign_FP':budget,'actual_source_benign_FP':int((negative>t).sum()),
     'note':'strict >; mass at cutoff is excluded; no random tie reassignment'})
 pd.DataFrame(thresholds).to_csv(OUT/'FIXED_SOURCE_THRESHOLDS.csv',index=False)
 pd.DataFrame(ties).to_csv(OUT/'EXPERIMENT1_SOURCE_SCORE_TIES.csv',index=False)
 print('\nEXPERIMENT 1 — SOURCE SCORE TIES\n'+pd.DataFrame(ties).to_string(index=False),flush=True)
 return thresholds

def evaluate_controls(models,hold,source_prob,panels,thresholds):
 rows=[];target_prob={}
 with threadpool_limits(limits=2):
  for capture,panel in panels.items():
   target_prob[capture]={}
   for family,model in models.items():
    p=model.predict_proba(encode(panel))[:,1];target_prob[capture][family]=p
    pd.DataFrame({'ks':panel.ks,'y':panel.y,'probability':p,'prediction_0_5':p>=.5}).to_csv(OUT/f'capture_{capture}'/('frozen_probabilities_'+family+'.csv'),index=False)
  for t in thresholds:
   family=t['family'];rows.append({'domain':'source_reference','family':family,'operating_point':t['name'],**metric(hold.y,source_prob[family],t['threshold'],t['strict'])})
   for capture,panel in panels.items():
    m=metric(panel.y,target_prob[capture][family],t['threshold'],t['strict'])
    rows.append({'domain':'capture_'+str(capture)+'_NEW_clean_control','family':family,'operating_point':t['name'],
     'benign_control_minimum_met':m['benign_rows']>=CFG['minimum_benign_for_informative_control'],**m})
 result=pd.DataFrame(rows);result.to_csv(OUT/'EXPERIMENT2_BENIGN_AND_RECALL_CONTROL.csv',index=False)
 print('\nEXPERIMENT 2 — BENIGN CONTROL AND RECALL\n'+result.to_string(index=False),flush=True)
 return target_prob

def paired_start_response(diag,models,panels,target_prob,thresholds):
 # This is a fixed association-rule diagnostic, not label assignment to mixed records.
 capture=49
 if capture not in panels:return
 panel=panels[capture];wanted=set(panel.ks)
 path=locate(diag/'capture_49',['extractor_inputs_delay10_timeout5.csv.gz','extractor_records_delay10_timeout5.csv.gz'])
 kept=[];scanned=0
 with opened(path) as f:
  for chunk in pd.read_csv(f,chunksize=CFG['CSV_chunk_rows'],dtype={'ks':str},low_memory=False):
   scanned+=len(chunk)
   if not set(F+['ks']).issubset(chunk):raise Stop('Stressed extracted-record schema mismatch')
   part=chunk[chunk.ks.isin(wanted)]
   if len(part):kept.append(part.copy())
 frame=pd.concat(kept,ignore_index=True) if kept else pd.DataFrame(columns=F+['ks'])
 bad=set(frame.loc[frame.ks.duplicated(keep=False),'ks']);frame=norm(frame[~frame.ks.isin(bad)])
 common=sorted(wanted&set(frame.ks));js(OUT/'capture49_stress_start_key_coverage.json',{
  'wanted_clean_keys':len(wanted),'uniquely_matched':len(common),'ambiguous_keys':len(bad),
  'missing_or_ambiguous':len(wanted-set(common)),'stressed_rows_streamed':scanned})
 if not common:
  js(OUT/'capture49_stress_start_key_status.json',{'status':'NO_UNAMBIGUOUS_START_MATCHES','synthetic_rows_created':False});return
 clean=panel.set_index('ks').loc[common];stressed=frame.set_index('ks').loc[common];rows=[]
 with threadpool_limits(limits=2):
  for family,model in models.items():
   p0=model.predict_proba(encode(clean))[:,1];p1=model.predict_proba(encode(stressed))[:,1]
   pd.DataFrame({'ks':common,'reference_unit_label':clean.y.to_numpy(),'clean_probability':p0,'stress_start_probability':p1}).to_csv(OUT/('capture49_start_response_scores_'+family+'.csv'),index=False)
   for t in [x for x in thresholds if x['family']==family]:
    a=p0>t['threshold'] if t['strict'] else p0>=t['threshold']
    b=p1>t['threshold'] if t['strict'] else p1>=t['threshold'];mal=clean.y.to_numpy()==1;ben=~mal
    rows.append({'family':family,'operating_point':t['name'],'matched_start_keys':len(common),
     'reference_malicious_keys':int(mal.sum()),'reference_benign_keys':int(ben.sum()),
     'positive_to_negative_start_responses':int((a&~b).sum()),'negative_to_positive_start_responses':int((~a&b).sum()),
     'malicious_reference_keys_with_clean_positive_start':int((a&mal).sum()),
     'malicious_reference_keys_with_stress_positive_start':int((b&mal).sum()),
     'benign_reference_keys_with_stress_positive_start':int((b&ben).sum()),
     'scope':'original-start-key response diagnostic only; NOT pure-attributed original-unit recall or automatic transformed-record labels'})
 result=pd.DataFrame(rows);result.to_csv(OUT/'EXPERIMENT2_FIXED_CUTOFF_START_RESPONSE.csv',index=False)
 print('\nFIXED SOURCE CUTOFFS — CAPTURE49 START-KEY RESPONSE (NOT UNIT RECALL)\n'+result.to_string(index=False),flush=True)

def source_group_sensitivity(hold,source_prob,panels,target_prob):
 negative=hold[hold.y.eq(0)].copy();groups=negative.group.astype(str).to_numpy();unique=np.unique(groups)
 if len(unique)<2:raise Stop('Too few benign source groups for the declared sensitivity analysis')
 positions={g:np.where(groups==g)[0] for g in unique};rng=np.random.default_rng(CFG['resampling_seed']);rows=[]
 for rep in range(CFG['source_group_resamples']):
  sampled=rng.choice(unique,size=len(unique),replace=True);idx=np.concatenate([positions[g] for g in sampled])
  for family,pall in source_prob.items():
   pneg=pall[hold.y.to_numpy()==0];p=pneg[idx]
   for alpha in CFG['source_FPR_levels']:
    t,budget=cutoff(p,alpha)
    for capture,panel in panels.items():
     m=metric(panel.y,target_prob[capture][family],t,True)
     rows.append({'repetition':rep,'family':family,'alpha':alpha,'capture':capture,'source_benign_group_count':len(unique),
      'resampled_benign_rows':len(idx),'threshold':t,'resampled_source_FPR':float((p>t).mean()),
      'target_benign_rows':m['benign_rows'],'target_FPR':m['benign_FPR'],'target_malicious_recall':m['malicious_recall']})
 frame=pd.DataFrame(rows);frame.to_csv(OUT/'EXPERIMENT3_ALL_SOURCE_GROUP_RESAMPLES.csv',index=False)
 summaries=[]
 for key,g in frame.groupby(['capture','family','alpha'],sort=True):
  capture,family,alpha=key
  summaries.append({'capture':capture,'family':family,'alpha':alpha,'resamples':len(g),
   'threshold_min':g.threshold.min(),'threshold_median':g.threshold.median(),'threshold_max':g.threshold.max(),
   'target_FPR_min':g.target_FPR.min(),'target_FPR_median':g.target_FPR.median(),'target_FPR_max':g.target_FPR.max(),
   'target_recall_min':g.target_malicious_recall.min(),'target_recall_median':g.target_malicious_recall.median(),'target_recall_max':g.target_malicious_recall.max(),
   'scope':'conditional sensitivity to observed source-network groups, not an independent-data confidence interval or a target-tuning procedure'})
 summary=pd.DataFrame(summaries);summary.to_csv(OUT/'EXPERIMENT3_SOURCE_GROUP_SENSITIVITY.csv',index=False)
 print('\nEXPERIMENT 3 — SOURCE GROUP SENSITIVITY\n'+summary.to_string(index=False),flush=True)


def save_checkpoint():
 p=OUT/'PRIVATE_benign_operating_point_results.zip';tmp=OUT/'checkpoint.tmp'
 with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
  for q in sorted(OUT.rglob('*')):
   if q.is_file() and q not in [p,tmp] and q.suffix not in ['.zip','.sqlite']:z.write(q,str(q.relative_to(OUT)))
 with zipfile.ZipFile(tmp) as z:
  if z.testzip():raise Stop('ZIP CRC failed')
 tmp.replace(p);return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}

def main():
 if not RAW.is_dir():raise Stop('Original IoT-23 mount required for PUBLISHED LABEL LOGS ONLY; no PCAP read is planned')
 if shutil.disk_usage(W).free<2*1024**3:raise Stop('At least 2 GiB free required for bounded temporary record indexing')
 js(OUT/'PROTOCOL_BEFORE_NEW_TARGET_PANEL_SCORING.json',{'config':CFG,'fixed_models':EXPECTED,
  'new_target_panels':'same existing clean prefixes, strict stable-core label linkage, lowest key hash within benign/malicious classes before prediction',
  'not_the_old_hash_mixed_panel':True,'no_target_based_cutoff_or_model_selection':True,
  'tail_exclusion':'latest saved compatible record start minus 120s, conservative finite-prefix control',
  'label_scan':'fixed row/time limits; all stops and missing controls reported, no automatic budget expansion',
  'source_score_ties':'strict conservative source FPR cutoffs; ties excluded; no retrospective randomized rescue',
  'resampling':'observed benign source-network-group sensitivity, not independence-certified inference',
  'scope':'post-exposure clean control experiment, no mitigation or universal robustness claim',
  'changed_model_weights':False,'new_replays':0,'application_functionality_tested':False})
 diag,models,hold,prob=load_source_models();thresholds=source_operating_points(hold,prob);panels={};statuses=[]
 for capture in CFG['captures']:
  panel,status=make_control_panel(diag,capture);statuses.append(status)
  if panel is not None and status['status']=='CONTROL_PANEL_COMPUTED':panels[capture]=panel
  js(OUT/'control_progress.json',statuses);js(OUT/'input_manifest.json',USED);save_checkpoint()
 if not panels:raise Stop('No clean control panels constructed. Exact reasons retained; no model conclusions produced.')
 target_prob=evaluate_controls(models,hold,prob,panels,thresholds)
 paired_start_response(diag,models,panels,target_prob,thresholds)
 source_group_sensitivity(hold,prob,panels,target_prob)
 enough=all(s['status']=='CONTROL_PANEL_COMPUTED' and s.get('benign_control_informative_by_predeclared_minimum',False) and s.get('declared_label_scan_completed',False) for s in statuses)
 R.update({'status':'BENIGN_AND_OPERATING_POINT_ANALYSIS_COMPLETE' if enough else 'ANALYSIS_COMPLETE_WITH_INSUFFICIENT_CONTROL_COVERAGE',
  'control_panels':statuses,'minimum_benign_count_met_for_both_targets':enough,
  'fresh_target_thresholds_chosen':False,'source_thresholds_derived':True,
  'conditional_source_group_sensitivity_only':True,'new_defense_validated':False,
  'limits':['Class-stratified key-ranked diagnostic panels are not natural traffic prevalence estimates.',
   '100 benign rows is a predeclared feasibility minimum, not proof of independent deployment evidence.',
   'Published labels and exact stable-core links do not certify malicious application functionality.',
   'Source holdout remains previously exposed and reused for diagnostic thresholds.',
   'No target-winner threshold is selected from these results.']})
 print('\nCONTROL PANEL STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)

try:
 source=globals().get('__file__')
 if source and Path(source).is_file():shutil.copyfile(source,OUT/'executed_analysis.py')
 main()
except Exception as ex:
 R.update({'status':'STOPPED_WITH_EXACT_REASON','reason':str(ex)});(OUT/'error.txt').write_text(traceback.format_exc());print('\nSTOPPED:',ex,flush=True)
finally:
 js(OUT/'input_manifest.json',USED);js(OUT/'receipt.json',R)
 try:
  cp=save_checkpoint();R['checkpoint']=cp;js(OUT/'receipt.json',R);print('\nPRIVATE CHECKPOINT:',cp['path'],flush=True)
 except Exception as ex:print('Checkpoint issue:',ex,flush=True)
 print('\nBENIGN-CONTROL RECEIPT\n'+json.dumps(R,indent=2),flush=True)
