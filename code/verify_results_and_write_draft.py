# Final verification and paper-results export. No fitting, inference or replay.
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,math,os,sys,traceback,zipfile
import numpy as np
import pandas as pd
from sklearn.metrics import balanced_accuracy_score,roc_auc_score

W=Path('/kaggle/working');B=Path('/kaggle/input/datasets/mdhamidborkottulla/full-working-backup')
INPUT_DIRECTORY_OVERRIDE=None
OUTPUT=W/'VERIFIED_PAPER_RESULTS_V1';OUTPUT.mkdir(parents=True,exist_ok=True)
EXPECTED={
 'CICIoT2023':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88',
 'CICIoMT2024':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473',
 'CSE':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3',
 'NSL':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29',
 'TONIoT':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf'}
class Stop(Exception):pass

def js(path,obj):
 path=Path(path);temp=path.with_name(path.name+'.tmp');temp.write_text(json.dumps(obj,indent=2,default=str),encoding='utf-8');temp.replace(path)
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def read_csv(path):return pd.read_csv(path,float_precision='round_trip',dtype={'row_id':str})
def truth_bool(x):
 if x in [True,1,'1','True','true']:return True
 if x in [False,0,'0','False','false']:return False
 raise Stop('Invalid saved Boolean '+repr(x))
def close(a,b):
 if pd.isna(a) and pd.isna(b):return True
 return bool(np.isclose(float(a),float(b),atol=1e-9,rtol=0))

def find_inputs():
 candidates=([Path(INPUT_DIRECTORY_OVERRIDE)] if INPUT_DIRECTORY_OVERRIDE else [])+[W/'FIVE_DATASET_FIXED_OP_V1',B/'kaggle_working'/'FIVE_DATASET_FIXED_OP_V1',B/'FIVE_DATASET_FIXED_OP_V1',B/'PRIVATE_five_dataset_fixed_op_checkpoint']
 for root in candidates:
  p=root/'receipt.json'
  if not p.is_file():continue
  r=json.loads(p.read_text())
  if r.get('status')=='FIVE_DATASET_EXTENSION_COMPLETE' and r.get('datasets_complete')==5:return root,r
 raise Stop('Completed FIVE_DATASET_FIXED_OP_V1 outputs must be available in working or mounted from its saved checkpoint. No experiment will be rerun to recreate them.')

def validate_job(root,entry):
 name=Path(entry['job_directory']).name
 candidates=[root/name,root/'PRIVATE_five_dataset_fixed_op_checkpoint'/name]
 job=next((p for p in candidates if (p/'receipt.json').is_file()),None)
 if job is None:raise Stop('Missing completed dataset directory '+name)
 r=json.loads((job/'receipt.json').read_text());dataset=entry['dataset']
 if r.get('status')!='DATASET_EXTENSION_COMPLETE' or r.get('experiment_signature')!=entry['signature'] or r.get('canonical_bundle_sha256')!=EXPECTED[dataset]:raise Stop('Dataset identity mismatch: '+dataset)
 hashes=r.get('artifact_sha256',{})
 if not hashes:raise Stop('Dataset artifact hash manifest absent')
 for filename,h in hashes.items():
  path=job/filename
  if not path.is_file() or sha(path)!=h:raise Stop('Changed/missing completed artifact: '+str(path))
 return job,r

def actual_metrics(y,p,cut,strict):
 y=np.asarray(y,int);p=np.asarray(p,float);d=p>cut if strict else p>=cut;neg=y==0;pos=y==1
 return {'records':len(y),'benign':int(neg.sum()),'malicious':int(pos.sum()),'FP':int((d&neg).sum()),'FN':int((~d&pos).sum()),
 'accuracy':float((d==y).mean()),'balanced_accuracy':float(balanced_accuracy_score(y,d)) if neg.any() and pos.any() else np.nan,
 'AUROC':float(roc_auc_score(y,p)) if neg.any() and pos.any() else np.nan,
 'recall':float(d[pos].mean()) if pos.any() else np.nan,'FPR':float(d[neg].mean()) if neg.any() else np.nan}

def monitor_fit(y,p):
 confidence=np.maximum(p,1-p);acc=float(((p>=.5)==y).mean());correct=int(((p>=.5)==y).sum())
 if correct==0:t=float(np.nextafter(confidence.max(),np.inf));fraction=0.
 else:
  t=float(np.sort(confidence)[::-1][correct-1]);fraction=(correct-int((confidence>t).sum()))/int((confidence==t).sum())
 source_est={'AC':float(confidence.mean()),'DoC':acc,'ATC_FRACTIONAL_TIE':float(((confidence>t)+fraction*(confidence==t)).mean())}
 if not np.isclose(source_est['ATC_FRACTIONAL_TIE'],acc,atol=1e-12):raise Stop('ATC source coverage does not reconstruct')
 return {'accuracy':acc,'confidence':float(confidence.mean()),'cutoff':t,'fraction':fraction,'source_estimates':source_est}

def estimate_target(p,fit):
 # Intentionally no target labels are accepted by this function.
 confidence=np.maximum(p,1-p)
 return {'AC':float(confidence.mean()),'DoC':float(np.clip(fit['accuracy']+confidence.mean()-fit['confidence'],0,1)),
 'ATC_FRACTIONAL_TIE':float(((confidence>fit['cutoff'])+fit['fraction']*(confidence==fit['cutoff'])).mean())}

def reconstruct(job,dataset):
 pred=read_csv(job/'fixed_model_predictions.csv')
 if set(pred.dataset)!={dataset} or not pred.label.isin([0,1]).all() or pred.duplicated(['domain','row_id']).any():raise Stop('Invalid saved prediction identities/labels')
 p=pred.probability.to_numpy(float)
 if not np.isfinite(p).all() or ((p<0)|(p>1)).any():raise Stop('Invalid saved probabilities')
 groups={name:g for name,g in pred.groupby('domain',sort=True)}
 if 'source_reference' not in groups or 'source_calibration' not in groups:raise Stop('Saved source prediction roles absent')
 settings=read_csv(job/'operating_points.csv');old_metrics=read_csv(job/'EXPERIMENT1_threshold_transfer.csv');checks=[];metric_rows=[]
 for _,s in settings.iterrows():
  name=s['name'];cut=float(s['cut']);strict=truth_bool(s['strict'])
  for domain,g in groups.items():
   m=actual_metrics(g.label.to_numpy(int),g.probability.to_numpy(float),cut,strict)
   old=old_metrics[old_metrics.domain.eq(domain)&old_metrics.operating_point.eq(name)]
   if len(old)!=1:raise Stop('Metric row missing or duplicated')
   ok=all(close(v,old.iloc[0][k]) for k,v in m.items())
   checks.append({'dataset':dataset,'kind':'actual_metric_row','domain':domain,'method':name,'reproduced':ok})
   if not ok:raise Stop('Actual metric fails reconstruction: '+dataset+'/'+domain+'/'+name)
   metric_rows.append({'dataset':dataset,'domain':domain,'operating_point':name,**m})
 ref=groups['source_reference'];fit=monitor_fit(ref.label.to_numpy(int),ref.probability.to_numpy(float))
 old_monitors=read_csv(job/'EXPERIMENT3_unlabeled_point_monitors.csv');monitor_rows=[]
 for domain,g in groups.items():
  if not domain.startswith('target::'):continue
  p=g.probability.to_numpy(float);y=g.label.to_numpy(int);actual=float(((p>=.5)==y).mean());estimates=estimate_target(p,fit)
  for method,estimate in estimates.items():
   source_est=fit['source_estimates'][method];drop=fit['accuracy']-actual;estdrop=source_est-estimate
   row={'dataset':dataset,'domain':domain,'estimator':method,'operating_point':'RAW_0_5_ONLY','records':len(g),
    'source_true_accuracy':fit['accuracy'],'target_true_accuracy':actual,'estimated_accuracy':estimate,
    'absolute_error':abs(estimate-actual),'overestimation':estimate-actual,'actual_accuracy_drop':drop,'estimated_accuracy_drop':estdrop,
    'differential_error':abs((estimate-actual)-(source_est-fit['accuracy'])),
    'warning_at_5pp':estdrop>=.05,'actual_drop_at_least_5pp':drop>=.05}
   old=old_monitors[old_monitors.domain.eq(domain)&old_monitors.estimator.eq(method)]
   if len(old)!=1:raise Stop('Monitor row missing or duplicated')
   numeric=[k for k in row if k not in {'dataset','domain','estimator','operating_point','warning_at_5pp','actual_drop_at_least_5pp'}]
   okay=all(close(row[k],old.iloc[0][k]) for k in numeric) and truth_bool(old.iloc[0].warning_at_5pp)==row['warning_at_5pp'] and truth_bool(old.iloc[0].actual_drop_at_least_5pp)==row['actual_drop_at_least_5pp']
   checks.append({'dataset':dataset,'kind':'estimated_metric_row','domain':domain,'method':method,'reproduced':okay})
   if not okay:raise Stop('Monitor estimate fails reconstruction: '+dataset+'/'+domain+'/'+method)
   monitor_rows.append(row)
 # Determine repeated operating points from observed decisions, not table row count.
 aliases=[]
 for _,setting in settings.iterrows():
  decisions=[]
  for domain in sorted(groups):
   p=groups[domain].probability.to_numpy(float)
   d=p>float(setting['cut']) if truth_bool(setting['strict']) else p>=float(setting['cut']);decisions.append(d.astype('uint8').tobytes())
  h=hashlib.sha256(b''.join(decisions)).hexdigest()
  aliases.append({'dataset':dataset,'operating_point':setting['name'],'threshold':float(setting['cut']),
   'comparison':'>' if truth_bool(setting['strict']) else '>=','observed_decision_signature':h,
   'scope':'identical signatures mean identical decisions on these stored populations, not new replication'})
 return metric_rows,monitor_rows,checks,aliases

def md_table(df,columns):
 def cell(x):
  if pd.isna(x):return 'NA'
  if isinstance(x,(float,np.floating)):return f'{float(x):.3f}'
  return str(x).replace('|','\\|').replace('\n',' ')
 lines=['| '+' | '.join(columns)+' |','| '+' | '.join(['---']*len(columns))+' |']
 lines.extend('| '+' | '.join(cell(v) for v in row)+' |' for row in df[columns].itertuples(index=False,name=None))
 return '\n'.join(lines)


def export_tables(out,metrics,monitors,aliases,checks,provenance):
 m=pd.DataFrame(metrics);m.to_csv(out/'RECONSTRUCTED_actual_metrics.csv',index=False)
 e=pd.DataFrame(monitors);e.to_csv(out/'RECONSTRUCTED_monitor_estimates.csv',index=False)
 pd.DataFrame(checks).to_csv(out/'REPRODUCTION_CHECKS.csv',index=False);pd.DataFrame(aliases).to_csv(out/'OPERATING_POINT_DECISION_ALIASES.csv',index=False)
 target=m[m.domain.str.startswith('target::')].copy();source5=target[target.operating_point.eq('SOURCE_FPR_5PCT')].copy()
 table1=source5[['dataset','domain','records','benign','malicious','FP','FN','AUROC','recall','FPR']].copy()
 table1['recall_percent']=100*table1.recall;table1['FPR_percent']=100*table1.FPR
 table1.to_csv(out/'TABLE1_source5_target_detection.csv',index=False)
 table2=e.copy()
 for c in ['target_true_accuracy','estimated_accuracy','absolute_error','actual_accuracy_drop','estimated_accuracy_drop','differential_error']:table2[c+'_pp']=100*table2[c]
 table2.to_csv(out/'TABLE2_observed_versus_estimated_accuracy.csv',index=False)
 warning=[]
 for method,g in e.groupby('estimator',sort=True):
  harmful=g.actual_drop_at_least_5pp.to_numpy(bool);alarm=g.warning_at_5pp.to_numpy(bool);negative=~harmful
  tp=int((harmful&alarm).sum());fn=int((harmful&~alarm).sum());fp=int((negative&alarm).sum());tn=int((negative&~alarm).sum())
  warning.append({'estimator':method,'domains':len(g),'degraded_domains':int(harmful.sum()),'nondegraded_domains':int(negative.sum()),
   'TP_domains':tp,'FN_domains':fn,'FP_domains':fp,'TN_domains':tn,
   'descriptive_warning_rate_on_degraded':tp/(tp+fn) if tp+fn else np.nan,
   'false_warning_rate':fp/(fp+tn) if fp+tn else np.nan,
   'negative_control_FPR_established':bool(fp+tn),
   'predicted_improvement_despite_actual_drop_domains':int((g.estimated_accuracy_drop.lt(0)&g.actual_drop_at_least_5pp).sum()),
   'scope':'whole-domain descriptive counts, not independent replications or deployment detection probabilities'})
 w=pd.DataFrame(warning);w.to_csv(out/'TABLE3_domain_warning_counts.csv',index=False)
 per=e.groupby(['dataset','estimator'],as_index=False).agg(target_domains=('domain','size'),mean_absolute_error=('absolute_error','mean'),
  mean_differential_error=('differential_error','mean'),warnings=('warning_at_5pp','sum'),degraded_domains=('actual_drop_at_least_5pp','sum'))
 per.to_csv(out/'TABLE4_equal_dataset_summary_inputs.csv',index=False)
 per.groupby('estimator',as_index=False).agg(equal_dataset_mean_absolute_error=('mean_absolute_error','mean'),equal_dataset_mean_differential_error=('mean_differential_error','mean')).to_csv(out/'TABLE4_equal_dataset_macro_errors.csv',index=False)
 violations=[]
 for point,alpha in [('SOURCE_FPR_1PCT',.01),('SOURCE_FPR_5PCT',.05)]:
  g=target[target.operating_point.eq(point)]
  violations.append({'operating_point':point,'domains':len(g),'target_FPR_above_nominal_source_level':int(g.FPR.gt(alpha).sum()),
   'note':'source constraint is not a promised target guarantee; not a theorem violation'})
 pd.DataFrame(violations).to_csv(out/'TABLE5_FPR_transfer_counts.csv',index=False)
 overview=target[target.operating_point.eq('RAW_0_5')].groupby('dataset',as_index=False).agg(target_domains=('domain','size'),evaluated_record_appearances=('records','sum'),benign_record_appearances=('benign','sum'),malicious_record_appearances=('malicious','sum'))
 overview.to_csv(out/'TABLE0_dataset_coverage.csv',index=False)
 totals={'datasets':int(overview.dataset.nunique()),'target_domains':int(overview.target_domains.sum()),'target_record_appearances':int(overview.evaluated_record_appearances.sum()),
  'all_degraded_target_domains_at_raw0_5':bool(e.actual_drop_at_least_5pp.all()),'source5_target_FPR_above_5_percent':int(source5.FPR.gt(.05).sum()),
  'source5_domains_with_AUROC_below_half':int(source5.AUROC.lt(.5).sum()),'verified_actual_metric_rows':len(m),'verified_monitor_rows':len(e)}
 js(out/'COMPUTED_FINDINGS.json',totals)
 glossary=r"""# Actual versus estimated accuracy

Observed accuracy = number of predictions matching saved benchmark labels / number of records.
It is a measured evaluation result against these annotations, not proof of real-world application security.

Estimated accuracy is a number output by a label-free monitor. It is computed, not fabricated,
not copied from another paper, and not a replacement for the observed accuracy.

AC = average max(p, 1-p) for the conventional raw-0.5 classifier.
DoC = clip(source observed accuracy + target mean confidence - source mean confidence, 0, 1).
ATC fractional tie = fraction of target confidence scores above a source-fitted cutoff,
plus the predeclared fraction of scores tied at that cutoff. Its cutoff/fraction are fitted
using source confidence and source correctness, not target correctness.

Target labels enter actual-accuracy/error evaluation only. The estimate_target() function
in this verifier does not accept target labels.

A reported estimate of 1.0 from a clipped formula is not a certificate of 100% accuracy.
A low final point-estimation error is not automatically a good change estimate or warning.
These monitors concern RECORD ACCURACY at raw 0.5, not original-unit malicious recall.
"""
 (out/'ACTUAL_VS_ESTIMATED.md').write_text(glossary)
 draft='# Results draft: verified five-dataset operating-point extension\n\n'
 draft+='This section reports exposed-data evaluation, not prospective independent confirmation or validation of a new robust monitor. All figures below are reconstructed from saved probabilities and benchmark labels; no classifier was fitted or rerun.\n\n'
 draft+='## Evaluation coverage\n\n'+md_table(overview,list(overview.columns))+'\n\n'
 draft+=f'The extension covers {totals["datasets"]} datasets and {totals["target_domains"]} target domains, with {totals["target_record_appearances"]:,} evaluated record appearances. These are not certified independent physical traffic units. Multiple operating points reuse the same records. CSE contributes nine target domains; equal-dataset summaries are reported separately to avoid silently weighting it nine times more than one-domain datasets.\n\n'
 draft+='## Source-defined operating points\n\n'
 draft+=md_table(table1,['dataset','domain','records','benign','malicious','AUROC','recall_percent','FPR_percent'])+'\n\n'
 draft+=f'The source-5% setting produced target FPR above 5% in {totals["source5_target_FPR_above_5_percent"]}/{totals["target_domains"]} domains. This demonstrates limited transfer of the source operating constraint; it does not refute a nonexistent distribution-free target guarantee.\n\n'
 draft+=f'At that setting, {totals["source5_domains_with_AUROC_below_half"]} target domains have observed AUROC below 0.5. Other domains retain strong ranking while achieving low recall at source-defined cutoffs. Accordingly, not all failures should be diagnosed as the same calibration or ranking problem. These are descriptive distinctions, not causal identifications.\n\n'
 draft+='The recorded threshold and source-5% threshold may be identical. OPERATING_POINT_DECISION_ALIASES.csv identifies duplicate observed decisions; duplicated rows are not extra experiments.\n\n'
 draft+='## Observed versus estimated performance\n\n'
 paper=e[['dataset','domain','estimator','target_true_accuracy','estimated_accuracy','absolute_error','actual_accuracy_drop','estimated_accuracy_drop']].copy()
 for c in ['target_true_accuracy','estimated_accuracy','absolute_error','actual_accuracy_drop','estimated_accuracy_drop']:paper[c]=100*paper[c]
 draft+='All numbers in the following table are percentages or percentage-point differences as appropriate. Observed accuracy uses benchmark labels; estimated accuracy uses the monitor formula.\n\n'+md_table(paper,list(paper.columns))+'\n\n'
 draft+='## Whole-domain warning behavior\n\n'+md_table(w,['estimator','domains','degraded_domains','nondegraded_domains','TP_domains','FN_domains','FP_domains','TN_domains'])+'\n\n'
 draft+='Warning decisions use a fixed estimated drop of at least five percentage points, not a threshold calibrated to 5% warning FPR. '
 if totals['all_degraded_target_domains_at_raw0_5']:draft+='Every evaluated target domain exceeds that observed-drop threshold. There are therefore no non-degraded target controls in this extension; target warning specificity, false-warning rate and a two-class damage-detection AUROC cannot be established from this target table alone. '
 draft+='Source self-fit results or identical-copy nulls must not be manufactured as independent negative controls. Domain counts are descriptive because domains may share sources and development exposure.\n\n'
 draft+='## Scope and limitations\n\n- Monitor results use raw-0.5 classification only, not the recorded/source-5% task.\n- Targets are natural-shift stored benchmark domains, not newly executed adversarial attacks.\n- Source row IDs do not certify device/capture independence.\n- Calibration resamples in the preceding extension are conditional row sensitivity, not independent-data confidence intervals.\n- The raw IoT-23 packet-accounting study is separate; its traffic-unit outcomes must not be replaced by these record metrics.\n- The failed 5s/15s remeasurement checker remains negative.\n- These results do not by themselves establish a new successful monitoring method or first-ever contribution.\n\n'
 draft+='## Claims suitable for the tested evidence\n\n- The evaluated source-defined operating points transfer differently across domains.\n- Strong observed ranking need not imply high recall at a source-defined cutoff.\n- Several evaluated label-free estimates substantially overstate record accuracy and understate observed degradation.\n- Correctness of the numerical reconstruction is distinct from the validity of an estimator assumption or the novelty of a research contribution.\n'
 (out/'RESULTS_SECTION_DRAFT.md').write_text(draft,encoding='utf-8')
 js(out/'input_provenance.json',provenance)
 return totals


def main():
 root,parent=find_inputs();entries=parent['datasets']
 if len(entries)!=5 or {x['dataset'] for x in entries}!=set(EXPECTED):raise Stop('Five-dataset roster does not match accepted module')
 jobs=[];provenance=[]
 for entry in entries:
  job,r=validate_job(root,entry);jobs.append((entry['dataset'],job));provenance.append({'dataset':entry['dataset'],'job':str(job),'signature':entry['signature'],'receipt_sha256':sha(job/'receipt.json'),'artifacts':r['artifact_sha256']})
 source=globals().get('__file__');code_hash=sha(source) if source and Path(source).is_file() else digest({'version':'verified-paper-results-v1'})
 identity=digest({'inputs':provenance,'code_sha256':code_hash,'numpy':np.__version__,'pandas':pd.__version__,'sklearn':__import__('sklearn').__version__})
 out=OUTPUT/identity[:16];out.mkdir(parents=True,exist_ok=True);done=out/'receipt.json'
 if done.is_file():
  r=json.loads(done.read_text())
  if r.get('status')=='VERIFIED_TABLES_AND_RESULTS_DRAFT_COMPLETE' and r.get('signature')==identity:
   if all((out/n).is_file() and sha(out/n)==h for n,h in r['output_sha256'].items()):
    print('REUSED VERIFIED FINALIZATION — no metric reconstruction repeated.');print(json.dumps(r,indent=2));return
   raise Stop('Completed finalization artifacts changed; no overwrite')
 allmetrics=[];allmonitors=[];allchecks=[];allaliases=[]
 for dataset,job in jobs:
  m,e,c,a=reconstruct(job,dataset);allmetrics.extend(m);allmonitors.extend(e);allchecks.extend(c);allaliases.extend(a)
  print('RECONSTRUCTION VERIFIED:',dataset,'actual metric rows',len(m),'monitor rows',len(e),flush=True)
 totals=export_tables(out,allmetrics,allmonitors,allaliases,allchecks,provenance)
 if source and Path(source).is_file():shutil.copyfile(source,out/'executed_verifier.py')
 artifacts={p.name:sha(p) for p in out.iterdir() if p.is_file() and p.name not in {'receipt.json','PRIVATE_verified_paper_results.zip'}}
 receipt={'status':'VERIFIED_TABLES_AND_RESULTS_DRAFT_COMPLETE','signature':identity,'source_extension_closed':True,
  'actual_metrics_reconstructed_from_predictions_and_labels':True,'estimated_metrics_reconstructed_from_scores_and_source_reference':True,
  'model_fits':0,'model_loads':0,'new_inference':0,'replays':0,'calibration_resampling_repeated':False,
  'findings':totals,'new_monitor_success_established':False,'novelty_established':False,
  'submission_readiness_claimed':False,'output_sha256':artifacts,'output_directory':str(out)}
 js(done,receipt);package=out/'PRIVATE_verified_paper_results.zip'
 with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(out.iterdir()):
   if p.is_file() and p!=package:z.write(p,p.name)
 with zipfile.ZipFile(package) as z:
  if z.testzip():raise Stop('Final result ZIP CRC failed')
 print('\nVERIFIED FINDINGS\n'+json.dumps(totals,indent=2),flush=True)
 print('\nFINALIZATION RECEIPT\n'+json.dumps(receipt,indent=2),flush=True)
 print('PRIVATE PACKAGE:',package,'SHA256:',sha(package),flush=True)
 print('Results text is ready as a draft; unproved novelty or method success is not inserted.',flush=True)

try:main()
except Exception as e:
 p=OUTPUT/('failure_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
 js(p,{'status':'STOPPED_WITH_EXACT_REASON','reason':str(e),'model_fits':0,'model_loads':0,'replays':0})
 print('STOPPED:',e,flush=True)
