# Paired original-unit and monitor analysis. No replay, fitting, or resampling.
from pathlib import Path
from datetime import datetime, timezone
import hashlib,json,traceback,zipfile
import numpy as np
import pandas as pd

W=Path('/kaggle/working')
OUT=W/('P3_PAIRED_UNIT_ANALYSIS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
ROOTS=[W,Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')]
IDS=['capture','split_policy','family','model_seed']
GOOD='RAW_CAPTURE_PACKET_AWARE_POINT_MONITOR_EVALUATION_COMPLETE'
STATUS={'PURE_ALARM_WITNESS':(1,1),'NO_RECORD_ALARM':(0,0),'UNRESOLVED':(0,1)}
receipt={'status':'STARTED','new_PCAP_replays':0,'model_fits':0,
 'new_sampling':False,'independent_confirmation':False,'whole_project_complete':False,
 'output_directory':str(OUT)}
paired=[];transitions=[];monitor=[];intakes=[];errors=[];bindings=[];seen=set()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def read(p):return json.loads(p.read_text())
def boolean(x):
 if x in [True,'True','true',1,'1']:return True
 if x in [False,'False','false',0,'0']:return False
 raise ValueError('Invalid Boolean '+repr(x))

for root in ROOTS:
 if not root.is_dir():continue
 for run in sorted(root.glob('P3_RAW_CAPTURE*')):
  if not run.is_dir():continue
  for case in sorted(run.glob('CTU-IoT-Malware-Capture-*-1')):
   rp=case/'receipt.json'
   if not rp.is_file():continue
   try:
    r=read(rp);cap=int(r['capture'])
    if r.get('status')!=GOOD:
     intakes.append({'capture':cap,'run':str(run),'status':r.get('status'),
      'reason':r.get('reason',''),'evaluated':False});continue
    names=['five_seed_target_results.csv','five_seed_monitor_results.csv','original_unit_results.csv.gz']
    files=[case/n for n in names]
    signature=(cap,*(sha(p) for p in files))
    if signature in seen:continue
    seen.add(signature)
    target=pd.read_csv(files[0]);mon=pd.read_csv(files[1]);units=pd.read_csv(files[2],dtype={'ks':str})
    if target.duplicated(IDS+['delay_seconds']).any():raise ValueError('Repeated target keys within case')
    if units.duplicated(IDS+['delay_seconds','ks']).any():raise ValueError('Repeated original unit keys')
    if not units.classification.isin(STATUS).all():raise ValueError('Unknown attribution classification')
    if set(target.capture)!={cap} or set(units.capture)!={cap}:raise ValueError('Capture mismatch')
    for p in files:bindings.append({'capture':cap,'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size})
    base=target[target.delay_seconds.eq(0)].set_index(IDS)
    if len(base)==0:raise ValueError('Clean baseline missing')
    for vals,g in units.groupby(IDS,sort=True):
     clean=g[g.delay_seconds.eq(0)][['ks','classification']].rename(columns={'classification':'clean_class'})
     if clean.empty:raise ValueError('Missing unit clean baseline')
     for delay in [1,10]:
      attack=g[g.delay_seconds.eq(delay)][['ks','classification']].rename(columns={'classification':'paced_class'})
      join=clean.merge(attack,on='ks',validate='one_to_one',how='outer',indicator=True)
      if not join['_merge'].eq('both').all():raise ValueError('Paired unit membership changed')
      n=len(join);lo0=np.array([STATUS[x][0] for x in join.clean_class]);hi0=np.array([STATUS[x][1] for x in join.clean_class])
      lo1=np.array([STATUS[x][0] for x in join.paced_class]);hi1=np.array([STATUS[x][1] for x in join.paced_class])
      same=(join.clean_class.eq('UNRESOLVED') & join.paced_class.eq('UNRESOLVED')).to_numpy()
      # No dependence assumptions are made for unresolved units.
      definite_loss=(lo0==1)&(hi1==0);possible_loss=(hi0==1)&(lo1==0)
      definite_gain=(hi0==0)&(lo1==1);possible_gain=(lo0==0)&(hi1==1)
      trow=target.set_index(IDS+['delay_seconds']).loc[(*vals,delay)]
      b=base.loc[vals]
      row=dict(zip(IDS,vals));row.update({'delay_seconds':delay,'evidence_run':str(run),
       'original_units':n,'modified_units':int(trow.modified_units),
       'condition_role':'IDENTITY' if int(trow.modified_units)==0 else 'PACING_APPLIED',
       'clean_unit_detection_lower':lo0.mean(),'clean_unit_detection_upper':hi0.mean(),
       'paced_unit_detection_lower':lo1.mean(),'paced_unit_detection_upper':hi1.mean(),
       'net_unit_detection_drop_lower':float((lo0-hi1).mean()),
       'net_unit_detection_drop_upper':float((hi0-lo1).mean()),
       'definite_detected_to_missed_units':int(definite_loss.sum()),
       'possible_detected_to_missed_units':int(possible_loss.sum()),
       'definite_missed_to_detected_units':int(definite_gain.sum()),
       'possible_missed_to_detected_units':int(possible_gain.sum()),
       'unresolved_in_both_conditions':int(same.sum()),
       'clean_record_accuracy':float(b.record_accuracy),'paced_record_accuracy':float(trow.record_accuracy),
       'record_accuracy_drop':float(b.record_accuracy-trow.record_accuracy),
       'selected_record_recall_drop':float(b.selected_record_recall-trow.selected_record_recall),
       'benign_FPR_change':float(trow.benign_FPR-b.benign_FPR),
       'definite_unit_drop_at_least_5pp':float((lo0-hi1).mean())>=.05,
       'unit_drop_at_least_5pp_ruled_out':float((hi0-lo1).mean())<.05})
      paired.append(row)
      for (a,z),count in join.groupby(['clean_class','paced_class']).size().items():
       transitions.append({**dict(zip(IDS,vals)),'delay_seconds':delay,'clean_class':a,'paced_class':z,'units':int(count),'evidence_run':str(run)})
    monbase=mon[mon.delay_seconds.eq(0)].set_index(IDS+['estimator'])
    for _,mr in mon[mon.delay_seconds.isin([1,10])].iterrows():
     key=tuple(mr[x] for x in IDS);delay=int(mr.delay_seconds)
     b=base.loc[key];t=target.set_index(IDS+['delay_seconds']).loc[(*key,delay)]
     estimated=float(monbase.loc[(*key,mr.estimator),'estimate']-mr.estimate)
     real=float(b.record_accuracy-t.record_accuracy)
     if not np.isclose(float(mr.differential_error),abs(estimated-real),atol=1e-10):raise ValueError('Stored differential error does not reproduce')
     monitor.append({**dict(zip(IDS,key)),'delay_seconds':delay,'estimator':mr.estimator,
      'actual_record_accuracy_drop':real,'estimated_record_accuracy_drop':estimated,
      'signed_change_error':estimated-real,'absolute_change_error':abs(estimated-real),
      'current_accuracy_absolute_error':abs(float(mr.estimate)-float(t.record_accuracy)),
      'warning_at_5pp':estimated>=.05,'record_damage_at_least_5pp':real>=.05,
      'warning_on_identity':bool(int(t.modified_units)==0 and estimated>=.05),
      'is_identity':int(t.modified_units)==0,'evidence_run':str(run)})
    intakes.append({'capture':cap,'run':str(run),'status':r['status'],'reason':'','evaluated':True})
   except Exception as e:
    errors.append({'case':str(case),'error':str(e)})
    (OUT/('error_'+str(len(errors))+'.txt')).write_text(traceback.format_exc())

P=pd.DataFrame(paired);M=pd.DataFrame(monitor)
P.to_csv(OUT/'paired_original_unit_and_record_outcomes.csv',index=False)
pd.DataFrame(transitions).to_csv(OUT/'paired_unit_transition_counts.csv',index=False)
M.to_csv(OUT/'paired_monitor_change_errors.csv',index=False)
pd.DataFrame(intakes).to_csv(OUT/'all_intake_outcomes.csv',index=False)
pd.DataFrame(bindings).to_csv(OUT/'input_hash_manifest.csv',index=False)
pd.DataFrame(errors,columns=['case','error']).to_csv(OUT/'analysis_errors.csv',index=False)
if not P.empty:
 k=IDS+['delay_seconds'];P[P.duplicated(k,keep=False)].to_csv(OUT/'repeated_cases_DO_NOT_POOL.csv',index=False)
 print('\nCAPTURE 34 — PAIRED CLEAN/1s/10s OUTCOMES')
 print(P[P.capture.eq(34)&P.model_seed.eq(8101)].to_string(index=False))
if not M.empty:
 summary=M.groupby(['evidence_run','capture','split_policy','family','delay_seconds','estimator'],as_index=False).agg(
  seed_rows=('model_seed','size'),mean_change_error=('absolute_change_error','mean'),
  mean_signed_change_error=('signed_change_error','mean'),mean_current_accuracy_error=('current_accuracy_absolute_error','mean'),
  warning_fraction=('warning_at_5pp','mean'))
 summary.to_csv(OUT/'paired_monitor_summary_descriptive.csv',index=False)
receipt.update({'status':'PAIRED_ANALYSIS_COMPLETE' if not errors and not P.empty else 'PAIRED_ANALYSIS_WITH_GAPS',
 'paired_outcome_rows':len(P),'monitor_rows':len(M),'errors':errors,
 'interpretation':'Record-accuracy errors and original-unit detection intervals are distinct targets. Unresolved attributions are not automatically misses. Seed means are descriptive, not independent-capture inference.'})
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
package=OUT/'PRIVATE_paired_analysis.zip'
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(OUT.iterdir()):
  if p.is_file() and p!=package:z.write(p,p.name)
with zipfile.ZipFile(package) as z:
 bad=z.testzip()
 if bad:raise RuntimeError('ZIP verification failed: '+bad)
print('\n'+json.dumps(receipt,indent=2))
print('Verified results:',package,'SHA256:',sha(package))
