# Run AFTER the continuation. Consolidates evidence; does not invent completion.
from pathlib import Path
from datetime import datetime, timezone
import hashlib,json,zipfile
import pandas as pd

WORK=Path('/kaggle/working')
DEST=WORK/('P3_CONSOLIDATED_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
DEST.mkdir(parents=True,exist_ok=False)
roots=[WORK,Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')]
roster=[7,9,33,36,39,43,17,34]
rows=[];tables={'targets':[],'monitors':[]};manifest=[];errors=[]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
seen=set()
for root in roots:
 if not root.is_dir():continue
 for run in sorted(root.glob('P3_RAW_CAPTURE*')):
  if not run.is_dir():continue
  for cap in roster:
   case=run/f'CTU-IoT-Malware-Capture-{cap}-1';rp=case/'receipt.json'
   if not rp.is_file():continue
   try:
    r=json.loads(rp.read_text());key=(cap,sha(rp))
    if key in seen:continue
    seen.add(key)
    row={'capture':cap,'run':str(run),'status':r.get('status','UNKNOWN'),
         'reason':r.get('reason',''),'new_PCAP_replays':r.get('new_PCAP_replays'),
         'pacing_eligible_units':r.get('pacing_eligible_units'),
         'receipt_sha256':key[1]}
    rows.append(row)
    for label,name in [('targets','five_seed_target_results.csv'),('monitors','five_seed_monitor_results.csv')]:
     p=case/name
     if not p.is_file():continue
     df=pd.read_csv(p)
     if 'capture' not in df or set(df.capture.astype(int))!={cap}:raise ValueError('Capture column mismatch: '+str(p))
     df['evidence_run']=str(run);df['evidence_file_sha256']=sha(p);tables[label].append(df)
    for p in sorted(case.iterdir()):
     if p.is_file() and p.suffix.lower() in {'.csv','.gz','.json','.py','.txt'}:
      manifest.append({'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)})
   except Exception as e:errors.append({'path':str(rp),'error':str(e)})
pd.DataFrame(rows).to_csv(DEST/'all_capture_receipts.csv',index=False)
pd.DataFrame(errors,columns=['path','error']).to_csv(DEST/'validation_errors.csv',index=False)
status=[]
for cap in roster:
 items=[r for r in rows if r['capture']==cap]
 done=[r for r in items if r['status']=='RAW_CAPTURE_PACKET_AWARE_POINT_MONITOR_EVALUATION_COMPLETE']
 status.append({'capture':cap,'saved_attempts':len(items),'completed_attempts':len(done),
  'execution_status':'EVALUATED' if done else ('ATTEMPT_RECORDED_NOT_EVALUATED' if items else 'NO_SAVED_ATTEMPT_FOUND'),
  'selected_result':'ALL_ATTEMPTS_RETAINED_NO_OUTCOME_SELECTION'})
pd.DataFrame(status).to_csv(DEST/'roster_status.csv',index=False)
for label,frames in tables.items():
 if not frames:continue
 df=pd.concat(frames,ignore_index=True)
 df.to_csv(DEST/f'all_{label}_with_provenance.csv',index=False)
 if label=='targets':
  keys=['capture','split_policy','family','model_seed','delay_seconds']
  df[df.duplicated(keys,keep=False)].to_csv(DEST/'repeated_target_keys_REQUIRE_REVIEW.csv',index=False)
  if {'record_accuracy','unit_detection_lower','unit_detection_upper','pacing_eligible_units'}<=set(df):
   df['condition_role']=df.apply(lambda x:'CLEAN' if x.delay_seconds==0 else ('IDENTITY_NO_ELIGIBLE_ACTION' if x.pacing_eligible_units==0 else 'TRANSFORMATION_APPLIED'),axis=1)
   cols=keys+['record_accuracy','selected_record_recall','benign_FPR','unit_detection_lower','unit_detection_upper','pacing_eligible_units','condition_role','evidence_run']
   df[cols].to_csv(DEST/'detector_and_unit_results.csv',index=False)
pd.DataFrame(manifest).drop_duplicates().to_csv(DEST/'input_evidence_manifest.csv',index=False)
readme="""# Evidence consolidation, not an automatic declaration of paper completion
All saved attempts are retained. Repeated target keys must be reconciled before pooling.
Identity conditions are not successful evasion tests. A metadata shortage is budget-limited.
Model seeds, windows, and flows do not establish independent capture/corpus replication.
This batch covers pacing on the declared additional captures only.
It does not run missing injection, alternate-timeout, agreement/gate/MD3, resource,
AUROC-reconciliation, literature-review, or manuscript tasks.
Only values read from actual saved tables are included. No unsupported completion flags.
"""
(DEST/'README.md').write_text(readme)
receipt={'status':'P3_EVIDENCE_CONSOLIDATED','roster':roster,'capture_status':status,
 'validation_errors':errors,'new_experiments_run_by_this_cell':False,
 'whole_project_complete':False,'output_directory':str(DEST)}
(DEST/'receipt.json').write_text(json.dumps(receipt,indent=2))
archive=DEST/'PRIVATE_consolidated_tables.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(DEST.iterdir()):
  if p.is_file() and p!=archive:z.write(p,p.name)
with zipfile.ZipFile(archive) as z:
 bad=z.testzip()
 if bad:raise RuntimeError('ZIP CRC failure: '+bad)
print(pd.DataFrame(status).to_string(index=False))
print(json.dumps({'output_directory':str(DEST),'archive':str(archive),
 'archive_sha256':sha(archive),'CRC_verified':True,'validation_error_count':len(errors)},indent=2))
