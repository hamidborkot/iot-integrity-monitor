# RUN AFTER THE FAILED CELL HAS STOPPED. Keep this kernel; do not restart.
# Removes ONLY rebuildable caches and incomplete replay output under this batch.
# Preserves models, input datasets, completed receipts, linked CSVs and completed replays.
import gc,hashlib,json,os,shutil,sqlite3
from datetime import datetime,timezone
from pathlib import Path

WORK=Path('/kaggle/working')
BASE=WORK/'TRACE_LINKAGE_BATCH_v1'
if not BASE.is_dir() or BASE.is_symlink():raise RuntimeError('Expected nonsymlink batch directory missing.')
BASE=BASE.resolve()

# Do not delete anything while a Zeek extraction in this batch is still running.
active=[]
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:
  name=(proc/'comm').read_text().strip()
  cwd=(proc/'cwd').resolve()
  if name in {'zeek','bro'} and cwd.is_relative_to(BASE):active.append(proc.name)
 except (OSError,RuntimeError):pass
if active:raise RuntimeError('Stop the running extraction before cleanup; active process IDs: '+','.join(active))

# Close only live SQLite connections belonging to this batch.
closed=0
for obj in gc.get_objects():
 if not isinstance(obj,sqlite3.Connection):continue
 try:
  dbs=obj.execute('PRAGMA database_list').fetchall()
  if any(row[2] and Path(row[2]).resolve().is_relative_to(BASE) for row in dbs):
   obj.close();closed+=1
 except sqlite3.ProgrammingError:pass
 except sqlite3.Error as error:raise RuntimeError('Could not safely close batch database: '+str(error))
gc.collect()

# Keep small completed candidate receipts in memory before freeing space.
completed=[];metadata_hashes={}
for p in BASE.rglob('*.json'):
 if p.is_symlink() or not p.is_file():continue
 if p.stat().st_size>2*1024**2:continue
 try:
  data=p.read_bytes();metadata_hashes[str(p)]=hashlib.sha256(data).hexdigest()
  if p.name=='candidate_receipt.json':
   obj=json.loads(data)
   if obj.get('status')=='FULL_LOG_LINKAGE_COMPUTED':completed.append(obj)
 except (OSError,ValueError):pass

before=shutil.disk_usage(WORK).free
removed=[]
# These files contain derived indexes, NOT original observations or labels.
for p in sorted(BASE.rglob('reference_keys.sqlite*')):
 if p.is_symlink() or not p.is_file():continue
 if p.name not in {'reference_keys.sqlite','reference_keys.sqlite-wal','reference_keys.sqlite-shm','reference_keys.sqlite-journal'}:continue
 if not p.resolve().is_relative_to(BASE):raise RuntimeError('Cache path escaped batch root.')
 size=p.stat().st_size;p.unlink()
 removed.append({'path':str(p),'bytes':size,'reason':'REBUILDABLE_SQLITE_CACHE'})

# Delete replay folders only when neither extraction nor candidate completion exists.
# Preserve the separate zeek.log and record the partial folder's file inventory.
for replay in sorted(BASE.rglob('replay')):
 if not replay.is_dir() or replay.is_symlink():continue
 job=replay.parent
 if (job/'extraction_complete.json').exists() or (job/'candidate_receipt.json').exists():continue
 files=[p for p in replay.rglob('*') if p.is_file() and not p.is_symlink()]
 if any(p.is_symlink() for p in replay.rglob('*')):raise RuntimeError('Unexpected symlink in partial replay; not deleting it.')
 if not replay.resolve().is_relative_to(BASE):raise RuntimeError('Partial replay path escaped batch root.')
 details=[{'path':str(p),'bytes':p.stat().st_size}for p in files]
 size=sum(r['bytes']for r in details)
 shutil.rmtree(replay)
 removed.append({'path':str(replay),'bytes':size,'reason':'INCOMPLETE_EXTRACTION_ONLY','partial_files':details})

after=shutil.disk_usage(WORK).free
if after<64*1024**2:raise RuntimeError('Cleanup freed too little space to save receipt; do not delete other outputs blindly.')
changed=[]
for value,expected in metadata_hashes.items():
 p=Path(value)
 if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:changed.append(value)
if changed:raise RuntimeError('Protected metadata changed: '+str(changed))

receipt={'created_utc':datetime.now(timezone.utc).isoformat(),'batch_root':str(BASE),
 'closed_batch_database_connections':closed,'removed_derivative_entries':removed,
 'free_bytes_before':before,'free_bytes_after':after,'free_GiB_after':round(after/1024**3,3),
 'protected_small_metadata_unchanged':True,'completed_candidate_receipts_preserved':len(completed),
 'original_input_datasets_deleted':False,'models_deleted':False,'completed_linked_CSVs_deleted':False,
 'completed_replay_logs_deleted':False,'NF_changed':False,
 'old_SQLite_batch_must_not_be_rerun':True,
 'continuation_design':'Compressed hash-partition joins; all records, bounded cache budget, one scenario at a time.'}
(WORK/'TRACE_STORAGE_RECOVERY_RECEIPT.json').write_text(json.dumps(receipt,indent=2))
(WORK/'TRACE_PRESERVED_CANDIDATE_RECEIPTS.json').write_text(json.dumps(completed,indent=2))
print(json.dumps({k:v for k,v in receipt.items()if k!='removed_derivative_entries'},indent=2))
print('\nREMOVED REBUILDABLE STORAGE')
for r in removed:print(round(r['bytes']/1024**3,3),'GiB',r['reason'],r['path'])
print('\nPRESERVED COMPUTED CANDIDATES')
for r in completed:
 print(r['scenario'],Path(r['capture']).name,'matches=',r['unique_exact_key_matches'],
       'generated=',r['generated_rows'],'reference=',r['reference_rows'],
       'predictor_differences=',r['predictor_difference_counts'])
print('\nPaste this recovery output. DO NOT rerun expand_trace_linkage_batch_v1.py.')
