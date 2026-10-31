# READ-ONLY KAGGLE AUDIT: prints only. No installs, extraction or disk writes.
from pathlib import Path,PurePosixPath
from collections import Counter,defaultdict
from contextlib import contextmanager
import os,io,csv,gzip,json,hashlib,zipfile

BASE=Path('/kaggle/input/datasets')
ROOTS=[BASE/p for p in [
 'amineipad/cic-iomt-dataset-2024','himadri07/ciciot2023',
 'sonalimishra3/iot-2023-dataset-full','fadiabuzwayed/ton-iot-train-test-network',
 'dhoogla/nftoniotv2','dhoogla/csecicids2018','shamstahzib/nsl-kdd-dataset',
 'mdhamidborkottulla/all-kaggle-work','mdhamidborkottulla/full-working-backup',
 'mdhamidborkottulla/batch5','mdhamidborkottulla/extractor',
 'mdhamidborkottulla/complete-backup','mdhamidborkottulla/full-backup',
 'mdhamidborkottulla/last-day-backup','mdhamidborkottulla/one-last',
 'mdhamidborkottulla/ran-files','mdhamidborkottulla/the-last-update',
 'mdhamidborkottulla/whole-in-one','mdhamidborkottulla/the-last-days-backup',
 'mdhamidborkottulla/pcaps-of-ciciot-23-and-24','mdhamidborkottulla/githubnids']]
RUN='RAW_ONLY_REMEASUREMENT_20261017T130813279947Z'
NESTED_SINGLE=32*1024**2
NESTED_TOTAL=128*1024**2
LIMIT_PRINT=45
NAMES={
 'fresh_HGB.joblib','fresh_LR.joblib','fresh_source_panel.csv','fresh_source_panel.csv.gz',
 'model_binding.json','environment.json','PRE_OUTCOME_PROTOCOL.json',
 'experiment1_unit_decisions.csv','experiment1_unit_decisions.csv.gz',
 'experiment2_window_information.csv','experiment2_window_information.csv.gz',
 'DECISION_INFORMATION_TABLE.csv','source_holdout_metrics.csv',
 'panel_BEFORE_LABELS.csv','panel_BEFORE_LABELS.csv.gz','raw_identity.json','null_control.json',
 'five_seed_models_and_calibrators.joblib','frozen_five_seed_bank.joblib',
 'source_panel_with_network_groups.csv','source_panel_with_network_groups.csv.gz'}
PREFIXES=('RAW_ONLY_REMEASUREMENT_','CONTROLLED_FIVE_SEED_SOURCE_SPLIT_',
 'FIVE_SEED_FIXED_TARGET_','LINEAGE_','MECHANISM_DIAGNOSIS_',
 'REMEASUREMENT_','TRACE_','DIAGNOSTIC_INPUT_FIX_')
assets=[];archive_paths=[];mounts=[];errors=[];groups=Counter();seen_paths=set()

for root in ROOTS:
 counts=Counter();total=0;n=0;symlinks=0
 if root.is_dir():
  for current,dirs,files in os.walk(root,followlinks=False):
   symlinks+=sum((Path(current)/d).is_symlink() for d in dirs)
   dirs[:]=[d for d in dirs if not (Path(current)/d).is_symlink()]
   directory=Path(current)
   if directory.name.startswith(PREFIXES):groups[directory.name]+=1
   for name in files:
    p=directory/name
    if p.is_symlink():symlinks+=1;continue
    try:size=p.stat().st_size
    except OSError as e:errors.append({'path':str(p),'error':str(e)});continue
    n+=1;total+=size;counts[p.suffix.lower() or '<none>']+=1
    if str(p) in seen_paths:continue
    seen_paths.add(str(p))
    if name in NAMES:assets.append({'path':str(p),'chain':[],'logical':str(p),'bytes':size})
    if p.suffix.lower()=='.zip':archive_paths.append(p)
 mounts.append({'root':str(root),'mounted':root.is_dir(),'files':n,'logical_GiB':round(total/1024**3,4),
  'top_extensions':counts.most_common(5),'symlinks_not_followed':symlinks})

nested_read=0;archive_members=0;archive_failures=0;nested_limits=[];nested_seen=set()
def scan_zip(z,physical,chain,depth):
 global nested_read,archive_members
 for info in z.infolist():
  if info.is_dir():continue
  archive_members+=1;logical='/'.join([str(physical),*chain,info.filename])
  for part in PurePosixPath(info.filename).parts:
   if part.startswith(PREFIXES):groups[part]+=1
  if PurePosixPath(info.filename).name in NAMES:
   assets.append({'path':str(physical),'chain':[*chain,info.filename],'logical':logical,'bytes':info.file_size})
  if info.filename.lower().endswith('.zip') and depth<2:
   if info.file_size>NESTED_SINGLE or nested_read+info.file_size>NESTED_TOTAL:
    nested_limits.append({'archive':str(physical),'member':info.filename,'bytes':info.file_size});continue
   try:
    payload=z.read(info);nested_read+=len(payload);h=hashlib.sha256(payload).hexdigest()
    if h in nested_seen:continue
    nested_seen.add(h)
    with zipfile.ZipFile(io.BytesIO(payload)) as inner:scan_zip(inner,physical,[*chain,info.filename],depth+1)
   except (OSError,ValueError,zipfile.BadZipFile) as e:errors.append({'archive':str(physical),'member':info.filename,'error':str(e)})
for p in archive_paths:
 try:
  with zipfile.ZipFile(p) as z:scan_zip(z,p,[],0)
 except (OSError,zipfile.BadZipFile) as e:
  archive_failures+=1;errors.append({'path':str(p),'error':str(e)})

@contextmanager
def opened(a):
 chain=a['chain']
 if not chain:
  with open(a['path'],'rb') as f:yield f
 elif len(chain)==1:
  with zipfile.ZipFile(a['path']) as z,z.open(chain[0]) as f:yield f
 else:
  with zipfile.ZipFile(a['path']) as z:payload=z.read(chain[0])
  for member in chain[1:-1]:
   with zipfile.ZipFile(io.BytesIO(payload)) as z:payload=z.read(member)
  with zipfile.ZipFile(io.BytesIO(payload)) as z,z.open(chain[-1]) as f:yield f

def location(a):return a['path']+(' ! '+' ! '.join(a['chain']) if a['chain'] else '')
def decoded_prefix(a,n=16384):
 with opened(a) as f:
  magic=f.read(2);f.seek(0)
  if magic==b'\x1f\x8b':
   with gzip.GzipFile(fileobj=f) as g:data=g.read(n)
   return 'gzip-by-content',data
  return 'plain-by-content',f.read(n)
def small_json(a):
 if a['bytes']>1024**2:raise ValueError('Metadata JSON exceeds audit bound')
 mode,b=decoded_prefix(a,1024**2+1)
 if len(b)>1024**2:raise ValueError('Decoded JSON exceeds audit bound')
 return json.loads(b)
def file_hash(a):
 h=hashlib.sha256()
 with opened(a) as f:
  for b in iter(lambda:f.read(1024**2),b''):h.update(b)
 return h.hexdigest()

exact=[a for a in assets if RUN in a['logical']]
def matches(relative):
 variants=[relative]
 if relative.endswith('.gz'):variants.append(relative[:-3])
 elif relative.endswith('.csv'):variants.append(relative+'.gz')
 return [a for a in exact if any(a['logical'].replace('\\','/').endswith('/'+v) for v in variants)]
roles={
 'model_HGB':matches('fresh_HGB.joblib'),'model_LR':matches('fresh_LR.joblib'),
 'model_binding':matches('model_binding.json'),'environment':matches('environment.json'),
 'protocol':matches('PRE_OUTCOME_PROTOCOL.json'),'saved_unit_outcomes':matches('experiment1_unit_decisions.csv.gz'),
 'saved_window_outcomes':matches('experiment2_window_information.csv'),
 'optional_source_panel':matches('fresh_source_panel.csv.gz')}
for c in [49,7]:
 for name in ['raw_identity.json','panel_BEFORE_LABELS.csv.gz']:roles[f'capture_{c}_{name}']=matches(f'capture_{c}/'+name)
roles['saved_null_control']=matches('capture_34/null_control.json')

print('=== READ_ONLY_AUDIT_BEGIN ===')
print('DISK_WRITES=0; MODEL_LOADS=0; TRAINING=0; REPLAYS=0; INSTALLS=0')
print('\nMOUNTS')
for row in mounts:print(json.dumps(row))
print('\nARCHIVE_SCAN',json.dumps({'ZIPs':len(archive_paths),'members_inspected':archive_members,
 'failed_archives':archive_failures,'nested_memory_read_MiB':round(nested_read/1024**2,2),
 'nested_depth_limit':2,'nested_size_limit_skips':len(nested_limits)}))
print('\nEXACT_RUN_ROLES:',RUN)
for role,hits in roles.items():
 print(role,'copies_found=',len(hits))
 for a in hits[:3]:print(' ',location(a),'bytes=',a['bytes'])
 if len(hits)>3:print(' ',len(hits)-3,'additional copies not printed')

print('\nCSV_CONTENT_CHECKS — headers only, no record values')
for role in ['optional_source_panel','saved_unit_outcomes','saved_window_outcomes','capture_49_panel_BEFORE_LABELS.csv.gz','capture_7_panel_BEFORE_LABELS.csv.gz']:
 for a in roles.get(role,[])[:2]:
  try:
   mode,data=decoded_prefix(a);first=data.decode('utf-8-sig').splitlines()[0]
   print(json.dumps({'role':role,'location':location(a),'content':mode,'columns':next(csv.reader([first]))}))
  except Exception as e:print(json.dumps({'role':role,'location':location(a),'error':str(e)}))

print('\nMODEL_IDENTITY_CHECKS — hashes only; no joblib loading')
bindings=[]
for a in roles['model_binding']:
 try:bindings.append((a,small_json(a)))
 except Exception as e:errors.append({'path':location(a),'error':str(e)})
expected={fam:set(str(b.get('model_sha256',{}).get(fam)) for _,b in bindings if b.get('model_sha256',{}).get(fam)) for fam in ['HGB','LR']}
for fam in ['HGB','LR']:
 for a in roles['model_'+fam][:4]:
  if a['bytes']>64*1024**2:
   print(json.dumps({'family':fam,'location':location(a),'status':'HASH_SKIPPED_SIZE_LIMIT'}));continue
  try:
   digest=file_hash(a)
   print(json.dumps({'family':fam,'location':location(a),'sha256':digest,
    'matching_binding_hash':digest in expected[fam],'conflicting_expected_hashes':len(expected[fam])>1}))
  except Exception as e:print(json.dumps({'family':fam,'error':str(e)}))

print('\nENVIRONMENT_AND_BINDING_METADATA')
for role in ['environment','protocol','model_binding']:
 for a in roles[role][:1]:
  try:
   obj=small_json(a)
   keys={'environment':['python','sklearn','numpy','pandas','zeek'],
    'protocol':['config','fresh_training','historical_results_reproduced'],
    'model_binding':['fresh_models','source_positive_rates','model_sha256','source_panel_sha256']}[role]
   print(role,json.dumps({k:obj.get(k) for k in keys},default=str))
  except Exception as e:print(role,'ERROR',str(e))

print('\nPROJECT_DIRECTORY_NAMES — presence only, not proof of completed experiments')
for name,count in sorted(groups.items())[:LIMIT_PRINT]:print(name)
if len(groups)>LIMIT_PRINT:print('Additional project directory names not printed:',len(groups)-LIMIT_PRINT)
if not roles['optional_source_panel']:
 alternatives=[a for a in assets if PurePosixPath(a['logical']).name in {'fresh_source_panel.csv','fresh_source_panel.csv.gz'}]
 print('\nSOURCE_PANEL_CANDIDATES_OUTSIDE_EXACT_RUN',len(alternatives))
 for a in alternatives[:8]:print(location(a))
print('\nSCAN_ERRORS',json.dumps(errors[:8]))
print('NESTED_SKIPS',json.dumps(nested_limits[:5]))
mandatory_missing=[k for k,v in roles.items() if not v and k!='optional_source_panel']
print('\nSUMMARY',json.dumps({'mandatory_diagnostic_roles_missing':mandatory_missing,
 'source_panel_found':bool(roles['optional_source_panel']),
 'source_panel_is_not_used_to_refit_or_predict_in_the_planned_diagnostic':True,
 'no_inputs_selected_or_modified':True,'no_experiment_launched':True,'disk_writes':0}))
print('=== READ_ONLY_AUDIT_END ===')
