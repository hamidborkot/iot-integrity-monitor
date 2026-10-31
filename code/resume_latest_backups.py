"""Resume after runtime disconnection: inspect the four mounted backups and restore verified trees.
No model loading/training, attacks, raw dataset reads, or new outcome generation.
"""
import contextlib,csv,hashlib,json,os,shutil,zipfile
from datetime import datetime,timezone
from pathlib import Path,PurePosixPath

ROOTS=[Path('/kaggle/input/datasets/mdhamidborkottulla')/name
 for name in ['the-last-update','complete-backup','whole-in-one','ran-files']]
OUT=Path('/kaggle/working')/('resume_verified_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
EXPECTED={
 'CICIoT2023_bundle.joblib':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88',
 'CICIoMT2024_bundle.joblib':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473',
 'CSE_bundle.joblib':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3',
 'NSL_bundle.joblib':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29',
 'TONIoT_bundle.joblib':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf',
 'NF_source_bundle.joblib':'d7dd5a584fa41419d088ac7c80c08742330677159ca35d6fd3fb3884cc5fe307',
 'NF_calibrated_source_bundle.joblib':'888e9783643a06792283f128403eda2e88309c6f162f0037e61dc6c907a39268',
 'NF_target_panels.joblib':'c9ad50e812246b29251587b0f85ba1aaa9b09749685f774e67580994ee609b5c'}
CORE_DIRS={'CICIoT2023_bundle.joblib':'CICIoT2023','CICIoMT2024_bundle.joblib':'CICIoMT2024',
 'CSE_bundle.joblib':'CSE','NSL_bundle.joblib':'NSL','TONIoT_bundle.joblib':'TONIoT'}
NF_DIRS={'nf_boundary_spec_v1','nf_step2_source_training_v1','nf_step3_calibration_v1',
 'nf_source_discrimination_diagnosis','nf_step4_target_contract_v1','nf_step4_target_contract_v2','nf_step5_locked_evaluation_v1'}
records=[];discovery_errors=[];root_rows=[]

def save(name,rows,columns):
 with (OUT/name).open('w',newline='',encoding='utf-8') as f:
  writer=csv.DictWriter(f,fieldnames=columns);writer.writeheader();writer.writerows(rows)
@contextlib.contextmanager
def reader(record):
 if record['member']:
  with zipfile.ZipFile(record['container']) as archive:
   with archive.open(record['member']) as handle:yield handle
 else:
  with Path(record['container']).open('rb') as handle:yield handle

def stream_hash(record):
 h=hashlib.sha256()
 with reader(record) as handle:
  for block in iter(lambda:handle.read(8*1024*1024),b''):h.update(block)
 return h.hexdigest()
def disk_hash(path):
 h=hashlib.sha256()
 with path.open('rb') as handle:
  for block in iter(lambda:handle.read(8*1024*1024),b''):h.update(block)
 return h.hexdigest()
def record_id(record):return record['container']+'::'+record['member']
def namespace(record):
 return ('zip',record['container']) if record['member'] else ('directory',record['root'])
def safe_name(name):
 p=PurePosixPath(name)
 return not p.is_absolute() and '..' not in p.parts

def read_json(record):
 with reader(record) as handle:
  payload=handle.read(20*1024*1024+1)
 if len(payload)>20*1024*1024:raise ValueError('JSON metadata exceeds safe limit.')
 return json.loads(payload)

for priority,root in enumerate(ROOTS):
 count=0
 if root.is_dir():
  for directory,dirs,filenames in os.walk(root,followlinks=False):
   current=Path(directory)
   dirs[:]=[name for name in dirs if not (current/name).is_symlink()]
   for name in sorted(filenames):
    path=current/name
    if path.is_symlink() or not path.is_file():continue
    count+=1;logical=str(path.relative_to(root))
    if name.lower().endswith('.zip'):
     try:
      with zipfile.ZipFile(path) as archive:
       for info in archive.infolist():
        if info.is_dir():continue
        if not safe_name(info.filename):raise ValueError('Unsafe archive member: '+info.filename)
        records.append({'priority':priority,'root':str(root),'container':str(path),
         'member':info.filename,'logical':info.filename,'bytes':info.file_size})
     except Exception as error:
      discovery_errors.append({'path':str(path),'error':f'{type(error).__name__}: {error}'})
    else:
     records.append({'priority':priority,'root':str(root),'container':str(path),
      'member':'','logical':logical,'bytes':path.stat().st_size})
 root_rows.append({'root':str(root),'exists':root.is_dir(),'regular_files_discovered':count})
save('roots.csv',root_rows,['root','exists','regular_files_discovered'])
save('discovery_errors.csv',discovery_errors,['path','error'])

anchors={};hash_checks=[]
for basename,expected in EXPECTED.items():
 candidates=[r for r in records if PurePosixPath(r['logical']).name==basename]
 candidates.sort(key=lambda r:(r['priority'],'PRIVATE_development_snapshot' in r['logical'],len(r['logical']),record_id(r)))
 for record in candidates:
  try:
   actual=stream_hash(record);match=actual==expected
   hash_checks.append({'file':basename,'source':record_id(record),'sha256':actual,'matches_expected':match,'error':''})
   if match:
    anchors[basename]=record;break
  except Exception as error:
   hash_checks.append({'file':basename,'source':record_id(record),'sha256':'','matches_expected':False,
    'error':f'{type(error).__name__}: {error}'})
save('anchor_hash_checks.csv',hash_checks,['file','source','sha256','matches_expected','error'])

# Select a complete core tree using its five known bundle anchors.
core_candidates=[]
for record in records:
 suffix='CICIoT2023/CICIoT2023_bundle.joblib'
 if not record['logical'].endswith(suffix):continue
 prefix=record['logical'][:-len(suffix)]
 available={r['logical']:r for r in records if namespace(r)==namespace(record)}
 members=[]
 for basename,directory in CORE_DIRS.items():
  candidate=available.get(prefix+directory+'/'+basename)
  if candidate is None:break
  members.append((basename,candidate))
 if len(members)==5:core_candidates.append((record,prefix,members))
core_candidates.sort(key=lambda item:(item[0]['priority'],'PRIVATE_development_snapshot' in item[1],len(item[1])))
selected_core=None
for record,prefix,members in core_candidates:
 try:
  if all(stream_hash(r)==EXPECTED[name] for name,r in members):
   selected_core=(namespace(record),prefix);break
 except Exception as error:
  discovery_errors.append({'path':record_id(record),'error':str(error)})

selected=[]
if selected_core:
 space,prefix=selected_core
 for r in records:
  if namespace(r)!=space or not r['logical'].startswith(prefix):continue
  relative=r['logical'][len(prefix):]
  if not relative or not safe_name(relative):continue
  if any(p.startswith('PRIVATE_development_snapshot') or p in {'.git','__pycache__'} for p in PurePosixPath(relative).parts):continue
  if relative.lower().endswith(('.zip','.pcap','.pcapng','.cap','.pcap.gz')):continue
  selected.append((r,OUT/'development'/relative))

# Recover NF stage trees from the verified NF anchor namespaces.
nf_sources=[]
for name in ['NF_source_bundle.joblib','NF_calibrated_source_bundle.joblib','NF_target_panels.joblib']:
 record=anchors.get(name)
 if record:
  parts=PurePosixPath(record['logical']).parts
  stage_index=next((i for i,p in enumerate(parts) if p in NF_DIRS),None)
  if stage_index is not None:
   prefix='/'.join(parts[:stage_index]);prefix=(prefix+'/') if prefix else ''
   nf_sources.append((record['priority'],namespace(record),prefix))
nf_sources.sort(key=lambda item:item[0])
selected_destinations={str(destination) for _,destination in selected}
for _,space,prefix in nf_sources:
 for r in records:
  if namespace(r)!=space or not r['logical'].startswith(prefix):continue
  relative=r['logical'][len(prefix):]
  if not relative or not safe_name(relative) or PurePosixPath(relative).parts[0] not in NF_DIRS:continue
  destination=OUT/relative
  if str(destination) not in selected_destinations:
   selected.append((r,destination));selected_destinations.add(str(destination))

# Recover a verified terminal NF receipt even if models are absent from a results-only ZIP.
result_candidates=[r for r in records if r['logical'].endswith('nf_step5_locked_evaluation_v1/evaluation_receipt.json')]
result_candidates.sort(key=lambda r:r['priority'])
selected_nf_result=None
for r in result_candidates:
 try:
  candidate=read_json(r)
  if candidate.get('settings_sha256')!='b18bf4cdbf33675e6e4350617b16ddf3ce554d7c25d8d51be530ec1436ab2019':continue
  prefix=r['logical'][:-len('evaluation_receipt.json')]
  index={item['logical']:item for item in records if namespace(item)==namespace(r)}
  if all(prefix+filename in index and stream_hash(index[prefix+filename])==digest for filename,digest in candidate['output_sha256'].items()):
   selected_nf_result=candidate
   result_records=[item for item in records if namespace(item)==namespace(r) and item['logical'].startswith(prefix)]
   for item in result_records:
    destination=OUT/'nf_step5_locked_evaluation_v1'/item['logical'][len(prefix):]
    # Prefer this checksum-verified result namespace to an unverified duplicate.
    selected=[pair for pair in selected if pair[1]!=destination]
    selected.append((item,destination))
   break
 except Exception as error:discovery_errors.append({'path':record_id(r),'error':str(error)})

# Ensure matched model objects are restored under canonical paths.
for name,record in anchors.items():
 if name in CORE_DIRS:destination=OUT/'development'/CORE_DIRS[name]/name
 elif name=='NF_source_bundle.joblib':destination=OUT/'nf_step2_source_training_v1'/name
 elif name=='NF_calibrated_source_bundle.joblib':destination=OUT/'nf_step3_calibration_v1'/name
 else:destination=OUT/'nf_step4_target_contract_v2'/name
 selected=[pair for pair in selected if pair[1]!=destination];selected.append((record,destination))

size=sum(r['bytes'] for r,_ in selected)
if size+1024**3>shutil.disk_usage('/kaggle/working').free:raise RuntimeError('Insufficient space for selected restoration plus 1 GiB reserve.')
copy_rows=[]
for index,(record,destination) in enumerate(selected,start=1):
 destination.parent.mkdir(parents=True,exist_ok=True)
 expected=stream_hash(record)
 if destination.exists():
  if disk_hash(destination)!=expected:raise RuntimeError('Restoration destination conflict: '+str(destination))
  continue
 temp=destination.with_suffix(destination.suffix+'.restoring')
 with reader(record) as source,temp.open('wb') as target:shutil.copyfileobj(source,target,8*1024*1024)
 if disk_hash(temp)!=expected:raise RuntimeError('Copy verification failed: '+str(destination))
 temp.replace(destination)
 copy_rows.append({'source':record_id(record),'destination':str(destination),'bytes':record['bytes'],'sha256':expected})
 if index%200==0:print('VERIFIED RESTORED FILES:',index,'/',len(selected),flush=True)
save('verified_restoration.csv',copy_rows,['source','destination','bytes','sha256'])
save('discovery_errors.csv',discovery_errors,['path','error'])

verified=[]
for name in CORE_DIRS:
 p=OUT/'development'/CORE_DIRS[name]/name
 if p.is_file() and disk_hash(p)==EXPECTED[name]:verified.append(name)
nf_results_verified=False
if selected_nf_result:
 nf_results_verified=all(disk_hash(OUT/'nf_step5_locked_evaluation_v1'/filename)==digest
  for filename,digest in selected_nf_result['output_sha256'].items())
receipt={'recovery_root':str(OUT),'restored_development_base':str(OUT/'development'),
 'verified_core_bundles':verified,'all_five_core_bundles_verified':len(verified)==5,
 'complete_core_tree_selected':selected_core is not None,
 'NF_verified_anchor_names':[name for name in anchors if name.startswith('NF_')],
 'NF_terminal_result_outputs_verified':nf_results_verified,
 'restored_files':len(copy_rows),'restored_bytes':sum(row['bytes'] for row in copy_rows),
 'backup_discovery_errors':len(discovery_errors),'models_loaded_or_retrained':False,
 'experiments_rerun':False,'legacy_ran_files_overlaid':False,
 'independent_corpus_boundary_created_by_restoration':False,
 'prospective_confirmation_created_by_restoration':False,
 'NF_boundary_result':selected_nf_result.get('boundary_result') if selected_nf_result else None}
(OUT/'resume_receipt.json').write_text(json.dumps(receipt,indent=2))
Path('/kaggle/working/research_resume_latest.json').write_text(json.dumps({'recovery_root':str(OUT),'development_base':str(OUT/'development')},indent=2))
print(json.dumps(receipt,indent=2));print('\nROOT AVAILABILITY');print(json.dumps(root_rows,indent=2))
print('\nNEXT: reuse verified completed artifacts; no blanket model/experiment rerun.')
