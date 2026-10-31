"""Restore/verify uploaded all-kaggle-work backup in a fresh runtime. No training, attacks or extraction.
Small files copied; large files symlinked read-only at original /kaggle/working-relative paths so saved receipts resolve.
"""
import hashlib,json,os,re,shutil,subprocess
from collections import defaultdict
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd

INPUT=Path('/kaggle/input/datasets/mdhamidborkottulla/all-kaggle-work')
WORK=Path('/kaggle/working')
INSTALL_ZEEK=True
COPY_BUDGET=4*1024**3
MIN_FREE=3*1024**3
THRESHOLDS_MIB=[64,16,4,1]
KNOWN_BUNDLES={'CICIoT2023_bundle.joblib':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88',
 'CICIoMT2024_bundle.joblib':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473',
 'CSE_bundle.joblib':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3',
 'NSL_bundle.joblib':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29',
 'TONIoT_bundle.joblib':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf'}
KNOWN_FILES={'NF_target_panels.joblib':'c9ad50e8...'.replace('...',''),
 'boundary_result.json':'0bdab303dca24571116b2b5395c83cfe686e56fd850c2784d7c2161ec5110bfa'}
KNOWN_FILES['NF_target_panels.joblib']='c9ad50e812246b29251587b0f85ba1aaa9b09749685f774e67580994ee609b5c'
OUT=WORK/('RESTORE_ALL_KAGGLE_WORK_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def dump(p,o):p.write_text(json.dumps(o,indent=2,ensure_ascii=False),encoding='utf-8')
def free():return shutil.disk_usage(WORK).free

if not INPUT.is_dir():raise FileNotFoundError(INPUT)
files=[];zips=[]
for d,dirs,names in os.walk(INPUT,followlinks=False):
 dirs.sort()
 for n in sorted(names):
  p=Path(d)/n
  if p.is_symlink():continue
  files.append((p,p.stat().st_size))
  if p.suffix.lower()=='.zip':zips.append(str(p))
bases=defaultdict(set);base_files=defaultdict(int)
for p,_ in files:
 parts=p.relative_to(INPUT).parts
 for i,part in enumerate(parts[:-1]):
  if re.match(r'^TRACE_',part):
   base=INPUT.joinpath(*parts[:i]);bases[base].add(part);break
for p,_ in files:
 for b in bases:
  if p==b or b in p.parents:base_files[b]+=1
if not bases:
 tops=sorted({p.relative_to(INPUT).parts[0] for p,_ in files})[:50]
 raise RuntimeError(f'No TRACE_* result directories found. ZIPs={zips[:10]}; top-level={tops}. Extraction layout is unknown; no guess made.')
base=max(bases,key=lambda b:(len(bases[b]),base_files[b],-len(str(b))))
alternates=[{'base':str(b),'trace_dirs':sorted(v),'files':base_files[b]}for b,v in bases.items()if b!=base]

selected=[(p,s)for p,s in files if base in p.parents and not p.name.endswith('.partial')and 'temporary_shards'not in p.parts]
threshold=None
for mib in THRESHOLDS_MIB:
 small=sum(s for _,s in selected if s<=mib*1024**2)
 if small<=COPY_BUDGET:threshold=mib*1024**2;copy_bytes=small;break
if threshold is None:raise RuntimeError('Even 1 MiB small-file copying exceeds 4 GiB budget; inspect inventory before restoring.')
if free()<copy_bytes+MIN_FREE:raise RuntimeError(f'Insufficient free space for planned copy {copy_bytes/1024**3:.2f} GiB.')

manifest=[];conflicts=[];copied=linked=skipped=0
for i,(src,size)in enumerate(selected,1):
 rel=src.relative_to(base);dest=WORK/rel
 if dest.exists()or dest.is_symlink():
  skipped+=1
  if not dest.is_symlink() and dest.is_file() and dest.stat().st_size==size:manifest.append({'relative_path':str(rel),'bytes':size,'mode':'EXISTING_SAME_SIZE','source':str(src)})
  else:conflicts.append({'relative_path':str(rel),'bytes':size,'reason':'DESTINATION_EXISTS_NOT_OVERWRITTEN'})
  continue
 dest.parent.mkdir(parents=True,exist_ok=True)
 if size<=threshold:
  shutil.copy2(src,dest);copied+=1;mode='COPIED'
  if free()<MIN_FREE:raise RuntimeError('Free-space reserve reached during copy; partial restore preserved.')
 else:
  os.symlink(src,dest);linked+=1;mode='SYMLINK_TO_READ_ONLY_INPUT'
 manifest.append({'relative_path':str(rel),'bytes':size,'mode':mode,'source':str(src)})
 if i%5000==0:print('RESTORE PROGRESS',i,'/',len(selected),flush=True)
pd.DataFrame(manifest).to_csv(OUT/'restore_manifest.csv',index=False)
pd.DataFrame(conflicts,columns=['relative_path','bytes','reason']).to_csv(OUT/'restore_conflicts.csv',index=False)

verification=[]
def check(label,path,expected=None):
 try:
  actual=sha(path);verification.append({'item':label,'path':str(path),'bytes':path.stat().st_size,'sha256':actual,
   'expected_sha256':expected or '', 'status':'VERIFIED' if expected is None or actual==expected else 'HASH_MISMATCH'})
 except Exception as e:verification.append({'item':label,'path':str(path),'status':'ERROR','error':f'{type(e).__name__}: {e}'})
for name,expected in KNOWN_BUNDLES.items():
 paths=sorted(WORK.rglob(name))
 if not paths:verification.append({'item':name,'status':'MISSING'});continue
 for p in paths[:4]:check(name,p,expected)
for name,expected in KNOWN_FILES.items():
 for p in sorted(WORK.rglob(name))[:3]:check(name,p,expected)
for r in sorted(WORK.rglob('candidate_receipt.json')):
 try:
  obj=json.loads(r.read_text())
  if obj.get('status')!='FULL_LOG_LINKAGE_COMPUTED':continue
  linked_path=Path(obj['linked_records_path'])
  check('linked:'+obj['scenario']+':'+Path(obj['capture']).name,linked_path,obj['linked_records_sha256'])
 except Exception as e:verification.append({'item':'candidate_receipt','path':str(r),'status':'ERROR','error':str(e)})
verified=pd.DataFrame(verification);verified.to_csv(OUT/'verification.csv',index=False)

dirs=[]
for p in sorted(WORK.iterdir()):
 if p.is_dir()and not p.name.startswith('RESTORE_ALL_'):
  total=0;count=0
  for q in p.rglob('*'):
   if q.is_file():
    count+=1
    try:total+=q.stat().st_size
    except OSError:pass
  dirs.append({'directory':p.name,'files':count,'bytes':total})
pd.DataFrame(dirs).to_csv(OUT/'restored_directories.csv',index=False)

def latest(prefix):
 found=[p for p in WORK.glob(prefix+'*') if p.is_dir() and (p/'receipt.json').is_file()]
 return max(found,key=lambda p:p.name) if found else None
c0=latest('TRACE_C0_PAIRED_VALIDITY_')
c0_receipt=json.loads((c0/'receipt.json').read_text()) if c0 else None
state={'created_utc':datetime.now(timezone.utc).isoformat(),'input':str(INPUT),'selected_base':str(base),'alternate_bases_not_merged':alternates,
 'files_selected':len(selected),'copied':copied,'symlinked_large_read_only':linked,'skipped_existing':skipped,'conflicts':len(conflicts),
 'copy_threshold_MiB':threshold/1024**2,'free_GiB_after_restore':round(free()/1024**3,3),'latest_C0_directory':str(c0) if c0 else None,
 'latest_C0_receipt':c0_receipt,'verification_status_counts':verified.status.value_counts().to_dict()if not verified.empty else {},
 'models_trained':False,'attacks_executed':False,'NF_changed':False,'extraction_rerun':False}

# Fresh runtimes lose /opt/zeek; reinstall identical official package family only if missing.
def ensure_zeek():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek']:
  if p and Path(p).is_file()and os.access(p,os.X_OK):return p,'ALREADY_INSTALLED'
 import requests
 release={}
 for line in Path('/etc/os-release').read_text().splitlines():
  if '='in line:k,v=line.split('=',1);release[k]=v.strip('"')
 if release.get('ID')!='ubuntu'or release.get('VERSION_ID')!='24.04':raise RuntimeError('Official-package install implemented only for Ubuntu 24.04.')
 tools=OUT/'zeek_install';tools.mkdir()
 base_url='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/'
 key=tools/'Release.key';r=requests.get(base_url+'Release.key',timeout=(20,90));r.raise_for_status();key.write_bytes(r.content)
 ring=tools/'zeek.gpg';subprocess.run(['gpg','--batch','--yes','--dearmor','--output',str(ring),str(key)],check=True)
 sourcelist=tools/'sources.list';existing=Path('/etc/apt/sources.list').read_text()if Path('/etc/apt/sources.list').is_file()else''
 sourcelist.write_text(existing+'\n'+f'deb [signed-by={ring}] {base_url} /\n')
 opts=['-o',f'Dir::Etc::sourcelist={sourcelist}','-o','Dir::Etc::sourceparts=/etc/apt/sources.list.d']
 env=os.environ|{'DEBIAN_FRONTEND':'noninteractive'}
 subprocess.run(['apt-get',*opts,'update'],check=True,env=env,timeout=900)
 policy=subprocess.run(['apt-cache',*opts,'policy','zeek-8.0'],check=True,text=True,capture_output=True).stdout
 m=re.search(r'Candidate:\s*(\S+)',policy)
 if not m or m.group(1)=='(none)':raise RuntimeError('zeek-8.0 candidate unavailable.')
 package='zeek-8.0='+m.group(1)
 sim=subprocess.run(['apt-get',*opts,'--simulate','--no-install-recommends','install',package],check=True,text=True,capture_output=True,env=env).stdout
 if re.search(r'^Remv\s|^Inst\s+\S+\s+\[',sim,re.M):raise RuntimeError('Install would upgrade/remove existing packages; stopped.')
 subprocess.run(['apt-get',*opts,'-y','--no-install-recommends','--no-upgrade','install',package],check=True,env=env,timeout=1800)
 return '/opt/zeek/bin/zeek','INSTALLED_THIS_RUNTIME'
zeek_binary=None;zeek_status='NOT_REQUESTED';zeek_version=''
if INSTALL_ZEEK:
 try:
  zeek_binary,zeek_status=ensure_zeek()
  v=subprocess.run([zeek_binary,'--version'],capture_output=True,text=True,timeout=30);zeek_version=(v.stdout or v.stderr).strip()
 except Exception as e:zeek_status=f'FAILED: {type(e).__name__}: {e}'
state.update({'zeek_binary':zeek_binary,'zeek_status':zeek_status,'zeek_version':zeek_version})
dump(OUT/'restore_receipt.json',state);dump(WORK/'ACTIVE_RESTORE_STATE.json',state)
print(json.dumps(state,indent=2))
print('\nVERIFICATION');print(verified.drop(columns=['sha256','expected_sha256'],errors='ignore').to_string(index=False))
print('\nRESTORED TOP-LEVEL DIRECTORIES');print(pd.DataFrame(dirs).sort_values('bytes',ascending=False).to_string(index=False))
if c0:
 print('\nLATEST C0 FILES');print('\n'.join(sorted(str(p.relative_to(c0))for p in c0.rglob('*')if p.is_file())[:80]))
if conflicts:print('\nCONFLICTS NOT OVERWRITTEN');print(pd.DataFrame(conflicts).head(30).to_string(index=False))
if alternates:print('\nALTERNATE BACKUP BASES, NOT MERGED');print(json.dumps(alternates,indent=2))
print('\nPaste this output. If any item is HASH_MISMATCH/ERROR/MISSING, do not continue to new experiments.')
