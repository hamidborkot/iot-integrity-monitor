"""Resume blocked reviewer tasks 1,2,5,7 using the verified previous runner.
Does NOT rerun completed tasks 3,4,6 or the previous Zeek timer grid.
Requires Internet for pinned dependencies/source build, if not already installed.
All previous results remain untouched. Does not certify external ground truth or invented manuscript files.
"""
import os,sys,json,hashlib,subprocess,shutil,urllib.request,re,tarfile,zipfile,ast,time,types
from pathlib import Path
from datetime import datetime,timezone
from collections import defaultdict
import pandas as pd

WORK=Path('/kaggle/working');BASE=Path('/kaggle/input/datasets/mdhamidborkottulla')
ORIGINAL_RUN='REVIEWER_EXPERIMENTS_20261027T191624929279Z'
OUT=WORK/('REVIEWER_BLOCKED_CONTINUATION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
BUILD=WORK/'.zeek_8_0_10_repair'
PREFIX=BUILD/'install'
VERSION='8.0.10'
LOG=OUT/'DEPENDENCY_REPAIR';LOG.mkdir()
MANUSCRIPT_MAIN=None  # optional exact path to YOUR main .tex if several source bundles are attached
MANUSCRIPT_BUNDLE_ROOT=None # optional root containing the .tex, .bib, styles and figures

def js(p,x):Path(p).write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def command(cmd,log,timeout=900,cwd=None):
 print('COMMAND:',cmd,'LOG:',log,flush=True)
 with open(log,'w') as f:r=subprocess.run(cmd,cwd=cwd,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 if r.returncode:raise RuntimeError(str(cmd[:3])+' failed: '+Path(log).read_text(errors='replace')[-1800:])
 return r

def all_files():
 result=[]
 for root in [BASE,WORK]:
  if not root.is_dir():continue
  for cur,dirs,names in os.walk(root,followlinks=False):
   dirs[:]=[d for d in dirs if (Path(cur)/d) not in (OUT,BUILD) and d not in ('.git','__pycache__')]
   for name in names:result.append(Path(cur)/name)
 return result
FILES=all_files()

def get_parent():
 # Prefer exact original run identity; do not choose a different result because it looks more favorable.
 possible={p.parent for p in FILES if p.name=='TASK_LEDGER.json' and ORIGINAL_RUN in p.parts}
 if possible:
  good=[]
  for folder in possible:
   if (folder/'executed_runner.py').is_file() and (folder/'CODE_IDENTITY.json').is_file():good.append(folder)
  if good:
   digests={sha(x/'executed_runner.py') for x in good}
   if len(digests)!=1:raise RuntimeError('Conflicting executed-source versions for the original run')
   return min(good,key=lambda x:(len(str(x)),str(x)))
 # If mounted as a ZIP instead of unpacked, restore only this run's non-large result/source artifacts.
 archives=[p for p in FILES if p.name=='PRIVATE_REVIEWER_EXPERIMENTS.zip']
 matches=[]
 for p in archives:
  try:
   with zipfile.ZipFile(p) as z:
    names=z.namelist()
    if {'executed_runner.py','CODE_IDENTITY.json','TASK_LEDGER.json'}.issubset(names):matches.append(p)
  except zipfile.BadZipFile:pass
 if not matches:raise RuntimeError('Previous executed runner/source binding is not mounted. Attach PRIVATE_REVIEWER_EXPERIMENTS.zip from the completed batch. Do not restart completed experiments.')
 if len({sha(p) for p in matches})!=1:raise RuntimeError('Different private experiment ZIPs attached; supply the exact original-run package')
 arc=min(matches,key=lambda x:(len(str(x)),str(x)));dest=OUT/'RESTORED_PARENT';dest.mkdir()
 with zipfile.ZipFile(arc) as z:
  for m in z.infolist():
   if m.is_dir():continue
   parts=Path(m.filename).parts
   if Path(m.filename).is_absolute() or '..' in parts:raise RuntimeError('Unsafe archive member')
   if 'scratch' in parts or m.filename.endswith(('.npy','.pcap')):continue
   if m.file_size>128*1024**2:raise RuntimeError('Unexpected large non-score artifact in parent ZIP')
   target=dest/m.filename;target.parent.mkdir(parents=True,exist_ok=True)
   with z.open(m) as src,open(target,'wb') as dst:shutil.copyfileobj(src,dst)
 js(OUT/'parent_archive_identity.json',{'path':str(arc),'sha256':sha(arc)})
 return dest

def checked_binary(p):
 if not p or not Path(p).is_file():return None
 try:
  q=subprocess.run([str(p),'--version'],capture_output=True,text=True,timeout=30)
  txt=q.stdout+q.stderr
  if q.returncode==0 and re.search(r'(?<![\d.])8\.0\.10(?![\d.])',txt):
   return str(Path(p).resolve()),txt.strip()
 except Exception:pass
 return None

def upstream_version(s):return s.strip().split(':')[-1].split('-')[0]

def get_zeek():
 for p in [PREFIX/'bin/zeek',shutil.which('zeek'),'/opt/zeek/bin/zeek']:
  hit=checked_binary(p)
  if hit:
   js(LOG/'VERIFIED_ZEEK.json',{'executable':hit[0],'version':hit[1],'executable_sha256':sha(hit[0]),'method':'existing_verified_binary'})
   return hit[0]
 errors=[]
 # First try installed repository metadata for exact CORE package, not just the metapackage.
 # Debian version epochs such as 1:8.0.10-0 are normalized correctly.
 if os.geteuid()==0 and shutil.which('apt-cache'):
  for pkg in ['zeek-8.0-core','zeek-8.0']:
   try:
    q=subprocess.run(['apt-cache','madison',pkg],capture_output=True,text=True,timeout=60)
    (LOG/(pkg+'_available_versions.txt')).write_text(q.stdout+q.stderr)
    versions=[x.split('|')[1].strip() for x in q.stdout.splitlines() if len(x.split('|'))>1]
    exact=[x for x in versions if upstream_version(x)==VERSION]
    if not exact:continue
    command(['apt-get','install','-y','--no-install-recommends',pkg+'='+exact[0]],LOG/(pkg+'_install.log'),900)
    for pp in [shutil.which('zeek'),'/opt/zeek/bin/zeek']:
     hit=checked_binary(pp)
     if hit:
      js(LOG/'VERIFIED_ZEEK.json',{'executable':hit[0],'version':hit[1],'executable_sha256':sha(hit[0]),'method':'pinned_binary_package','package':pkg,'package_version':exact[0]});return hit[0]
   except Exception as e:errors.append({'method':'apt '+pkg,'error':str(e)})
 # Source fallback: exact official release, local prefix, bounded parallel build.
 if shutil.disk_usage(WORK).free<7*1024**3:raise RuntimeError('Need 7 GiB free for pinned source build and subsequent replay; existing work will not be deleted')
 if os.geteuid()!=0:raise RuntimeError('Pinned source fallback needs build prerequisites; root is unavailable')
 deps=['cmake','make','g++','flex','bison','libpcap-dev','libssl-dev','python3-dev','swig','zlib1g-dev','libmaxminddb-dev']
 command(['apt-get','update'],LOG/'build_apt_update.log',900)
 command(['apt-get','install','-y','--no-install-recommends']+deps,LOG/'build_dependencies.log',1200)
 BUILD.mkdir(exist_ok=True)
 request=urllib.request.Request('https://api.github.com/repos/zeek/zeek/releases/tags/v8.0.10',headers={'User-Agent':'Pinned-Zeek-Reviewer-Continuation','Accept':'application/vnd.github+json'})
 with urllib.request.urlopen(request,timeout=90) as r:release=json.load(r)
 if release.get('tag_name')!='v8.0.10':raise RuntimeError('Official release tag mismatch')
 assets=[a for a in release.get('assets',[]) if a.get('name')=='zeek-8.0.10.tar.gz']
 if len(assets)!=1:raise RuntimeError('Expected exact official Zeek source release asset; no alternate source guessed')
 asset=assets[0];url=asset['browser_download_url']
 if not url.startswith('https://github.com/zeek/zeek/releases/'):raise RuntimeError('Unexpected release asset origin')
 archive=BUILD/'zeek-8.0.10.tar.gz'
 if not archive.is_file():
  req=urllib.request.Request(url,headers={'User-Agent':'Pinned-Zeek-Reviewer-Continuation'})
  with urllib.request.urlopen(req,timeout=180) as src,open(archive.with_suffix('.tmp'),'wb') as dst:
   written=0
   while True:
    b=src.read(4*1024**2)
    if not b:break
    written+=len(b)
    if written>512*1024**2:raise RuntimeError('Source asset exceeds bounded download size')
    dst.write(b)
  archive.with_suffix('.tmp').replace(archive)
 observed=sha(archive);expected=asset.get('digest')
 if expected and expected.startswith('sha256:') and observed!=expected.split(':',1)[1]:raise RuntimeError('Official asset SHA256 mismatch')
 js(LOG/'SOURCE_RELEASE_IDENTITY.json',{'tag':release['tag_name'],'url':url,'asset_id':asset.get('id'),'download_sha256':observed,'API_digest':expected,'API_digest_verified':bool(expected and expected.startswith('sha256:')),
  'note':'If API digest is absent, observed SHA is provenance, not independent publisher checksum verification.'})
 srcdir=BUILD/'zeek-8.0.10'
 if not srcdir.is_dir():
  with tarfile.open(archive) as tar:tar.extractall(BUILD,filter='data')
 if not (srcdir/'configure').is_file():raise RuntimeError('Official source layout unexpected')
 os.chmod(srcdir/'configure',0o755)
 helptext=subprocess.run([str(srcdir/'configure'),'--help'],cwd=srcdir,capture_output=True,text=True,timeout=60)
 (LOG/'configure_help.txt').write_text(helptext.stdout+helptext.stderr)
 args=[str(srcdir/'configure'),'--prefix='+str(PREFIX)]
 for flag in ['--disable-zeekjs','--disable-spicy']:
  if flag in helptext.stdout+helptext.stderr:args.append(flag)
 command(args,LOG/'configure.log',900,cwd=srcdir)
 command(['cmake','--build','build','--parallel','2'],LOG/'build.log',7200,cwd=srcdir)
 command(['cmake','--install','build'],LOG/'install.log',900,cwd=srcdir)
 hit=checked_binary(PREFIX/'bin/zeek')
 if not hit:raise RuntimeError('Built executable failed exact version verification; logs preserved')
 os.environ['PATH']=str(PREFIX/'bin')+os.pathsep+os.environ.get('PATH','')
 js(LOG/'VERIFIED_ZEEK.json',{'executable':hit[0],'version':hit[1],'executable_sha256':sha(hit[0]),'method':'official_pinned_source_build','prior_attempts':errors,'not_claimed_binary_identical_to_old_build':True})
 return hit[0]


def canonical_parts(p):
 parts=list(Path(str(p)).parts);out=[]
 for x in parts:
  if x in ('/',''):continue
  # Providers sometimes expose an unpacked .gz as a .csv convenience file.
  if x.endswith('.gz'):x=x[:-3]
  if not out or out[-1]!=x:out.append(x)
 return tuple(out)

def resolve_exact_asset(asset,files,expected=None):
 if isinstance(asset,str):asset={'path':asset}
 if not isinstance(asset,dict) or not asset.get('path'):raise RuntimeError('Invalid saved asset reference')
 old=Path(asset['path']);parts=canonical_parts(old)
 paths=[];depth_used=None
 # The full capture + condition suffix is considered before shorter suffixes.
 # Never fall back to basename-only or delay-directory-only matches.
 for depth in range(len(parts),2,-1):
  suffix=parts[-depth:]
  paths=[p for p in files if p.is_file() and canonical_parts(p)[-depth:]==suffix]
  if paths:depth_used=depth;break
 if old.is_file():paths.append(old)
 paths=list(set(paths))
 if not paths:raise RuntimeError('No exact >=3-component asset suffix: '+str(old))
 groups=defaultdict(list)
 for p in paths:groups[sha(p)].append(p)
 expected=expected or asset.get('sha256')
 if expected:
  if expected not in groups:raise RuntimeError('Exact capture-specific candidates exist but recorded hash does not match: '+str(old))
  paths=groups[expected]
 elif len(groups)!=1:raise RuntimeError('Different contents at the SAME full experiment suffix; no arbitrary selection: '+str(paths))
 result=min(paths,key=lambda p:(len(str(p)),str(p)))
 return result,{'old_path':str(old),'resolved_path':str(result),'suffix_depth':depth_used,'sha256':sha(result),'recorded_hash':expected,'member_reference':asset.get('member')}


def main():
 parent=get_parent();source=parent/'executed_runner.py';binding=json.loads((parent/'CODE_IDENTITY.json').read_text())
 actual=sha(source)
 if binding.get('sha256')!=actual:raise RuntimeError('Parent executed runner hash mismatch')
 tree=ast.parse(source.read_text());fn={n.name for n in tree.body if isinstance(n,ast.FunctionDef)}
 required={'task1','task2','task3','task4','task5','task6','task7','run_task','resolve_asset','main'}
 if not required.issubset(fn):raise RuntimeError('Not the expected original seven-task runner')
 ns={'__name__':'verified_prior_runner_definitions','__file__':str(source)}
 exec(compile(tree,str(source),'exec'),ns)
 # Importing definitions creates one empty output folder; no experiment has run.
 empty=ns['OUT']
 ns['OUT']=OUT;ns['WORK']=WORK;ns['BASE']=BASE;ns['LEDGER']=[];ns['PROV']=[];ns['FILES']=all_files()
 if empty!=OUT:
  try:empty.rmdir()
  except OSError:pass
 oldledger=json.loads((parent/'TASK_LEDGER.json').read_text());old={int(x['task']):x for x in oldledger}
 js(OUT/'PARENT_BINDING.json',{'parent':str(parent),'executed_source_sha256':actual,'original_ledger':oldledger})
 # Source-defined expected hashes are collected from the exact retained monitor-A manifest.
 registry={};resolution_log=[]
 manifests=[p for p in ns['FILES'] if p.name=='input_manifest.json' and 'LINEAGE_MONITOR_BATCH_A_20261015T202755206014Z' in str(p)]
 for path in manifests:
  obj=json.loads(path.read_text())
  for cond in obj.get('conditions',[]):
   asset=cond.get('candidate_asset',{})
   key=asset.get('path') if isinstance(asset,dict) else asset
   if key and cond.get('candidate_sha256'):registry[key]=cond['candidate_sha256']
 def repaired_asset(asset):
  oldpath=asset.get('path') if isinstance(asset,dict) else asset
  try:resolved,row=resolve_exact_asset(asset,ns['FILES'],registry.get(oldpath))
  except Exception as e:raise ns['Block'](str(e)) from e
  # An archive-member reference can resolve to an already unpacked exact file.
  if isinstance(asset,dict) and asset.get('member') and resolved.suffix.lower()=='.zip':raise ns['Block']('Archive member still compressed; no member silently ignored')
  resolution_log.append(row);js(OUT/'ASSET_RESOLUTION_LOG.json',resolution_log)
  ns['PROV'].append({'task':ns['TASK'].name,'role':'capture-specific saved asset','path':str(resolved),'sha256':row['sha256']})
  return resolved
 ns['resolve_asset']=repaired_asset
 def repaired_zeek():
  try:return get_zeek()
  except Exception as e:raise ns['Block'](str(e)) from e
 ns['zeek_binary']=repaired_zeek
 # Avoid repeated builds/downloads: installation is attempted once, before both replay tasks.
 binary=None
 print('\nPINNED DEPENDENCY REPAIR',flush=True)
 try:binary=get_zeek();print('ZEEK READY:',binary,flush=True)
 except Exception as e:
  js(LOG/'REPAIR_FAILURE.json',{'reason':str(e)});print('ZEEK REPAIR FAILED:',e,flush=True)
 if binary:ns['zeek_binary']=lambda:binary
 else:
  def no_zeek():raise ns['Block']('Pinned dependency repair did not pass; see DEPENDENCY_REPAIR logs. No repeated install attempted.')
  ns['zeek_binary']=no_zeek
 print('\nPRESERVED SUCCESSFUL TASKS',flush=True)
 for number,filename in [(3,'same_cohort_bounds.csv'),(4,'independent_validation_summary.csv'),(6,'M4_verdict_inputs_REPRODUCTION.csv')]:
  if number not in old:raise RuntimeError('Parent ledger missing preserved task '+str(number))
  folder=parent/f'{number:02d}';path=folder/filename
  if not path.is_file():raise RuntimeError('Completed output is missing: '+str(path))
  print('\nTASK',number,'REUSED; NOT RERUN\n'+pd.read_csv(path).to_string(index=False,max_rows=None,max_cols=None),flush=True)
  row=dict(old[number]);row['status']='REUSED_WITHIN_PREVIOUS_DECLARED_SCOPE';row['source_output']=str(path);row['source_output_sha256']=sha(path);ns['LEDGER'].append(row)
 # This continuation executes only the four previously blocked tasks.
 for number,title in [(1,'Second extractor paired counts'),(2,'Matched MD3 with repaired capture-specific resolution'),(5,'Fresh48 benign descendant accounting')]:
  ns['run_task'](number,title,ns['task'+str(number)])
 # Compiler task: same implementation unless user explicitly identifies a main source.
 if MANUSCRIPT_MAIN is not None:
  mainpath=Path(MANUSCRIPT_MAIN)
  if not mainpath.is_file():raise RuntimeError('Specified manuscript .tex absent')
  bundle=Path(MANUSCRIPT_BUNDLE_ROOT) if MANUSCRIPT_BUNDLE_ROOT else mainpath.parent
  if mainpath.parent!=bundle:raise RuntimeError('For this compile runner place the main .tex at the manuscript bundle root')
  ns['FILES']=[p for p in ns['FILES'] if p.suffix.lower()!='.tex']+[mainpath]
 ns['run_task'](7,'Compile actual manuscript source if attached',ns['task7'])
 pd.DataFrame(ns['PROV']).to_csv(OUT/'CONTINUATION_INPUT_PROVENANCE.csv',index=False)
 ledger=sorted(ns['LEDGER'],key=lambda x:int(x['task']));pd.DataFrame(ledger).to_csv(OUT/'FINAL_TASK_LEDGER.csv',index=False);js(OUT/'FINAL_TASK_LEDGER.json',ledger)
 print('\nFINAL CONTINUATION LEDGER\n'+pd.DataFrame(ledger).to_string(index=False,max_colwidth=None),flush=True)
 residual={
  'tasks_3_4_6_rerun':False,
  'original_32_job_zeek_grid_rerun':False,
  'independent_expert_ledger_ground_truth':'NOT_CREATED by this code; the previous sample is an independent decoder/matcher check with shared event evidence',
  'historical_capture49_benign_descendant_FPR':'NOT_REPLACED by the fresh48 task; fresh48 has its own explicitly labelled result',
  'capture35_certificate_violations':'RETAINED; no thresholds or frozen formula retuned to conceal them',
  'manuscript_missing_means':'BLOCKED, not a passed compile',
  'bibliographic_metadata_authenticity':'Not established by a successful TeX compile',
  'all_reviewer_requests_automatically_solved':False}
 js(OUT/'REMAINING_SCIENTIFIC_SCOPE.json',residual);print('\nSCIENTIFIC SCOPE\n'+json.dumps(residual,indent=2),flush=True)

try:main()
except Exception as e:
 js(OUT/'CONTINUATION_SETUP_FAILURE.json',{'error':str(e)});(OUT/'traceback.txt').write_text(__import__('traceback').format_exc());print('CONTINUATION STOPPED:',e,flush=True)
finally:
 # Include all printed task tables/logs; never copy raw PCAPs, memmaps or dependency build trees.
 package=OUT/'PRIVATE_BLOCKED_TASK_CONTINUATION.zip'
 with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(OUT.rglob('*')):
   if p.is_file() and p!=package and 'scratch' not in p.relative_to(OUT).parts and p.suffix not in ('.pcap','.npy') and p.stat().st_size<=128*1024**2:
    z.write(p,str(p.relative_to(OUT)))
 with zipfile.ZipFile(package) as z:
  bad=z.testzip()
  if bad:raise RuntimeError('Package CRC failure '+bad)
 print('CONTINUATION OUTPUT:',OUT,'\nPACKAGE:',package,'\nSHA256:',sha(package),flush=True)
