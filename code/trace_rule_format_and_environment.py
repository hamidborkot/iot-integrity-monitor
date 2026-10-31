# NEXT STEP: verify and expose the acquired label rules + exact extractor environment.
# No downloads, model fitting, attack optimization, or broad filesystem re-audit.
import hashlib,json,os,re,shutil,subprocess,zipfile
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd

WORK=Path('/kaggle/working')
ROOT=WORK/'TRACE_LABEL_RECOVERY_20261011T153846517131Z'
if not (ROOT/'publisher_retrieval_receipts.csv').is_file():
 candidates=[p for p in WORK.glob('TRACE_LABEL_RECOVERY_*') if p.is_dir() and (p/'publisher_retrieval_receipts.csv').is_file()]
 if len(candidates)!=1:raise RuntimeError('Set ROOT to the completed TRACE_LABEL_RECOVERY folder; no arbitrary version selected.')
 ROOT=candidates[0]
OUT=WORK/('TRACE_RULE_FORMAT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def write_json(path,obj):path.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')

table=pd.read_csv(ROOT/'publisher_retrieval_receipts.csv',keep_default_na=False)
required={'kind','path','sha256','scenario','url_final'}
if not required.issubset(table):raise ValueError('Unexpected publisher receipt columns.')
rules=table[table.kind.eq('publisher_rules')].copy()
if rules.empty:raise RuntimeError('No previously downloaded publisher rules; do not fabricate replacements.')
verified=[];errors=[];unique={}
for _,row in rules.iterrows():
 p=Path(row['path'])
 if not p.is_file():errors.append({'path':str(p),'issue':'FILE_MISSING'});continue
 actual=sha(p)
 if actual!=row['sha256']:errors.append({'path':str(p),'issue':'HASH_MISMATCH'});continue
 if p.stat().st_size>1024**2:errors.append({'path':str(p),'issue':'UNEXPECTED_RULE_SIZE'});continue
 text=p.read_text(encoding='utf-8-sig')
 verified.append({'scenario':row['scenario'],'path':str(p),'sha256':actual,'source_url':row['url_final']})
 unique.setdefault(actual,{'text':text,'scenarios':[],'path':str(p)})['scenarios'].append(row['scenario'])
pd.DataFrame(verified).to_csv(OUT/'verified_rule_sources.csv',index=False)
pd.DataFrame(errors,columns=['path','issue']).to_csv(OUT/'verification_errors.csv',index=False)
if errors:raise RuntimeError('Downloaded rule verification failed; inspect verification_errors.csv. Nothing approved.')

# Preserve actual syntax. Interpretation waits for the real contents; no guessed labeler.
report='# Exact publisher rule contents\n\n'
for h,value in unique.items():
 report+='\n## SHA256 '+h+'\nScenarios: '+', '.join(sorted(value['scenarios']))+'\n\n```text\n'+value['text']+'\n```\n'
(OUT/'ACTUAL_RULE_CONTENTS.md').write_text(report,encoding='utf-8')

binary=shutil.which('zeek') or shutil.which('bro')
if not binary:
 for p in [Path('/opt/zeek/bin/zeek'),Path('/usr/local/zeek/bin/zeek'),Path('/usr/local/bin/zeek')]:
  if p.is_file() and os.access(p,os.X_OK):binary=str(p);break
env={'os_release':Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else '',
 'architecture':__import__('platform').machine(),'effective_uid':os.geteuid() if hasattr(os,'geteuid') else None,
 'zeek_binary':binary or '', 'zeek_runnable':False,'version_stdout':'','version_stderr':'',
 'apt_get':shutil.which('apt-get') or '', 'dpkg_deb':shutil.which('dpkg-deb') or '',
 'free_working_bytes':shutil.disk_usage(WORK).free}
if binary:
 try:
  version=subprocess.run([binary,'--version'],text=True,capture_output=True,timeout=30)
  env.update({'zeek_runnable':version.returncode==0,'returncode':version.returncode,
   'version_stdout':version.stdout,'version_stderr':version.stderr})
 except Exception as error:env['binary_error']=str(error)
write_json(OUT/'extractor_environment.json',env)

# Only validate the paths already recorded by the completed trace-recovery step.
scenarios=pd.read_csv(ROOT/'scenario_label_evidence.csv',keep_default_na=False)
links=[]
for _,row in scenarios.iterrows():
 for role,col in [('capture','local_capture_paths'),('labeled_log','local_log_paths')]:
  for value in json.loads(row[col]):
   p=Path(value)
   item={'scenario':row['official_scenario'],'role':role,'path':str(p),'exists':p.is_file(),
    'bytes':p.stat().st_size if p.is_file() else None,'header_preview':''}
   if role=='labeled_log' and p.is_file():
    lines=[]
    with p.open('r',encoding='utf-8',errors='replace') as f:
     for i,line in enumerate(f):
      if i>40:break
      if line.startswith(('#separator','#fields','#types')):lines.append(line.rstrip())
      elif not line.startswith('#'):
       lines.append(line.rstrip());break
    item['header_preview']='\n'.join(lines)
   links.append(item)
pd.DataFrame(links).to_csv(OUT/'recorded_trace_paths_and_log_headers.csv',index=False)
receipt={'output_directory':str(OUT),'reused_rule_recovery_directory':str(ROOT),
 'publisher_rule_files_verified':len(verified),'distinct_rule_contents':len(unique),
 'missing_recorded_trace_paths':sum(not r['exists'] for r in links),'zeek_runnable':env['zeek_runnable'],
 'label_semantics_approved':False,'v1_v2_equivalence_approved':False,'clean_replay_completed':False,
 'models_trained':False,'attacks_executed':False,'NF_changed':False,
 'next_step':'Install/validate extractor if needed, interpret actual rules, then clean capture/log mapping.'}
write_json(OUT/'receipt.json',receipt)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(OUT.rglob('*')):
  if p.is_file():z.write(p,str(p.relative_to(OUT)))
with zipfile.ZipFile(package) as z:
 if z.testzip() is not None:raise RuntimeError('Review archive integrity failure.')
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package)},indent=2))
print('\nEXTRACTOR ENVIRONMENT\n'+json.dumps(env,indent=2))
print('\nEXACT UNIQUE LABEL RULES')
for h,value in unique.items():
 print('\nSHA256:',h,'SCENARIOS:',', '.join(value['scenarios']));print(value['text'])
print('\nFIRST TWO EXISTING LABELED-LOG HEADERS')
for row in [r for r in links if r['role']=='labeled_log' and r['exists']][:2]:
 print(row['path']);print(row['header_preview'])
print('\nPaste the receipt, environment and rule output. Existing experiments were not rerun.')
