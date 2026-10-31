"""First unfinished plan-linked gate: recover actual IoT-23 label evidence.
Uses existing filesystem inventory. No wide re-audit, models, predictions or attacks.
Downloads only publisher directory pages, README and labeling-rule files.
Does NOT approve v1/v2 equivalence, flow mapping, labels, attacks, or confirmation.
"""
import hashlib,json,re,shutil,subprocess,zipfile
from collections import defaultdict
from datetime import datetime,timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin,urlparse,unquote
import pandas as pd
import requests

AUDIT=Path('/kaggle/working/PLAN_CLOSURE_AUDIT_20261011T152520447854Z')
INDEX=AUDIT/'filesystem_inventory.csv'
ASSET_INDEX=AUDIT/'raw_asset_inventory.csv'
ACTIVE=Path('/kaggle/working/resume_verified_20261011T144807877506Z')
WORK=Path('/kaggle/working')
OUT=WORK/('TRACE_LABEL_RECOVERY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)
OFFICIAL='https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/'
MAX_BYTES=8*1024**2
SESSION=requests.Session()
SESSION.headers['User-Agent']='Research asset provenance audit; no bulk capture downloads'
SCENARIO_RE=re.compile(r'CTU-(?:IoT-Malware|Honeypot)-Capture-\d+-\d+',re.I)

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def key(s):return re.sub(r'[^a-z0-9]','',s.lower())
def scenario(s):
 found=SCENARIO_RE.findall(str(s));return found[-1] if found else ''
def write_json(p,obj):p.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')

if not INDEX.is_file() or not ASSET_INDEX.is_file():raise FileNotFoundError('Required existing audit indexes not present.')
index=pd.read_csv(INDEX,keep_default_na=False)
assets=pd.read_csv(ASSET_INDEX,keep_default_na=False)
if 'locator' not in index or 'locator' not in assets:raise ValueError('Unexpected inventory schema.')

# Small, exact artifacts bypass the previous global metadata budget.
anchors=[]
for name in ['source_contract_coverage.csv','evaluation_receipt.json','boundary_result.json']:
 paths=[Path(s) for s in index.loc[index.locator.map(lambda s:Path(s).name==name),'locator']]
 for p in paths:
  if not p.is_file() or p.stat().st_size>1024**2:continue
  if name=='source_contract_coverage.csv' and str(ACTIVE) not in str(p):continue
  try:
   if p.suffix=='.json':
    obj=json.loads(p.read_text())
    if name=='evaluation_receipt.json' and not ('boundary_result' in obj or 'scoped_same_parent_boundary_evaluation_completed' in obj):continue
    anchors.append({'path':str(p),'sha256':sha(p),'name':name,'key_values':json.dumps(obj)})
   else:
    t=pd.read_csv(p,keep_default_na=False)
    anchors.append({'path':str(p),'sha256':sha(p),'name':name,'key_values':t.to_json(orient='records')})
  except Exception as e:anchors.append({'path':str(p),'name':name,'error':str(e)})
pd.DataFrame(anchors).to_csv(OUT/'known_completed_anchor_correction.csv',index=False)

# Accept dated *-labels.config names; the previous exact-basename asset regex missed them.
local_rules=[]
for value in index.locator:
 p=Path(value)
 if re.search(r'labels?\.config$',p.name,re.I) and p.is_file():
  local_rules.append({'scenario':scenario(str(p)),'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)})
pd.DataFrame(local_rules,columns=['scenario','path','bytes','sha256']).to_csv(OUT/'local_label_rules_recovered.csv',index=False)

local=defaultdict(lambda:{'captures':[],'logs':[]})
for value in assets.locator:
 if '!' in value:continue
 p=Path(value)
 sc=scenario(str(p))
 if not sc or not p.is_file():continue
 if re.search(r'\.pcap(?:ng)?(?:\.gz)?$',p.name,re.I):local[key(sc)]['captures'].append(str(p))
 elif re.search(r'(?:conn\.log|conn-log).*labeled$',p.name,re.I):local[key(sc)]['logs'].append(str(p))

class Links(HTMLParser):
 def __init__(self):super().__init__();self.urls=[]
 def handle_starttag(self,tag,attrs):
  if tag=='a':
   for k,v in attrs:
    if k=='href' and v:self.urls.append(v)

def download(url,path):
 if urlparse(url).scheme!='https' or urlparse(url).netloc!=urlparse(OFFICIAL).netloc:raise ValueError('Nonpublisher download refused.')
 with SESSION.get(url,stream=True,timeout=(15,60)) as r:
  r.raise_for_status()
  if urlparse(r.url).netloc!=urlparse(OFFICIAL).netloc:raise ValueError('Off-host redirect refused.')
  parts=[];n=0
  for b in r.iter_content(65536):
   n+=len(b)
   if n>MAX_BYTES:raise ValueError('Small-evidence download limit exceeded; no bulk file downloaded.')
   parts.append(b)
  data=b''.join(parts)
  if not data:raise ValueError('Empty response.')
  path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
  return {'url_requested':url,'url_final':r.url,'http_status':r.status_code,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'path':str(path),'retrieved_utc':datetime.now(timezone.utc).isoformat()},data

retrieval=[];errors=[];canonical={}
try:
 record,blob=download(OFFICIAL,OUT/'publisher_index.html');retrieval.append({**record,'kind':'publisher_index','scenario':''})
 parser=Links();parser.feed(blob.decode('utf-8','replace'))
 for href in parser.urls:
  url=urljoin(OFFICIAL,href);name=unquote(urlparse(url).path.rstrip('/').split('/')[-1])
  if SCENARIO_RE.fullmatch(name) and urlparse(url).netloc==urlparse(OFFICIAL).netloc and urlparse(url).path.startswith(urlparse(OFFICIAL).path):canonical[key(name)]=(name,url.rstrip('/')+'/')
except Exception as e:errors.append({'scenario':'','stage':'publisher_index','error':f'{type(e).__name__}: {e}'})

scenario_rows=[]
for sc_key,files in sorted(local.items()):
 name,url=canonical.get(sc_key,('', ''))
 row={'scenario_key':sc_key,'official_scenario':name,'local_pcaps':len(set(files['captures'])),'local_logs':len(set(files['logs'])),
      'local_capture_paths':json.dumps(sorted(set(files['captures']))),'local_log_paths':json.dumps(sorted(set(files['logs']))),
      'local_rule_files':sum(key(r['scenario'])==sc_key for r in local_rules),'publisher_rule_files_retrieved':0,
      'local_capture_log_mapping_verified':False,'publisher_local_version_equivalence_verified':False,
      'label_semantics_approved':False,'confirmatory_scenario_selected':False}
 if not url:
  row['status']='NO_EXACT_PUBLISHER_SCENARIO_LINK';scenario_rows.append(row);continue
 folder=OUT/'publisher_evidence'/name
 try:
  record,blob=download(url,folder/'directory_index.html');retrieval.append({**record,'kind':'scenario_index','scenario':name})
  parser=Links();parser.feed(blob.decode('utf-8','replace'))
  links=sorted(set(urljoin(url,h) for h in parser.urls))
  for linked in links:
   filename=unquote(urlparse(linked).path.split('/')[-1])
   if not re.search(r'labels?\.config$|^README\.(md|html)$',filename,re.I):continue
   if not urlparse(linked).path.startswith(urlparse(url).path):continue
   record,data=download(linked,folder/filename)
   is_rule=bool(re.search(r'labels?\.config$',filename,re.I))
   if is_rule and re.search(rb'<!doctype\s+html|<html\b',data[:1000],re.I):raise ValueError('Rule URL returned HTML; not accepted as labeling rules.')
   retrieval.append({**record,'kind':'publisher_rules' if is_rule else 'publisher_readme','scenario':name})
   if is_rule:
    row['publisher_rule_files_retrieved']+=1
    (folder/(filename+'.preview.txt')).write_text(data.decode('utf-8','replace')[:16000],encoding='utf-8')
  row['status']='PUBLISHER_RULE_EVIDENCE_ACQUIRED_NOT_YET_APPLIED' if row['publisher_rule_files_retrieved'] else 'NO_RULE_LINK_IN_INSPECTED_DIRECTORY'
 except Exception as e:
  row['status']='RETRIEVAL_INCOMPLETE';errors.append({'scenario':name,'stage':'scenario_evidence','error':f'{type(e).__name__}: {e}'})
 scenario_rows.append(row)

# Locate Zeek beyond PATH; do not install/change the environment in this step.
zeek=shutil.which('zeek') or shutil.which('bro')
if not zeek:
 for p in [Path('/opt/zeek/bin/zeek'),Path('/usr/local/zeek/bin/zeek'),Path('/usr/local/bin/zeek')]:
  if p.is_file():zeek=str(p);break
environment={'binary':zeek or '', 'version':'','runnable':False,'os_release':Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else '',
 'effective_uid':__import__('os').geteuid() if hasattr(__import__('os'),'geteuid') else None,'apt_get_found':bool(shutil.which('apt-get'))}
if zeek:
 try:
  r=subprocess.run([zeek,'--version'],text=True,capture_output=True,timeout=30)
  environment.update({'returncode':r.returncode,'version':r.stdout.strip() or r.stderr.strip(),'runnable':r.returncode==0})
 except Exception as e:environment['error']=str(e)
write_json(OUT/'extractor_environment.json',environment)
pd.DataFrame(retrieval).to_csv(OUT/'publisher_retrieval_receipts.csv',index=False)
pd.DataFrame(scenario_rows).to_csv(OUT/'scenario_label_evidence.csv',index=False)
pd.DataFrame(errors,columns=['scenario','stage','error']).to_csv(OUT/'retrieval_errors.csv',index=False)

receipt={'output_directory':str(OUT),'existing_audit_index_reused':True,'local_scenarios_with_trace_assets':len(local),
 'local_rule_files_found_including_dated_names':len(local_rules),
 'publisher_scenarios_with_rule_evidence':sum(r['publisher_rule_files_retrieved']>0 for r in scenario_rows),
 'publisher_rule_files_retrieved':sum(r['publisher_rule_files_retrieved'] for r in scenario_rows),'zeek_runnable':environment['runnable'],
 'label_rules_applied':False,'version_equivalence_verified':False,'clean_replay_completed':False,
 'trace_validity_approved':False,'models_trained':False,'predictions_computed':False,'attacks_executed':False,
 'NF_rerun':False,'retrieval_errors':len(errors),
 'next_gate':'Verify rule format/version and extractor environment, then clean capture-to-labeled-flow replay. No scenario selection by outcomes.'}
write_json(OUT/'receipt.json',receipt)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED,compresslevel=3) as z:
 for p in sorted(OUT.rglob('*')):
  if p.is_file():z.write(p,str(p.relative_to(OUT)))
with zipfile.ZipFile(package) as z:
 bad=z.testzip()
 if bad:raise RuntimeError('ZIP CRC failure: '+bad)
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package),'review_zip_CRC_verified':True},indent=2))
print('\nTRACE LABEL-EVIDENCE STATUS')
print(pd.DataFrame(scenario_rows).drop(columns=['local_capture_paths','local_log_paths']).to_string(index=False) if scenario_rows else 'No recognizable CTU trace scenario found in existing inventory.')
print('\nEXTRACTOR ENVIRONMENT');print(json.dumps(environment,indent=2))
print('\nACTUAL RULE PREVIEWS — first two downloaded rules; not assumed valid for local logs')
for p in list((OUT/'publisher_evidence').rglob('*.preview.txt'))[:2] if (OUT/'publisher_evidence').exists() else []:
 print('\n'+str(p));print(p.read_text()[:6000])
print('\nUpload the small private review ZIP; do not upload captures or model bundles.')
