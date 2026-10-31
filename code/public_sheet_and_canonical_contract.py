"""Two small completions: repair legitimate public-sheet redirects; canonical Conn::Info binding.
No original labels changed, no classifier training, no extraction, no attack.
"""
import hashlib,json,re,subprocess,zipfile
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlparse,urljoin
import pandas as pd
import requests

WORK=Path('/kaggle/working')
PREV=WORK/'TRACE_VERSION_SOURCE_20261011T185218378382Z'
OUT=WORK/('TRACE_PUBLIC_SOURCE_FIX_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
MAX_BYTES=8*1024**2
CORE=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SOURCE=Path('/opt/zeek/share/zeek/base/protocols/conn/main.zeek')
EXPECTED='952ee3a005f0f1a9ea50c655335a4c45096388212d8202e3cd8583082c0ab6f1'
PAGE='https://www.stratosphereips.org/datasets-iot23'
session=requests.Session();session.headers['User-Agent']='Metadata-only public research provenance retrieval'
redirects=[];retrieved=[];errors=[]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,o):p.write_text(json.dumps(o,indent=2,ensure_ascii=False),encoding='utf-8')
def allowed(url):
 u=urlparse(url);h=(u.hostname or '').lower()
 return u.scheme=='https' and (h in {'docs.google.com','drive.google.com','sheets.googleapis.com'} or h.endswith('.googleusercontent.com'))
def download_public(url,path):
 seen=[]
 for step in range(9):
  if not allowed(url):raise ValueError('Redirect outside public Google export hosts; no login or credentials used.')
  if url in seen:raise ValueError('Redirect loop.')
  seen.append(url)
  with session.get(url,stream=True,allow_redirects=False,timeout=(20,90))as r:
   if r.status_code in {301,302,303,307,308}:
    target=urljoin(url,r.headers.get('Location',''))
    redirects.append({'from_url':url,'status':r.status_code,'to_url':target,'allowed_public_host':allowed(target)})
    if not allowed(target):raise ValueError('Login/off-host redirect refused: '+target)
    url=target;continue
   r.raise_for_status();chunks=[];size=0
   for b in r.iter_content(65536):
    size+=len(b)
    if size>MAX_BYTES:raise ValueError('Public metadata exceeds 8 MiB cap.')
    chunks.append(b)
   data=b''.join(chunks)
   if not data:raise ValueError('Empty export.')
   if re.search(rb'<(?:!doctype|html|form)\b',data[:1000],re.I):raise ValueError('HTML/login page, not exported CSV.')
   path.write_bytes(data)
   return {'final_url':url,'bytes':size,'sha256':sha(path),'path':str(path),'authentication_used':False}
 raise ValueError('Too many redirects.')

errfile=PREV/'explicit_source_errors.csv'
if not errfile.is_file():raise FileNotFoundError(errfile)
old=pd.read_csv(errfile,keep_default_na=False)
urls=list(dict.fromkeys(old.loc[old.stage.eq('label_design_sheet'),'item'].tolist()))
if not urls:raise RuntimeError('No recorded sheet-export URLs; no guessed IDs introduced.')
for i,url in enumerate(urls):
 p=OUT/f'publisher_sheet_{i}.csv'
 try:
  result=download_public(url,p)
  table=pd.read_csv(p,keep_default_na=False)
  result.update({'requested_url':url,'rows':len(table),'columns':list(table.columns)})
  retrieved.append(result)
  # Show any rows actually naming relevant scenarios; absence is not fabricated away.
  cells=table.astype(str)
  mask=cells.apply(lambda c:c.str.contains(r'CTU-IoT-Malware-Capture-(?:1|3|7|8|9)-1',regex=True,case=False)).any(axis=1)
  table.loc[mask].to_csv(OUT/f'publisher_sheet_{i}_exact_scenario_mentions.csv',index=False)
  table.head(35).to_csv(OUT/f'publisher_sheet_{i}_preview.csv',index=False)
 except Exception as e:errors.append({'stage':'public_sheet','item':url,'error':f'{type(e).__name__}: {e}'})
pd.DataFrame(redirects).to_csv(OUT/'A_public_redirect_chain.csv',index=False)
dump(OUT/'A_public_sheet_receipts.json',retrieved)

# Bind declarations only to the connection log's Info record; no thresholds or packet structs.
if not SOURCE.is_file() or sha(SOURCE)!=EXPECTED:raise RuntimeError('Installed conn/main.zeek version changed; do not reuse previous source review.')
lines=SOURCE.read_text().splitlines()
start=next((i for i,line in enumerate(lines)if re.search(r'\btype\s+Info\s*:\s*record\s*\{',line)),None)
if start is None:raise RuntimeError('Conn::Info declaration not found.')
end=next((i for i in range(start+1,len(lines))if lines[i].strip()=='};'),None)
if end is None:raise RuntimeError('Conn::Info record boundary not found.')
version=subprocess.run(['/opt/zeek/bin/zeek','--version'],capture_output=True,text=True,timeout=30)
if version.returncode:raise RuntimeError('Zeek not runnable.')
V=version.stdout.strip()or version.stderr.strip()
expected_types={'duration':'interval','proto':'transport_proto',**{f:'count'for f in CORE if f not in {'duration','proto'}}}
units={'duration':'seconds',**{f:'packets'for f in ['orig_pkts','resp_pkts']},**{f:'bytes'for f in ['orig_bytes','resp_bytes','orig_ip_bytes','resp_ip_bytes','missed_bytes']},'proto':'transport protocol enum'}
channels={'duration':'timing',**{f:'directional_volume'for f in CORE if f not in {'duration','proto','missed_bytes'}},'proto':'protocol','missed_bytes':'capture_quality'}
rows=[]
for feature in CORE:
 positions=[i for i in range(start,end+1)if re.match(r'^\s*'+re.escape(feature)+r'\s*:',lines[i])]
 if len(positions)!=1:raise RuntimeError('Ambiguous Conn::Info field declaration: '+feature)
 i=positions[0];decl=lines[i]
 if '&log'not in decl or not re.match(r'^\s*'+re.escape(feature)+r'\s*:\s*'+expected_types[feature]+r'\b',decl):raise RuntimeError('Unexpected field type/log binding: '+feature)
 a=i
 while a>start and (lines[a-1].lstrip().startswith('##')or not lines[a-1].strip()):a-=1
 exact='\n'.join(lines[a:i+1])
 rows.append({'feature':feature,'record_type':'Conn::Info','extractor_version':V,'source_path':str(SOURCE),
  'source_sha256':EXPECTED,'start_line':a+1,'declaration_line':i+1,'exact_source_quote':exact,
  'zeek_type':expected_types[feature],'unit':units[feature],'candidate_channel':channels[feature],
  'role':'quality_metadata_not_attacker_optimized'if feature=='missed_bytes'else'candidate_predictor',
  'field_source_binding_verified':True,'attack_action_approved':False,
  'dependency_policy':'Re-extract from packets; no direct independent CSV mutation'if feature!='proto'else'Immutable under padding/pacing',
  'missing_value_policy':'Preserve missingness; source-training-only preprocessing must be specified before evaluation',
  'source_limit':'orig/resp_bytes use TCP sequence accounting; IP byte counters are not equal to payload counters; duration may exclude trailing nonproductive packets'})
pd.DataFrame(rows).to_csv(OUT/'B_canonical_Conn_Info_contract.csv',index=False)
(OUT/'B_bound_main.zeek').write_bytes(SOURCE.read_bytes())
report='# Canonical connection-log field contract\n\nAll excerpts are within Conn::Info, not similarly named fields in unrelated records.\n'
for r in rows:report+=f"\n## {r['feature']}\n{r['source_path']} / SHA256 {r['source_sha256']} / line {r['declaration_line']}\n\n```zeek\n{r['exact_source_quote']}\n```\n"
(OUT/'B_canonical_field_quotes.md').write_text(report,encoding='utf-8')

receipt={'output_directory':str(OUT),'public_sheet_exports_recovered':len(retrieved),'public_sheet_exports_requested':len(urls),
 'public_sheet_errors':len(errors),'canonical_Conn_Info_fields_bound':len(rows),'required_fields':len(CORE),
 'capture_quality_fields':['missed_bytes'],'field_binding_verified':len(rows)==len(CORE),
 'publisher_rules_applied':False,'v1_label_reproduction_proved':False,'published_labels_replaced':False,
 'per_record_publisher_identity_proved':False,'packet_transform_contract_approved':False,'primary_allocation_frozen':False,
 'models_trained':False,'attacks_executed':False,'Zeek_rerun':False,'NF_changed':False,
 'next_step':'Review recovered v1 label-design rows and verified Conn::Info bindings. Freeze admissible labels/actions/allocation explicitly before outcome evaluation.'}
dump(OUT/'receipt.json',receipt)
pd.DataFrame(errors,columns=['stage','item','error']).to_csv(OUT/'explicit_errors.csv',index=False)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED)as z:
 for p in sorted(OUT.iterdir()):
  if p.is_file():z.write(p,p.name)
with zipfile.ZipFile(package)as z:
 if z.testzip()is not None:raise RuntimeError('Review ZIP integrity failure.')
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package)},indent=2))
print('\nA — PUBLIC SHEET RECEIPTS\n'+json.dumps(retrieved,indent=2))
for i in range(len(urls)):
 p=OUT/f'publisher_sheet_{i}.csv'
 if p.is_file():
  t=pd.read_csv(p,keep_default_na=False);print('\nSHEET',i,'COLUMNS',list(t.columns));print(t.head(25).to_string(index=False))
  q=OUT/f'publisher_sheet_{i}_exact_scenario_mentions.csv';print('\nEXACT SCENARIO MENTIONS');print(q.read_text()[:16000])
print('\nB — CANONICAL CONN::INFO CONTRACT');print(pd.DataFrame(rows)[['feature','record_type','zeek_type','unit','candidate_channel','role','field_source_binding_verified','attack_action_approved']].to_string(index=False))
print('\nEXPLICIT ERRORS');print(pd.DataFrame(errors).to_string(index=False)if errors else'None')
print('\nUpload the small review ZIP if the sheet table is too wide; no model/capture upload needed.')
