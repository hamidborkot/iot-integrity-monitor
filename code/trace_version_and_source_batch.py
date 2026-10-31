"""Paired provenance completion work: official v1 label documentation + installed Zeek field evidence.
No captures/logs downloaded, source labels changed, extraction rerun, models or attacks.
Counts corroborate a release; do not claim per-record identity or parser reproduction.
"""
import hashlib,json,re,subprocess,zipfile
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlparse,parse_qs,urljoin,urlencode
import pandas as pd
import requests
from bs4 import BeautifulSoup

WORK=Path('/kaggle/working');STREAM=WORK/'TRACE_LINKAGE_STREAM_v2';OLD=WORK/'TRACE_LINKAGE_BATCH_v1'
OUT=WORK/('TRACE_VERSION_SOURCE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
SCENARIOS=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-7-1','CTU-IoT-Malware-Capture-8-1','CTU-IoT-Malware-Capture-9-1']
CORE=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
PAGE='https://www.stratosphereips.org/datasets-iot23';LIMIT=8*1024**2
session=requests.Session();session.headers['User-Agent']='Research source provenance; metadata-only retrieval'
retrieval=[];errors=[]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,o):p.write_text(json.dumps(o,indent=2,ensure_ascii=False),encoding='utf-8')
def fetch(url,path,allowed_hosts):
 if urlparse(url).scheme!='https' or urlparse(url).netloc not in allowed_hosts:raise ValueError('Unapproved metadata host.')
 with session.get(url,stream=True,timeout=(20,90)) as r:
  r.raise_for_status();chunks=[];size=0
  if urlparse(r.url).netloc not in allowed_hosts:raise ValueError('Unexpected redirect host; no login/auth bypass.')
  for b in r.iter_content(65536):
   size+=len(b)
   if size>LIMIT:raise ValueError('Metadata download cap reached; no dataset downloaded.')
   chunks.append(b)
  data=b''.join(chunks)
  if not data:raise ValueError('Empty response.')
  path.write_bytes(data)
  retrieval.append({'requested_url':url,'final_url':r.url,'status':r.status_code,'bytes':size,'sha256':sha(path),'path':str(path)})
  return data

# A1: archive the actual publisher v1 page and its exact capture-specific label table.
release=[];quotes=[];sheet_links=[]
try:
 blob=fetch(PAGE,OUT/'official_v1_dataset_page.html',{'www.stratosphereips.org','stratosphereips.org'})
 soup=BeautifulSoup(blob,'html.parser');text=soup.get_text('\n',strip=True)
 (OUT/'official_v1_dataset_page.txt').write_text(text,encoding='utf-8')
 for line in text.splitlines():
  if any(term in line.lower() for term in ['version 1.0.0','flaber','labels were assigned','analyst','labeling rules']):quotes.append({'source_url':PAGE,'source_sha256':sha(OUT/'official_v1_dataset_page.html'),'exact_text':line})
 for name in SCENARIOS:
  head=next((h for h in soup.find_all(['h1','h2','h3','h4'])if h.get_text(' ',strip=True).startswith(name)),None)
  if head is None:errors.append({'stage':'v1_capture_table','item':name,'error':'Exact capture heading not found'});continue
  found=None
  for element in head.find_all_next():
   if element.name in ['h1','h2'] and name not in element.get_text(' ',strip=True):break
   if element.name=='table':found=element;break
  if found is None:errors.append({'stage':'v1_capture_table','item':name,'error':'Label table not located; counts not invented'});continue
  counts={}
  for tr in found.find_all('tr'):
   cells=[c.get_text(' ',strip=True)for c in tr.find_all(['td','th'])]
   if len(cells)<2:continue
   number=cells[-1].replace(',','').replace(' ','')
   if not number.isdigit():continue
   counts[cells[0]]=int(number)
  if not counts or 'Benign'not in counts:errors.append({'stage':'v1_capture_table','item':name,'error':'Could not parse exact published label counts'});continue
  p=STREAM/name/'reference_summary.json'
  if not p.is_file():p=OLD/name/'reference_index_receipt.json'
  local=json.loads(p.read_text());binary=local['published_labels']
  official_b=counts['Benign'];official_m=sum(v for k,v in counts.items()if k!='Benign')
  release.append({'scenario':name,'official_v1_benign':official_b,'official_v1_nonbenign':official_m,
   'local_benign':binary.get('benign',0),'local_malicious':binary.get('malicious',0),
   'official_total':sum(counts.values()),'local_total':local['rows'],
   'aggregate_counts_match':official_b==binary.get('benign')and official_m==binary.get('malicious')and sum(counts.values())==local['rows'],
   'per_record_publisher_identity_proved':False,'official_detailed_label_counts':json.dumps(counts),
   'source_url':PAGE,'source_sha256':sha(OUT/'official_v1_dataset_page.html'),
   'table_quote':found.get_text(' | ',strip=True)})
 for a in soup.find_all('a',href=True):
  linked=urljoin(PAGE,a['href'])
  if urlparse(linked).netloc=='docs.google.com' and '/spreadsheets/d/'in urlparse(linked).path:
   sheet_links.append({'url':linked,'anchor_text':a.get_text(' ',strip=True)})
 # A2: archive the publisher-linked labeling design sheet, without treating it as executable rules.
 unique=[]
 for row in sheet_links:
  if row['url']not in [x['url']for x in unique]:unique.append(row)
 for i,row in enumerate(unique[:2]):
  link=row['url'];u=urlparse(link);m=re.search(r'/spreadsheets/d/([^/]+)',u.path)
  if not m:continue
  gid=parse_qs(u.fragment).get('gid',['0'])[0]
  export='https://docs.google.com/spreadsheets/d/'+m.group(1)+'/export?'+urlencode({'format':'csv','gid':gid})
  try:
   data=fetch(export,OUT/f'publisher_linked_label_design_{i}.csv',{'docs.google.com','doc-0s-00-sheets.googleusercontent.com','drive.google.com'})
   if data.lstrip().startswith((b'<!DOCTYPE',b'<html',b'<!doctype')):raise ValueError('Export returned HTML/login page; not label-design data.')
  except Exception as e:errors.append({'stage':'label_design_sheet','item':export,'error':str(e)})
except Exception as e:errors.append({'stage':'official_v1_page','item':PAGE,'error':f'{type(e).__name__}: {e}'})
pd.DataFrame(release).to_csv(OUT/'A_v1_release_label_count_reconciliation.csv',index=False)
pd.DataFrame(quotes).to_csv(OUT/'A_actual_publisher_labeling_quotes.csv',index=False)
pd.DataFrame(sheet_links).to_csv(OUT/'A_publisher_linked_design_sources.csv',index=False)

# B: bind each proposed core field to exact installed Zeek source, not guessed descriptions.
zeek=Path('/opt/zeek/bin/zeek')
version=subprocess.run([str(zeek),'--version'],capture_output=True,text=True,timeout=30)
if version.returncode:raise RuntimeError('Installed Zeek not runnable; no source-version binding.')
installed_version=version.stdout.strip()or version.stderr.strip()
roots=[Path('/opt/zeek/share/zeek/base/protocols/conn'),Path('/opt/zeek/share/zeek/base/init-bare.zeek')]
paths=[]
for root in roots:
 if root.is_dir():paths.extend(root.rglob('*.zeek'))
 elif root.is_file():paths.append(root)
source_rows=[];coverage=[];snap=OUT/'installed_source';snap.mkdir()
for feature in CORE:
 matches=[]
 for path in sorted(set(paths)):
  lines=path.read_text(encoding='utf-8').splitlines()
  for i,line in enumerate(lines):
   if not re.match(r'^\s*'+re.escape(feature)+r'\s*:',line):continue
   start=i
   while start>0 and (lines[start-1].lstrip().startswith('##')or not lines[start-1].strip()):start-=1
   quote='\n'.join(lines[start:min(len(lines),i+6)])
   record={'feature':feature,'installed_version':installed_version,'source_path':str(path),'source_sha256':sha(path),
    'start_line':start+1,'declaration_line':i+1,'exact_source_quote':quote,
    'source_excerpt_found':True,'operational_mapping_final_approved':False}
   source_rows.append(record);matches.append(record)
   copy=snap/(sha(path)+'_'+path.name)
   if not copy.exists():copy.write_bytes(path.read_bytes())
 coverage.append({'feature':feature,'exact_installed_declaration_excerpts':len(matches),'installed_source_evidence_found':bool(matches),
  'review_required':True,'packet_transform_approved':False})
pd.DataFrame(source_rows).to_csv(OUT/'B_exact_installed_field_source.csv',index=False)
pd.DataFrame(coverage).to_csv(OUT/'B_installed_field_coverage.csv',index=False)
report='# Actual installed Zeek core-field source\n\n'
for row in source_rows:
 report+=f"\n## {row['feature']}\nVersion: {row['installed_version']}\nSource: {row['source_path']}\nSHA256: {row['source_sha256']}\nLines: {row['start_line']}–{row['declaration_line']}\n\n```zeek\n{row['exact_source_quote']}\n```\n"
(OUT/'B_SOURCE_QUOTES.md').write_text(report,encoding='utf-8')
pd.DataFrame(retrieval).to_csv(OUT/'download_receipts.csv',index=False)
pd.DataFrame(errors,columns=['stage','item','error']).to_csv(OUT/'explicit_source_errors.csv',index=False)
receipt={'output_directory':str(OUT),'paired_work':['OFFICIAL_V1_LABEL_PROVENANCE','INSTALLED_ZEEK_CORE_FIELD_SOURCE'],
 'official_capture_tables_reconciled':len(release),'aggregate_label_counts_matching':sum(r['aggregate_counts_match']for r in release),
 'core_fields_with_installed_source_excerpts':sum(r['installed_source_evidence_found']for r in coverage),
 'core_fields_required':len(CORE),'source_error_records':len(errors),'Zeek_version':installed_version,
 'v2_rule_disagreements_erased':False,'published_labels_replaced':False,
 'per_record_publisher_identity_proved':False,'label_rule_reproduction_claim_allowed':False,
 'feature_contract_final_approved':False,'models_trained':False,'attacks_executed':False,'Zeek_rerun':False,'NF_changed':False,
 'next_step':'Review exact v1 label provenance and installed field definitions. Then resolve/document the primary-label policy and source-backed trace allocation/action contract; no silently changed plan.'}
dump(OUT/'receipt.json',receipt)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED)as z:
 for p in sorted(OUT.rglob('*')):
  if p.is_file():z.write(p,str(p.relative_to(OUT)))
with zipfile.ZipFile(package)as z:
 if z.testzip()is not None:raise RuntimeError('Review ZIP integrity failure.')
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package)},indent=2))
print('\nA — V1 RELEASE LABEL COUNT RECONCILIATION');print(pd.DataFrame(release).drop(columns=['table_quote','source_sha256','official_detailed_label_counts'],errors='ignore').to_string(index=False))
print('\nA — EXACT PUBLISHER LABELING QUOTES');print(pd.DataFrame(quotes).to_string(index=False))
print('\nB — INSTALLED SOURCE COVERAGE');print(pd.DataFrame(coverage).to_string(index=False))
print('\nB — ACTUAL FIELD DEFINITIONS\n'+report)
print('\nEXPLICIT SOURCE ERRORS');print(pd.DataFrame(errors).to_string(index=False)if errors else'None')
