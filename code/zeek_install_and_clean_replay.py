"""Zeek bootstrap + one clean replay linkage test. No training or attacks.
Official signed APT package; simulation blocks installed-package upgrades/removals.
Smoke capture is selected by file size only, not labels/model outcomes.
Published labels are joined only on unique exact connection keys; never inferred.
"""
import hashlib,json,os,re,shutil,subprocess,time,zipfile
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import pandas as pd
import requests

WORK=Path('/kaggle/working')
RECOVERY=WORK/'TRACE_LABEL_RECOVERY_20261011T153846517131Z'
if not (RECOVERY/'scenario_label_evidence.csv').is_file():raise FileNotFoundError(RECOVERY)
OUT=WORK/('TRACE_CLEAN_REPLAY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)
TOOLS=WORK/'trace_tools';TOOLS.mkdir(exist_ok=True)
MAX_REPLAY_SECONDS=900
MAX_REFERENCE_ROWS=1000000
MAX_GENERATED_ROWS=1000000
MIN_FREE_BYTES=2*1024**3
COMMANDS=[]

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def save_json(path,obj):path.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')
def run(cmd,name,cwd=None,timeout=600):
 logfile=OUT/(name+'.log');started=time.monotonic()
 env=os.environ.copy();env['DEBIAN_FRONTEND']='noninteractive'
 try:
  with logfile.open('w') as f:
   result=subprocess.run(cmd,cwd=cwd,stdout=f,stderr=subprocess.STDOUT,text=True,timeout=timeout,env=env)
  COMMANDS.append({'name':name,'command':cmd,'returncode':result.returncode,'seconds':time.monotonic()-started,'log':str(logfile)})
  if result.returncode:raise RuntimeError(f'{name} failed ({result.returncode}): '+logfile.read_text(errors='replace')[-5000:])
  return logfile.read_text(errors='replace')
 except subprocess.TimeoutExpired:
  COMMANDS.append({'name':name,'command':cmd,'returncode':'TIMEOUT','seconds':time.monotonic()-started,'log':str(logfile)})
  raise RuntimeError(f'{name} timeout; partial logs preserved in {logfile}')

def zeek_path():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
  if p and Path(p).is_file() and os.access(p,os.X_OK):return p
 return None

def get_logs(path,cap):
 rows=[];fields=None;total=0;complete=True;bad=0
 with path.open('r',encoding='utf-8',errors='strict') as f:
  for line_number,line in enumerate(f,1):
   if line.startswith('#fields'):
    fields=line.strip().split()[1:];continue
   if line.startswith('#') or not line.strip():continue
   if fields is None:raise ValueError('Missing #fields in '+str(path))
   if total>=cap:complete=False;break
   total+=1
   parts=line.rstrip().split()
   if len(parts)!=len(fields):bad+=1;continue
   row=dict(zip(fields,parts));row['_line']=line_number;rows.append(row)
 return rows,{'records_scanned':total,'complete_file_scanned':complete,'malformed_rows':bad,'fields':fields}

def connection_key(row):
 required=['ts','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto']
 if any(k not in row for k in required):raise ValueError('Required connection-key field absent.')
 micros=int((Decimal(row['ts'])*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN))
 return (micros,row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower())

receipt={'output_directory':str(OUT),'models_trained':False,'attacks_executed':False,'NF_changed':False,
 'confirmatory_scenario_selected':False,'label_rules_applied':False,'packet_validity_approved':False,
 'full_trace_mapping_approved':False,'purpose':'CLEAN_EXTRACTION_SMOKE_AND_EXACT_KEY_MAPPING_ONLY'}
try:
 # Explicitly mark placeholder rule files as unsuitable, without deleting/replacing them.
 sources=pd.read_csv(RECOVERY/'publisher_retrieval_receipts.csv',keep_default_na=False)
 rule_rows=[]
 for _,r in sources[sources.kind.eq('publisher_rules')].iterrows():
  p=Path(r['path'])
  if not p.is_file() or sha(p)!=r['sha256']:raise RuntimeError('Rule source hash mismatch: '+str(p))
  active=[line.split('#',1)[0].strip() for line in p.read_text().splitlines()]
  active=[line for line in active if line]
  placeholders=[line for line in active if re.search(r'xxx\.xxx\.xxx\.xxx|(?:srcPort|dstPort)\s*=\s*xx\b',line,re.I)]
  rule_rows.append({'scenario':r['scenario'],'source_sha256':r['sha256'],'active_placeholder_lines':len(placeholders),
   'status':'PLACEHOLDER_TEMPLATE_NOT_APPLICABLE' if placeholders else 'CONCRETE_RULES_REQUIRE_FIDELITY_REVIEW',
   'rules_verified_against_local_labels':False})
 pd.DataFrame(rule_rows).to_csv(OUT/'rule_applicability.csv',index=False)

 binary=zeek_path()
 if binary is None:
  release={}
  for line in Path('/etc/os-release').read_text().splitlines():
   if '=' in line:
    k,v=line.split('=',1);release[k]=v.strip('"')
  if release.get('ID')!='ubuntu' or release.get('VERSION_ID')!='24.04':raise RuntimeError('This verified installer is for the reported Ubuntu 24.04 environment only.')
  if os.geteuid()!=0:raise RuntimeError('Root privileges required for official package installation.')
  if not shutil.which('gpg'):raise RuntimeError('gpg missing; signed-repository bootstrap cannot proceed safely.')
  if shutil.disk_usage(WORK).free<MIN_FREE_BYTES:raise RuntimeError('Less than 2 GiB free before installation.')
  base='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/'
  response=requests.get(base+'Release.key',timeout=(20,90));response.raise_for_status()
  keyfile=TOOLS/'zeek_OBS_Release.key';keyfile.write_bytes(response.content)
  keyring=TOOLS/'zeek_OBS_keyring.gpg'
  run(['gpg','--batch','--yes','--dearmor','--output',str(keyring),str(keyfile)],'repository_key')
  key_info=run(['gpg','--show-keys','--with-colons',str(keyring)],'repository_fingerprints')
  # Repo trust is scoped to this source list, not installed as a global trust key.
  sourcelist=TOOLS/'zeek_sources.list'
  existing=Path('/etc/apt/sources.list').read_text() if Path('/etc/apt/sources.list').is_file() else ''
  sourcelist.write_text(existing+'\n'+f'deb [signed-by={keyring}] {base} /\n')
  opts=['-o',f'Dir::Etc::sourcelist={sourcelist}','-o','Dir::Etc::sourceparts=/etc/apt/sources.list.d']
  run(['apt-get',*opts,'update'],'apt_update',timeout=900)
  policy=run(['apt-cache',*opts,'policy','zeek-8.0'],'zeek_package_candidate')
  match=re.search(r'Candidate:\s*(\S+)',policy)
  if not match or match.group(1)=='(none)':raise RuntimeError('Official zeek-8.0 package candidate unavailable; no unpinned fallback used.')
  version=match.group(1);package='zeek-8.0='+version
  simulated=run(['apt-get',*opts,'--simulate','--no-install-recommends','install',package],'apt_simulation')
  if re.search(r'^Remv\s|^Inst\s+\S+\s+\[',simulated,re.M):raise RuntimeError('Installation would remove/upgrade an existing package; stopped to preserve environment.')
  save_json(OUT/'installation_lock.json',{'repository':base,'key_sha256':sha(keyfile),'key_fingerprints':key_info,
   'package':package,'existing_package_upgrades_allowed':False})
  run(['apt-get',*opts,'-y','--no-install-recommends','--no-upgrade','install',package],'apt_install',timeout=1800)
  binary=zeek_path()
  if not binary:raise RuntimeError('Package installed but Zeek executable not located.')
 version=run([binary,'--version'],'zeek_version',timeout=30).strip()
 receipt.update({'zeek_binary':binary,'zeek_version':version,'zeek_runnable':True})

 # Pick smallest one-PCAP / one-labelled-log entry: a mapping pilot, never a primary selection.
 scenarios=pd.read_csv(RECOVERY/'scenario_label_evidence.csv',keep_default_na=False)
 eligible=[]
 for _,r in scenarios.iterrows():
  caps=[Path(p) for p in json.loads(r['local_capture_paths'])]
  logs=[Path(p) for p in json.loads(r['local_log_paths'])]
  if len(caps)==1 and len(logs)==1 and caps[0].is_file() and logs[0].is_file():
   eligible.append((caps[0].stat().st_size,r['official_scenario'],caps[0],logs[0]))
 if not eligible:raise RuntimeError('No unambiguous local one-capture/one-log mapping pilot; no arbitrary merge performed.')
 _,name,capture,reference=min(eligible,key=lambda x:(x[0],x[1],str(x[2])))
 replay_dir=OUT/'clean_replay';replay_dir.mkdir()
 save_json(OUT/'smoke_selection.json',{'scenario':name,'capture':str(capture),'reference':str(reference),
  'selection_rule':'SMALLEST_CAPTURE_BYTES_AMONG_ONE_CAPTURE_ONE_LOG; NO LABEL_OR_MODEL_OUTCOME_SELECTION',
  'confirmatory_selection':False,'pcap_sha256':sha(capture),'reference_log_sha256':sha(reference),
  'checksum_policy':'-C: ignore checksum errors for capture/offload compatibility; NOT a packet-validity approval'})
 print('REPLAYING:',name,'CAPTURE BYTES:',capture.stat().st_size,flush=True)
 run([binary,'-C','-r',str(capture)],'zeek_clean_replay',cwd=replay_dir,timeout=MAX_REPLAY_SECONDS)
 generated=replay_dir/'conn.log'
 if not generated.is_file():raise RuntimeError('Zeek finished without conn.log; see replay log.')
 target,ref_info=get_logs(reference,MAX_REFERENCE_ROWS)
 reproduced,gen_info=get_logs(generated,MAX_GENERATED_ROWS)
 if ref_info['malformed_rows'] or gen_info['malformed_rows']:raise RuntimeError('Malformed log rows; parser must be repaired before mapping.')
 lookup=defaultdict(list);invalid_ref=0
 for row in target:
  try:lookup[connection_key(row)].append(row)
  except Exception:invalid_ref+=1
 gen_counts=Counter();invalid_generated=0
 for row in reproduced:
  try:gen_counts[connection_key(row)]+=1
  except Exception:invalid_generated+=1
 mapped=[];unmatched=0;ambiguous=0;field_diff=Counter()
 for row in reproduced:
  try:k=connection_key(row)
  except Exception:continue
  found=lookup.get(k,[])
  if not found:unmatched+=1;continue
  if len(found)!=1 or gen_counts[k]!=1:ambiguous+=1;continue
  supplied=found[0];label=supplied.get('label','')
  if not label:raise RuntimeError('Supplied label column absent; detailed-label is not used as a replacement.')
  item={'timestamp_microseconds':k[0],'orig_h':k[1],'orig_p':k[2],'resp_h':k[3],'resp_p':k[4],'proto':k[5],
   'generated_line':row['_line'],'reference_line':supplied['_line'],'published_label':label,
   'published_detailed_label':supplied.get('detailed-label',''),'generated_uid':row.get('uid',''),
   'reference_uid':supplied.get('uid','')}
  for f in ['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','conn_state','service','missed_bytes']:
   if f in row and f in supplied:
    item[f+'_generated']=row[f];item[f+'_reference']=supplied[f]
    if row[f]!=supplied[f]:field_diff[f]+=1
  mapped.append(item)
 pd.DataFrame(mapped).to_csv(OUT/'unique_exact_key_mapping.csv',index=False)
 receipt.update({'status':'CLEAN_REPLAY_AND_MAPPING_SMOKE_COMPUTED','scenario':name,
  'reference_scan':ref_info,'generated_scan':gen_info,'unique_exact_key_matches':len(mapped),
  'unmatched_generated_rows':unmatched,'ambiguous_generated_rows':ambiguous,
  'invalid_reference_keys':invalid_ref,'invalid_generated_keys':invalid_generated,
  'match_fraction_of_parsed_generated_rows':len(mapped)/len(reproduced) if reproduced else None,
  'mapped_field_string_differences':dict(field_diff),
  'placeholder_rule_scenarios':sum(r['active_placeholder_lines']>0 for r in rule_rows),
  'concrete_rule_scenarios_pending_review':sum(r['active_placeholder_lines']==0 for r in rule_rows),
  'label_semantics_approved':False,'full_trace_mapping_approved':False,
  'next_step':'Review mapping completeness, version differences and actual labels. Then resolve eligible scenarios; no training yet.'})
except Exception as error:
 receipt.update({'status':'BLOCKED_WITH_EXPLICIT_CAUSE','error':f'{type(error).__name__}: {error}',
  'next_step':'Resolve this exact recorded error; do not repeat completed development experiments.'})
finally:
 save_json(OUT/'command_receipts.json',COMMANDS);save_json(OUT/'receipt.json',receipt)
 print('\nSTEP RECEIPT\n'+json.dumps(receipt,indent=2))
 if (OUT/'rule_applicability.csv').is_file():
  print('\nLABEL-RULE APPLICABILITY');print(pd.read_csv(OUT/'rule_applicability.csv').to_string(index=False))
 # Small review package excludes PCAPs and full generated connection logs.
 package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
 with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
  for p in OUT.iterdir():
   if p.is_file() and p.stat().st_size<=32*1024**2:z.write(p,p.name)
 with zipfile.ZipFile(package) as z:
  if z.testzip() is not None:raise RuntimeError('Review ZIP integrity failure.')
 print('\nPRIVATE REVIEW ZIP:',package,'SHA256:',sha(package))
 print('Paste STEP RECEIPT; if blocked, also paste the failed-command log tail.')
