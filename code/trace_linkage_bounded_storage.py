"""Bounded-storage linkage continuation. Full records, no SQLite indexes or sampling.
Completed 1/3 candidate receipts and Capture-8 replay are reused.
One scenario's compressed shards at a time; successful joins delete only temporary shards.
Existing scientific outputs/model bundles/source inputs are never removed.
"""
import csv,gzip,hashlib,json,os,re,resource,shutil,subprocess,time
from collections import Counter
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN,InvalidOperation
from pathlib import Path
import pandas as pd

WORK=Path('/kaggle/working')
OLD=WORK/'TRACE_LINKAGE_BATCH_v1'
SRC=WORK/'TRACE_LABEL_RECOVERY_20261011T153846517131Z'
PILOT=WORK/'TRACE_CLEAN_REPLAY_20261011T161846072286Z'
OUT=WORK/'TRACE_LINKAGE_STREAM_v2';OUT.mkdir(exist_ok=True)
CACHE=OUT/'temporary_shards';CACHE.mkdir(exist_ok=True)
ZEEK='/opt/zeek/bin/zeek'
SCENARIOS=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-7-1','CTU-IoT-Malware-Capture-8-1','CTU-IoT-Malware-Capture-9-1']
PREDICTORS=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto','conn_state','history']
NUMERIC=set(PREDICTORS[:8])
PARTITIONS=256
MAX_BUCKET_ROWS=300000
CACHE_BUDGET=3*1024**3
REPLAY_BUDGET=5*1024**3
MIN_FREE=4*1024**3
TIMEOUT=3600
RESULTS=[];RULE_SUMMARY=[];ERRORS=[]

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def key(row):
 micros=int((Decimal(row['ts'])*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
 return json.dumps([micros,row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower()],separators=(',',':'))
def stream(p):
 fields=None
 opener=gzip.open(p,'rt',encoding='utf-8')if p.name.endswith('.gz')else p.open('r',encoding='utf-8')
 with opener as f:
  for number,line in enumerate(f,1):
   if line.startswith('#fields'):
    fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   if fields is None:raise ValueError('Missing Zeek schema: '+str(p))
   values=line.strip().split()
   if len(values)!=len(fields):raise ValueError(f'Malformed log row: {p}:{number}')
   row=dict(zip(fields,values));row['_line']=number;yield row

def equal(field,a,b):
 if field in NUMERIC and a!='-'and b!='-':
  try:return Decimal(a)==Decimal(b)
  except InvalidOperation:return False
 return a==b

def parse_rules(text):
 rules=[];head=None;warnings=[]
 mapping={'srcIP':'id.orig_h','dstIP':'id.resp_h','srcPort':'id.orig_p','dstPort':'id.resp_p','Proto':'proto'}
 for number,line in enumerate(text.splitlines(),1):
  line=line.split('#',1)[0].strip()
  if not line:continue
  if re.search(r'xxx\.xxx\.xxx\.xxx|(?:srcPort|dstPort)\s*=\s*xx\b',line,re.I):raise ValueError('Placeholder rule refused.')
  if not line.startswith('-'):
   m=re.fullmatch(r'(Background|Benign|Malicious)(?:,\s*([^:]+?))?\s*:*',line)
   if not m:raise ValueError('Unsupported heading: '+line)
   if not line.endswith(':')or line.endswith('::'):warnings.append({'line':number,'text':line,'diagnostic_normalization_only':True})
   head=(m.group(1),(m.group(2)or'').strip());continue
  if head is None:raise ValueError('Rule without heading.')
  terms=[]
  for atom in line[1:].split('&'):
   m=re.fullmatch(r'\s*([A-Za-z]+)\s*=\s*([^\s&]+)\s*',atom)
   if not m or m.group(1)not in mapping:raise ValueError('Unsupported term: '+atom)
   terms.append((m.group(1),m.group(2)))
  rules.append((head,terms))
 return rules,warnings,mapping

def infer(row,rules,mapping):
 label='UNMATCHED'
 for head,terms in rules:
  ok=True
  for field,value in terms:
   actual=row[mapping[field]]
   if value.lower()=='all':continue
   if field=='Proto':equal0=actual.lower()==value.lower()
   elif field in {'srcPort','dstPort'}:
    try:equal0=int(actual)==int(value)
    except ValueError:equal0=False
   else:equal0=actual==value
   if not equal0:ok=False;break
  if ok:label=head[0].lower()
 return label


def atomic(p,obj):
 temp=p.with_suffix(p.suffix+'.partial');temp.write_text(json.dumps(obj,indent=2,ensure_ascii=False));temp.replace(p)
def folder_bytes(p):return sum(q.stat().st_size for q in p.rglob('*')if q.is_file() and not q.is_symlink())
def guard():
 free=shutil.disk_usage(WORK).free
 if free<MIN_FREE:raise RuntimeError(f'Free space safety stop: {free/1024**3:.2f} GiB; partial outputs preserved.')
 size=folder_bytes(CACHE)
 if size>CACHE_BUDGET:raise RuntimeError('Compressed temporary-shard budget exceeded; no sampling or silently incomplete result.')
def bucket(k):return hashlib.blake2b(k.encode(),digest_size=2).digest()[0]
def cache_remove(p):
 if not p.exists():return
 if p.is_symlink()or not p.resolve().is_relative_to(CACHE.resolve()):raise RuntimeError('Unsafe temporary-cache deletion refused.')
 shutil.rmtree(p)
def hasher_stream(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()

def partition(log,out,kind,rules,mapping):
 receipt=out/'partition_receipt.json'
 source_sha=sha(log)
 if receipt.exists():
  previous=json.loads(receipt.read_text())
  if previous['source_sha256']==source_sha and previous['complete']:
   for r in previous['shards']:
    q=out/r['file']
    if not q.is_file()or hasher_stream(q)!=r['sha256']:raise RuntimeError('Saved shard changed.')
   return previous
  raise RuntimeError('Existing shard receipt has incompatible source.')
 if out.exists():cache_remove(out)
 out.mkdir(parents=True)
 writers=[];rows=0;labels=Counter();confusion=Counter()
 try:
  soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
  if soft<1024 and hard>=1024:resource.setrlimit(resource.RLIMIT_NOFILE,(1024,hard))
  for n in range(PARTITIONS):writers.append(gzip.open(out/f'{n:03d}.jsonl.gz','wt',encoding='utf-8',compresslevel=1))
  for row in stream(log):
   k=key(row);features=[row[f]for f in PREDICTORS]
   label=row.get('label','');detail=row.get('detailed-label','')
   record=[k,features,row['_line'],label,detail]
   writers[bucket(k)].write(json.dumps(record,separators=(',',':'),ensure_ascii=False)+'\n');rows+=1
   if kind=='reference':
    if not label:raise RuntimeError('Primary supplied label absent.')
    labels[label.lower()]+=1;confusion[(label.lower(),infer(row,rules,mapping))]+=1
   if rows%250000==0:
    print(kind,log.parent.name,'PARTITIONED ROWS',rows,flush=True)
    for w in writers:w.flush()
    guard()
 finally:
  for w in writers:w.close()
 guard()
 shards=[{'file':q.name,'bytes':q.stat().st_size,'sha256':sha(q)}for q in sorted(out.glob('*.jsonl.gz'))]
 result={'source_sha256':source_sha,'complete':True,'rows':rows,'kind':kind,'shards':shards,
 'compressed_bytes':sum(r['bytes']for r in shards),'published_labels':dict(labels),
 'confusion':[{'published':a,'rule':b,'records':v}for(a,b),v in confusion.items()],
 'rule_agreements':sum(v for(a,b),v in confusion.items()if a==b)}
 atomic(receipt,result);return result

def load_bucket(path):
 lookup={};rows=0
 with gzip.open(path,'rt',encoding='utf-8')as f:
  for line in f:
   row=json.loads(line);rows+=1
   if rows>MAX_BUCKET_ROWS:raise RuntimeError('Bucket memory safety limit reached; no rows discarded.')
   k=row[0]
   if k in lookup:lookup[k][1]+=1
   else:lookup[k]=[row,1]
 return lookup

def extract(capture,job,cap_sha):
 pilot=json.loads((PILOT/'smoke_selection.json').read_text())
 if cap_sha==pilot['pcap_sha256']:return PILOT/'clean_replay/conn.log',True
 old_job=OLD/job.parent.name/cap_sha[:20]
 for base in [old_job,job]:
  marker=base/'extraction_complete.json';log=base/'replay/conn.log'
  if marker.exists()and log.is_file():
   saved=json.loads(marker.read_text())
   if saved.get('pcap_sha256')==cap_sha and saved.get('conn_log_sha256')==sha(log):return log,True
 replay=job/'replay';replay.mkdir(exist_ok=True)
 if list(replay.iterdir()):raise RuntimeError('Incomplete replay remains; do not mix attempts. Report this path: '+str(replay))
 guard();stdout=job/'zeek.log'
 print('EXTRACTING',job.parent.name,capture.name,'bytes',capture.stat().st_size,flush=True)
 with stdout.open('w')as f:
  process=subprocess.Popen([ZEEK,'-C','-r',str(capture)],cwd=replay,stdout=f,stderr=subprocess.STDOUT)
  start=time.monotonic()
  try:
   while process.poll() is None:
    time.sleep(5)
    if time.monotonic()-start>TIMEOUT:raise RuntimeError('Zeek timeout; partial extraction retained.')
    if shutil.disk_usage(WORK).free<MIN_FREE or folder_bytes(replay)>REPLAY_BUDGET:raise RuntimeError('Zeek storage safety stop before disk exhaustion.')
  except Exception:
   process.terminate()
   try:process.wait(timeout=30)
   except subprocess.TimeoutExpired:process.kill();process.wait()
   raise
 if process.returncode or not (replay/'conn.log').is_file():raise RuntimeError('Zeek failed; inspect '+str(stdout))
 log=replay/'conn.log';atomic(job/'extraction_complete.json',{'pcap_sha256':cap_sha,'conn_log_sha256':sha(log),'zeek_version':VERSION})
 return log,False

def lossless_archive_new_log(log,job):
 # Only this v2 job's own extracted conn.log is compacted; old completed logs are untouched.
 if log.parent!=job/'replay' or not log.is_file():return
 dest=job/'replay/conn.log.gz';partial=dest.with_suffix('.gz.partial')
 original=sha(log);guard()
 try:
  with log.open('rb')as source,gzip.open(partial,'wb',compresslevel=1)as target:
   total=0
   for block in iter(lambda:source.read(8*1024**2),b''):
    target.write(block);total+=len(block)
    if total%(128*1024**2)==0:guard()
  check=hashlib.sha256()
  with gzip.open(partial,'rb')as f:
   for b in iter(lambda:f.read(8*1024**2),b''):check.update(b)
  if check.hexdigest()!=original:raise RuntimeError('Lossless compressed replay verification failed.')
  partial.replace(dest)
  atomic(job/'compressed_replay_receipt.json',{'uncompressed_sha256':original,'compressed_sha256':sha(dest),'path':str(dest),'lossless_verified':True})
  log.unlink()
 except Exception:
  if partial.exists():partial.unlink()
  raise

v=subprocess.run([ZEEK,'--version'],capture_output=True,text=True,timeout=30)
if v.returncode:raise RuntimeError('Installed Zeek is not runnable.')
VERSION=v.stdout.strip()or v.stderr.strip()
policy={'scenarios':SCENARIOS,'candidate_predictors':PREDICTORS,'zeek_version':VERSION,
 'all_records':True,'sampling':False,'partitions':PARTITIONS,'temporary_cache_budget_bytes':CACHE_BUDGET,
 'minimum_free_bytes':MIN_FREE,'maximum_uncompressed_replay_bytes':REPLAY_BUDGET,
 'selection':'Reuse completed candidates; assess every remaining recorded PCAP separately; no merging or target-performance selection.'}
lock=OUT/'policy.json'
if lock.exists()and json.loads(lock.read_text())!=policy:raise RuntimeError('V2 policy changed; cannot mix results.')
if not lock.exists():atomic(lock,policy)
scenario_table=pd.read_csv(SRC/'scenario_label_evidence.csv',keep_default_na=False)
sources=pd.read_csv(SRC/'publisher_retrieval_receipts.csv',keep_default_na=False)

for name in SCENARIOS:
 refcache=CACHE/name/'reference'
 try:
  selected=scenario_table[scenario_table.official_scenario.eq(name)]
  if len(selected)!=1:raise RuntimeError('Recorded scenario ambiguous.')
  spec=selected.iloc[0];refs=[Path(p)for p in json.loads(spec['local_log_paths'])]
  captures=[Path(p)for p in json.loads(spec['local_capture_paths'])]
  if len(refs)!=1:raise RuntimeError('Exactly one reference log required.')
  reference=refs[0];ref_sha=sha(reference)
  source=sources[(sources.kind=='publisher_rules')&(sources.scenario==name)]
  if len(source)!=1:raise RuntimeError('Rule source ambiguous.')
  source=source.iloc[0];p=Path(source['path'])
  if sha(p)!=source['sha256']:raise RuntimeError('Rule source changed.')
  rules,warnings,mapping=parse_rules(p.read_text())
  scdir=OUT/name;scdir.mkdir(exist_ok=True)
  atomic(scdir/'rule_interpretation.json',{'source_sha256':source['sha256'],'heading_warnings':warnings,'publisher_parser_fidelity_verified':False})
  refinfo=None
  for capture in sorted(captures,key=lambda p:(p.stat().st_size,str(p))):
   try:
    cap_sha=sha(capture);job=scdir/cap_sha[:20];job.mkdir(exist_ok=True)
    # Reuse previously computed scientific results, not the deleted database caches.
    previous_paths=[job/'candidate_receipt.json',OLD/name/cap_sha[:20]/'candidate_receipt.json']
    previous=None
    for pp in previous_paths:
     if not pp.is_file():continue
     obj=json.loads(pp.read_text())
     if obj.get('status')=='FULL_LOG_LINKAGE_COMPUTED'and obj.get('pcap_sha256')==cap_sha and obj.get('reference_sha256')==ref_sha:
      linked=Path(obj['linked_records_path'])
      if not linked.is_file()or sha(linked)!=obj['linked_records_sha256']:raise RuntimeError('Saved linked-record output missing/changed.')
      previous={**obj,'computed_result_reused':True,'receipt_source':str(pp)};break
    if previous:
     RESULTS.append(previous);print(name,capture.name,'COMPLETED RESULT REUSED',flush=True);continue
    log,extraction_reused=extract(capture,job,cap_sha)
    if refinfo is None:
     refinfo=partition(reference,refcache,'reference',rules,mapping)
     atomic(scdir/'reference_summary.json',{**{k:v for k,v in refinfo.items()if k!='shards'},'source_rule_sha256':source['sha256'],'noncanonical_headers':len(warnings)})
    gencache=CACHE/name/cap_sha[:20]
    geninfo=partition(log,gencache,'generated',rules,mapping)
    final=job/'linked_records.csv.gz';partial=job/'linked_records.csv.gz.partial'
    fields=PREDICTORS+['published_label','published_detailed_label','reference_line','generated_line','source_scenario','pcap_sha256','reference_log_sha256']
    matches=0;unmatched=0;ambiguous=0;diff=Counter();labels=Counter()
    with gzip.open(partial,'wt',encoding='utf-8',newline='',compresslevel=1)as f:
     writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
     for n in range(PARTITIONS):
      refbucket=load_bucket(refcache/f'{n:03d}.jsonl.gz');genbucket=load_bucket(gencache/f'{n:03d}.jsonl.gz')
      for k,(g,ng)in genbucket.items():
       found=refbucket.get(k)
       if found is None:unmatched+=ng;continue
       r,nr=found
       if nr!=1 or ng!=1:ambiguous+=ng;continue
       matches+=1;labels[r[3].lower()]+=1
       for i,feature in enumerate(PREDICTORS):
        if not equal(feature,r[1][i],g[1][i]):diff[feature]+=1
       writer.writerow({**dict(zip(PREDICTORS,g[1])),'published_label':r[3],'published_detailed_label':r[4],
        'reference_line':r[2],'generated_line':g[2],'source_scenario':name,'pcap_sha256':cap_sha,'reference_log_sha256':ref_sha})
      del refbucket,genbucket
      if (n+1)%32==0:guard();print(name,capture.name,'JOINED PARTITIONS',n+1,'/',PARTITIONS,flush=True)
    partial.replace(final)
    result={'status':'FULL_LOG_LINKAGE_COMPUTED','scenario':name,'capture':str(capture),'pcap_sha256':cap_sha,'reference_sha256':ref_sha,
     'generated_log_sha256':geninfo['source_sha256'],'reference_rows':refinfo['rows'],'generated_rows':geninfo['rows'],
     'unique_exact_key_matches':matches,'unmatched_generated_rows':unmatched,'ambiguous_generated_rows':ambiguous,
     'full_reference_coverage':matches==refinfo['rows'],'full_generated_coverage':matches==geninfo['rows'],
     'predictor_difference_counts':dict(diff),'mapped_published_label_counts':dict(labels),
     'linked_records_path':str(final),'linked_records_sha256':sha(final),'linked_record_format':'gzip CSV',
     'extraction_reused':extraction_reused,'computed_result_reused':False,'source_rule_sha256':source['sha256'],
     'publisher_tool_fidelity_verified':False,'confirmatory_scenario_selected':False,'packet_validity_approved':False,
     'all_records_processed':True,'sampling':False,'join_method':'compressed hash-partition, exact original connection keys'}
    atomic(job/'candidate_receipt.json',result);RESULTS.append(result)
    cache_remove(gencache)
    # Compact the newly produced replay only after successful exact linkage.
    lossless_archive_new_log(log,job)
    print(name,capture.name,'MATCHES',matches,'/',geninfo['rows'],'DIFFERENCES',dict(diff),flush=True)
   except Exception as error:
    ERRORS.append({'scenario':name,'capture':str(capture),'error':f'{type(error).__name__}: {error}'})
    if shutil.disk_usage(WORK).free<MIN_FREE:raise RuntimeError('Storage safety stop; resolve explicitly, not by rerunning SQLite.')
  summaryfile=scdir/'reference_summary.json';oldref=OLD/name/'reference_index_receipt.json'
  if summaryfile.is_file():rs=json.loads(summaryfile.read_text());n=rs['rows'];agree=rs['rule_agreements'];pub=rs['published_labels']
  elif oldref.is_file():rs=json.loads(oldref.read_text());n=rs['rows'];agree=rs['rule_agreement'];pub=rs['published_labels']
  else:n=agree=None;pub={}
  RULE_SUMMARY.append({'scenario':name,'reference_rows':n,'rule_agreements':agree,'rule_agreement_fraction':agree/n if n else None,
   'published_label_counts':json.dumps(pub),'noncanonical_rule_headers':len(warnings)})
  cache_remove(CACHE/name)
 except Exception as error:ERRORS.append({'scenario':name,'capture':'SCENARIO_STAGE','error':f'{type(error).__name__}: {error}'})
 pd.DataFrame(RESULTS).to_csv(OUT/'candidate_linkage_summary.csv',index=False)
 pd.DataFrame(RULE_SUMMARY).to_csv(OUT/'scenario_rule_agreement.csv',index=False)
 pd.DataFrame(ERRORS,columns=['scenario','capture','error']).to_csv(OUT/'explicit_failures.csv',index=False)
 if shutil.disk_usage(WORK).free<MIN_FREE:break

summary=[]
for name in SCENARIOS:
 rows=[r for r in RESULTS if r['scenario']==name]
 faithful=[r for r in rows if r['full_reference_coverage']and r['full_generated_coverage']and not r['predictor_difference_counts']]
 summary.append({'scenario':name,'computed_candidates':len(rows),'full_bijection_predictor_fidelity_candidates':len(faithful),
 'status':'FULL_FIDELITY_CANDIDATE_FOR_REVIEW'if len(faithful)==1 else ('MULTIPLE_FULL_CANDIDATES_REVIEW'if faithful else 'LINKAGE_OR_FEATURE_DIFFERENCES_REMAIN'),
 'scientific_approval_automatic':False})
pd.DataFrame(summary).to_csv(OUT/'scenario_gate_summary.csv',index=False)
receipt={'output_directory':str(OUT),'computed_candidates':len(RESULTS),'completed_results_reused':sum(r.get('computed_result_reused',False)for r in RESULTS),
 'explicit_failure_records':len(ERRORS),'SQLite_used':False,'sampling_used':False,'free_GiB':round(shutil.disk_usage(WORK).free/1024**3,3),
 'remaining_temporary_cache_GiB':round(folder_bytes(CACHE)/1024**3,3),'models_trained':False,'attacks_executed':False,'NF_changed':False,
 'packet_validity_approved':False,'confirmatory_scenarios_selected':False}
atomic(OUT/'receipt.json',receipt)
print('\nSTREAMING BATCH RECEIPT\n'+json.dumps(receipt,indent=2))
print('\nSCENARIO GATES\n'+pd.DataFrame(summary).to_string(index=False))
print('\nRULE AGREEMENT\n'+pd.DataFrame(RULE_SUMMARY).to_string(index=False))
print('\nEXPLICIT FAILURES\n'+(pd.DataFrame(ERRORS).to_string(index=False)if ERRORS else 'None'))
