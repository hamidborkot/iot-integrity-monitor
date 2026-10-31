"""Resumable full-log linkage expansion for all five concrete-rule scenarios.
Streaming SQLite joins avoid loading giant connection logs into RAM.
No models, attacks, label replacement, or outcome-driven scenario selection.
Capture 8 replay is reused. Every listed candidate for other scenarios is assessed separately.
"""
import csv,hashlib,json,os,re,shutil,sqlite3,subprocess
from collections import Counter
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN,InvalidOperation
from pathlib import Path
import pandas as pd

WORK=Path('/kaggle/working')
SRC=WORK/'TRACE_LABEL_RECOVERY_20261011T153846517131Z'
PILOT=WORK/'TRACE_CLEAN_REPLAY_20261011T161846072286Z'
OUT=WORK/'TRACE_LINKAGE_BATCH_v1';OUT.mkdir(exist_ok=True)
ZEEK='/opt/zeek/bin/zeek'
SCENARIOS=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-7-1','CTU-IoT-Malware-Capture-8-1','CTU-IoT-Malware-Capture-9-1']
PREDICTORS=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto','conn_state','history']
NUMERIC=set(PREDICTORS[:8])
EXCLUDED=['uid','service','local_orig','local_resp','tunnel_parents','ip_proto','id.orig_h','id.resp_h','id.orig_p','id.resp_p','ts']
MAX_REPLAY_SECONDS=1800
BATCH=5000

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def dump(p,obj):p.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')
def key(row):
 micros=int((Decimal(row['ts'])*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
 return json.dumps([micros,row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower()],separators=(',',':'))
def stream(p):
 fields=None
 with p.open('r',encoding='utf-8') as f:
  for number,line in enumerate(f,1):
   if line.startswith('#fields'):
    fields=line.strip().split()[1:];continue
   if line.startswith('#') or not line.strip():continue
   if fields is None:raise ValueError('Missing Zeek schema: '+str(p))
   values=line.strip().split()
   if len(values)!=len(fields):raise ValueError(f'Malformed log row: {p}:{number}')
   row=dict(zip(fields,values));row['_line']=number;yield row

def equal(field,a,b):
 if field in NUMERIC and a!='-' and b!='-':
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
   match=re.fullmatch(r'(Background|Benign|Malicious)(?:,\s*([^:]+?))?\s*:*',line)
   if not match:raise ValueError('Unsupported label heading: '+line)
   if not line.endswith(':') or line.endswith('::'):
    warnings.append({'line':number,'source_text':line,'issue':'NONCANONICAL_HEADING_INTERPRETED_DIAGNOSTICALLY; publisher-parser fidelity not approved'})
   head=(match.group(1),(match.group(2)or'').strip());continue
  if head is None:raise ValueError('Rule without heading.')
  terms=[]
  for atom in line[1:].split('&'):
   m=re.fullmatch(r'\s*([A-Za-z]+)\s*=\s*([^\s&]+)\s*',atom)
   if not m or m.group(1)not in mapping:raise ValueError('Unsupported rule expression: '+atom)
   terms.append((m.group(1),m.group(2)))
  rules.append((head,terms))
 return rules,warnings,mapping

def infer(row,rules,mapping):
 label='UNMATCHED'
 for head,terms in rules:
  good=True
  for field,value in terms:
   actual=row[mapping[field]]
   if value.lower()=='all':continue
   if field=='Proto':ok=actual.lower()==value.lower()
   elif field in {'srcPort','dstPort'}:
    try:ok=int(actual)==int(value)
    except ValueError:ok=False
   else:ok=actual==value
   if not ok:good=False;break
  if good:label=head[0].lower()
 return label

version=subprocess.run([ZEEK,'--version'],capture_output=True,text=True,timeout=30)
if version.returncode:raise RuntimeError('Previously installed Zeek is not runnable.')
policy={'scenarios':SCENARIOS,'candidate_predictors':PREDICTORS,'excluded_or_metadata_only':EXCLUDED,
 'selection':'All five prelisted concrete-rule scenarios; every recorded PCAP candidate assessed separately, no merging and no target performance selection.',
 'checksum_policy':'Ignore capture checksums (-C), not packet-validity certification',
 'zeek_version':version.stdout.strip() or version.stderr.strip(),
 'label_source':'Supplied expert labels attached only to unique exact-key matches. Rule results remain a separate diagnostic.',
 'publisher_tool_fidelity_verified':False}
lock=OUT/'batch_policy.json'
if lock.exists() and json.loads(lock.read_text())!=policy:raise RuntimeError('Existing batch policy differs; do not mix versions.')
if not lock.exists():dump(lock,policy)
scenarios=pd.read_csv(SRC/'scenario_label_evidence.csv',keep_default_na=False)
source=pd.read_csv(SRC/'publisher_retrieval_receipts.csv',keep_default_na=False)
results=[];failures=[];rule_results=[]

for name in SCENARIOS:
 try:
  matches=scenarios[scenarios.official_scenario.eq(name)]
  if len(matches)!=1:raise ValueError('Ambiguous/missing recorded scenario.')
  row=matches.iloc[0];refs=[Path(x)for x in json.loads(row['local_log_paths'])]
  caps=[Path(x)for x in json.loads(row['local_capture_paths'])]
  if len(refs)!=1 or not refs[0].is_file():raise ValueError('Exactly one supplied labelled log required.')
  reference=refs[0];rp=source[(source.scenario==name)&(source.kind=='publisher_rules')]
  if len(rp)!=1:raise ValueError('Exactly one publisher rule source required.')
  rp=rp.iloc[0];rulefile=Path(rp['path'])
  if sha(rulefile)!=rp['sha256']:raise ValueError('Rule source changed.')
  rules,warnings,mapping=parse_rules(rulefile.read_text())
  scenario_dir=OUT/name;scenario_dir.mkdir(exist_ok=True)
  dump(scenario_dir/'rule_interpretation.json',{'source_sha256':rp['sha256'],'heading_warnings':warnings,
    'rule_count':len(rules),'publisher_tool_fidelity_verified':False,'diagnostic_only':True})
  ref_sha=sha(reference);dbfile=scenario_dir/'reference_keys.sqlite'
  db_receipt=scenario_dir/'reference_index_receipt.json'
  cached=None
  if dbfile.exists() and db_receipt.exists():
   cached=json.loads(db_receipt.read_text())
   if cached.get('reference_sha256')!=ref_sha or not cached.get('complete'):raise ValueError('Reference index invalid; do not reuse.')
  elif dbfile.exists():raise ValueError('Incomplete reference index present; preserve it and report this blocker.')
  conn=sqlite3.connect(dbfile);conn.execute('PRAGMA temp_store=FILE');conn.execute('PRAGMA synchronous=NORMAL')
  if cached is None:
   conn.execute('CREATE TABLE ref(k TEXT PRIMARY KEY,n INTEGER,payload TEXT)')
   pending=[];counts=Counter();confusion=Counter();total=0
   for r in stream(reference):
    if 'label'not in r:raise ValueError('Primary label field missing; do not substitute detailed-label.')
    observed=r['label'].lower();pred=infer(r,rules,mapping)
    counts[observed]+=1;confusion[(observed,pred)]+=1;total+=1
    pending.append((key(r),1,json.dumps(r,separators=(',',':'))))
    if len(pending)>=BATCH:
     conn.executemany('INSERT INTO ref VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',pending);conn.commit();pending=[]
     if total%250000==0:print(name,'REFERENCE ROWS',total,flush=True)
     if shutil.disk_usage(WORK).free<1024**3:raise RuntimeError('Free disk below 1 GiB; stopped before exhausting storage.')
   if pending:conn.executemany('INSERT INTO ref VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',pending);conn.commit()
   cached={'reference_sha256':ref_sha,'complete':True,'rows':total,'published_labels':dict(counts),
    'rule_agreement':sum(v for (a,b),v in confusion.items()if a==b),'confusion':[{'published':a,'rule':b,'records':v}for (a,b),v in confusion.items()]}
   dump(db_receipt,cached)
  rule_results.append({'scenario':name,'reference_rows':cached['rows'],'rule_agreements':cached['rule_agreement'],
   'rule_agreement_fraction':cached['rule_agreement']/cached['rows'] if cached['rows'] else None,
   'noncanonical_rule_headers':len(warnings),'published_label_counts':json.dumps(cached['published_labels'])})
  pd.DataFrame(cached['confusion']).to_csv(scenario_dir/'rule_binary_confusion.csv',index=False)

  for capture in sorted(caps,key=lambda p:(p.stat().st_size if p.exists()else float('inf'),str(p))):
   try:
    if not capture.is_file():raise FileNotFoundError(capture)
    cap_sha=sha(capture);job=scenario_dir/cap_sha[:20];job.mkdir(exist_ok=True)
    completed=job/'candidate_receipt.json'
    if completed.exists():
     previous=json.loads(completed.read_text())
     if previous.get('reference_sha256')!=ref_sha or previous.get('pcap_sha256')!=cap_sha:raise ValueError('Cached job input mismatch.')
     if previous.get('status')=='FULL_LOG_LINKAGE_COMPUTED':results.append(previous);print(name,capture.name,'REUSED',flush=True);continue
    pilot=json.loads((PILOT/'smoke_selection.json').read_text())
    if cap_sha==pilot['pcap_sha256'] and ref_sha==pilot['reference_log_sha256']:
     generated=PILOT/'clean_replay/conn.log';reused=True
    else:
     existing_done=job/'extraction_complete.json';replaydir=job/'replay';replaydir.mkdir(exist_ok=True)
     generated=replaydir/'conn.log';reused=existing_done.exists()
     if reused:
      info=json.loads(existing_done.read_text())
      if not generated.is_file() or sha(generated)!=info['conn_log_sha256']:raise ValueError('Saved extracted log changed.')
     else:
      print('EXTRACTING',name,capture.name,capture.stat().st_size,'bytes',flush=True)
      with (job/'zeek.log').open('w')as log:
       try:r=subprocess.run([ZEEK,'-C','-r',str(capture)],cwd=replaydir,stdout=log,stderr=subprocess.STDOUT,timeout=MAX_REPLAY_SECONDS)
       except subprocess.TimeoutExpired:raise RuntimeError('Zeek timeout; partial logs preserved, no completion claimed.')
      if r.returncode or not generated.is_file():raise RuntimeError('Zeek failed; inspect '+str(job/'zeek.log'))
      dump(existing_done,{'pcap_sha256':cap_sha,'conn_log_sha256':sha(generated),'zeek_version':policy['zeek_version']})
    # Per-candidate generated-key table is disk-backed; references are never merged or relabelled.
    conn.execute('DROP TABLE IF EXISTS gen');conn.execute('CREATE TABLE gen(k TEXT PRIMARY KEY,n INTEGER,payload TEXT)')
    pending=[];genrows=0
    for g in stream(generated):
     pending.append((key(g),1,json.dumps(g,separators=(',',':'))));genrows+=1
     if len(pending)>=BATCH:
      conn.executemany('INSERT INTO gen VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',pending);conn.commit();pending=[]
    if pending:conn.executemany('INSERT INTO gen VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',pending);conn.commit()
    matched=0;diff=Counter();new_labels=Counter();rule_invariance=0
    fields=PREDICTORS+['published_label','published_detailed_label','reference_line','generated_line','source_scenario','pcap_sha256','reference_log_sha256']
    with (job/'linked_records.csv').open('w',newline='')as f:
     writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
     for rp0,gp0 in conn.execute('SELECT ref.payload,gen.payload FROM ref JOIN gen USING(k) WHERE ref.n=1 AND gen.n=1'):
      ref=json.loads(rp0);g=json.loads(gp0);matched+=1
      for feature in PREDICTORS:
       if feature not in ref or feature not in g:raise ValueError('Candidate predictor absent: '+feature)
       if not equal(feature,ref[feature],g[feature]):diff[feature]+=1
      if infer(ref,rules,mapping)!=infer(g,rules,mapping):rule_invariance+=1
      label=ref['label'];new_labels[label.lower()]+=1
      writer.writerow({**{feature:g[feature]for feature in PREDICTORS},'published_label':label,
       'published_detailed_label':ref.get('detailed-label',''),'reference_line':ref['_line'],'generated_line':g['_line'],
       'source_scenario':name,'pcap_sha256':cap_sha,'reference_log_sha256':ref_sha})
    ambiguous=conn.execute('SELECT COALESCE(SUM(gen.n),0) FROM gen JOIN ref USING(k) WHERE gen.n>1 OR ref.n>1').fetchone()[0]
    unmatched=conn.execute('SELECT COALESCE(SUM(gen.n),0) FROM gen LEFT JOIN ref USING(k) WHERE ref.k IS NULL').fetchone()[0]
    detail={'status':'FULL_LOG_LINKAGE_COMPUTED','scenario':name,'capture':str(capture),'pcap_sha256':cap_sha,
     'reference_sha256':ref_sha,'generated_log_sha256':sha(generated),'reference_rows':cached['rows'],'generated_rows':genrows,
     'unique_exact_key_matches':matched,'unmatched_generated_rows':unmatched,'ambiguous_generated_rows':ambiguous,
     'full_reference_coverage':matched==cached['rows'],'full_generated_coverage':matched==genrows,
     'predictor_difference_counts':dict(diff),'mapped_published_label_counts':dict(new_labels),
     'rule_result_changes_on_reextracted_fields':rule_invariance,'extraction_reused':reused,
     'linked_records_path':str(job/'linked_records.csv'),'linked_records_sha256':sha(job/'linked_records.csv'),
     'source_rule_sha256':rp['sha256'],'publisher_tool_fidelity_verified':False,
     'confirmatory_scenario_selected':False,'packet_validity_approved':False}
    dump(completed,detail);results.append(detail)
    print(name,capture.name,'MATCHES',matched,'/',genrows,'REFERENCE',cached['rows'],'DIFFERENCES',dict(diff),flush=True)
   except Exception as error:failures.append({'scenario':name,'capture':str(capture),'error':f'{type(error).__name__}: {error}'})
  conn.execute('DROP TABLE IF EXISTS gen');conn.commit();conn.close()
 except Exception as error:failures.append({'scenario':name,'capture':'REFERENCE_OR_RULES','error':f'{type(error).__name__}: {error}'})
 pd.DataFrame(results).to_csv(OUT/'candidate_linkage_summary.csv',index=False)
 pd.DataFrame(rule_results).to_csv(OUT/'scenario_rule_agreement.csv',index=False)
 pd.DataFrame(failures,columns=['scenario','capture','error']).to_csv(OUT/'explicit_failures.csv',index=False)

summary=[]
for name in SCENARIOS:
 candidates=[r for r in results if r['scenario']==name]
 complete=[r for r in candidates if r['full_reference_coverage'] and r['full_generated_coverage'] and not r['predictor_difference_counts']]
 rr=[r for r in rule_results if r['scenario']==name]
 summary.append({'scenario':name,'candidate_captures_assessed':len(candidates),'full_bijection_predictor_fidelity_candidates':len(complete),
  'rule_agreement_fraction':rr[0]['rule_agreement_fraction'] if rr else None,
  'status':'ONE_FULL_LINKAGE_CANDIDATE_FOR_REVIEW' if len(complete)==1 else ('MULTIPLE_FULL_CANDIDATES_REVIEW_DUPLICATION' if len(complete)>1 else 'NO_FULL_FIDELITY_CANDIDATE_YET'),
  'scientific_approval_automatic':False})
pd.DataFrame(summary).to_csv(OUT/'scenario_gate_summary.csv',index=False)
receipt={'output_directory':str(OUT),'planned_concrete_rule_scenarios':len(SCENARIOS),'candidate_linkages_computed_or_reused':len(results),
 'explicit_failures':len(failures),'source_labels_replaced':False,'models_trained':False,'attacks_executed':False,
 'NF_changed':False,'confirmatory_scenarios_selected':False,'new_packet_validity_claim':False,
 'next_step':'Review the complete linkage candidates and rule agreement; resolve only actual blockers, then freeze trace-study allocation and feature/action contract before outcomes.'}
dump(OUT/'receipt.json',receipt)
print('\nBATCH RECEIPT\n'+json.dumps(receipt,indent=2))
print('\nSCENARIO GATES\n'+pd.DataFrame(summary).to_string(index=False))
print('\nRULE AGREEMENT\n'+pd.DataFrame(rule_results).to_string(index=False))
print('\nEXPLICIT FAILURES\n'+(pd.DataFrame(failures).to_string(index=False)if failures else 'None'))
print('\nRetain this directory. Rerunning resumes completed candidates; no blanket replay.')
