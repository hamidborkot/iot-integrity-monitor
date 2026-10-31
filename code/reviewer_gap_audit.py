# ONE-RUN REVIEWER-GAP AUDIT. Metadata inventory of all mounted files; bounded content checks of relevant artifacts.
# No installs, model loads, training, replay, deletion or edits to existing experiments.
import os, sys, re, csv, json, gzip, hashlib, zipfile, shutil, platform
import importlib.metadata as im
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

INPUT=Path('/kaggle/input/datasets')
WORK=Path('/kaggle/working')
OUT=WORK/('REVIEWER_GAP_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
SMALL=8*1024**2
SAMPLE_LIMIT=256*1024
TASKS={
 'second_extractor':r'nfstream|argus|second.extractor|extractor.comparison',
 'matched_drift_baseline':r'md3|detectron|d3m|drift.baseline|warning.*unit',
 'same_cohort_rule_sensitivity':r'pure|witness|merge|mg.*sens|rule.*sens|attribution|membership|unit_detection',
 'independent_ledger_validation':r'independent.*(ledger|packet|mapping)|reference.*validator|ground.*truth|packet.*(uid|membership)|fingerprint|ledger',
 'benign_descendant_false_alarms':r'benign|false.*alarm|unit.*prediction|unit.*decision|unit.*bounds|descendant',
 'capture35_full_outputs':r'm4_|capture.?35|capture-35|purity_proxy|period_auroc|pre_reg',
 'zeek_timer_grid':r'zeek_count_sweep|counts_by_group|frozen_protocol|mechanism_information|failure_decomposition|syn_timeout|timeout.*sensitivity',
 'manuscript_compile_bibliography':r'\.tex$|\.bib$|\.bbl$|\.blg$|latex|compile|bibliograph',
 'policies_and_horizons':r'policy|timing|horizon|availability',
 'existing_final_packages':r'paper_lock|accepted_results|resolution_final|gap_closure|zeek_complete_evidence'
}
RX={k:re.compile(v,re.I) for k,v in TASKS.items()}
FOCUS=re.compile('|'.join('(?:'+v+')' for v in TASKS.values()),re.I)
records=[]; errors=[]; receipts=[]; profiles=[]; quotes=[]; versions=[]; archive_rows=[]
seen=set(); captured=set()

def error(p,stage,e):errors.append({'path':str(p),'stage':stage,'error':str(e)[:600]})
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def save(name,rows,cols=None):
 cols=cols or list(dict.fromkeys(k for row in rows for k in row))
 with open(OUT/name,'w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=cols or ['note'],extrasaction='ignore');w.writeheader();w.writerows(rows)
def source(p):
 try:return str(p.relative_to(INPUT))
 except ValueError:return 'WORKING/'+str(p.relative_to(WORK))
def reader(p):
 with open(p,'rb') as f:magic=f.read(2)
 return gzip.open(p,'rt',encoding='utf-8-sig',errors='strict',newline='') if magic==b'\x1f\x8b' else open(p,'rt',encoding='utf-8-sig',errors='strict',newline='')
def excerpts(text,p,limit=12):
 pats=re.compile(r'tcp_SYN_timeout|tcp_attempt_delay|tcp_inactivity_timeout|set_inactivity_timeout|nfstream|argus|UNRESOLVED|PURE_ALARM|NO_RECORD_ALARM|membership_validated|paired_retained|benign.*(alarm|descendant)|Fatal error|Undefined control sequence|Citation .*undefined|Reference .*undefined|\\bibitem\s*\{\s*\}',re.I)
 n=0
 for i,line in enumerate(text.splitlines(),1):
  if pats.search(line):quotes.append({'path':str(p),'line':i,'excerpt':line[:1000]});n+=1
  if n>=limit:break

def inspect(p,row):
 name=p.name.lower();size=row['bytes'];rel=row['relative_path']
 if not FOCUS.search(rel):return
 if size<=SMALL and p.suffix.lower() not in ('.pcap','.pcapng','.joblib','.npz','.pdf'):
  try:row['sha256']=sha(p)
  except Exception as e:error(p,'hash',e)
 if name.endswith('.zip'):
  try:
   with zipfile.ZipFile(p) as z:
    for m in z.infolist():
     if not m.is_dir() and FOCUS.search(m.filename):archive_rows.append({'archive':str(p),'member':m.filename,'bytes':m.file_size,'CRC':m.CRC,'status':'MEMBER_NAME_ONLY_NOT_CONTENT_VALIDATED'})
  except Exception as e:error(p,'zip_directory',e)
  return
 if name.endswith('.json') and size<=SMALL:
  try:
   obj=json.loads(p.read_text(encoding='utf-8-sig'))
   if isinstance(obj,dict):
    if any(k in obj for k in ('status','scientific_decision','config','checks','model_sha256','experiment_signature')) or 'receipt' in name:
     receipts.append({'path':str(p),'sha256':row['sha256'],'status':obj.get('status','NOT_SPECIFIED'),'keys':'|'.join(obj.keys()),'content':json.dumps(obj,ensure_ascii=True,default=str)})
    # Preserve evidence; declaration of a freeze is not independent proof of chronology.
    if 'version' in name or 'environment' in name or 'receipt' in name:
     for k,v in obj.items():
      if re.search(r'version|extractor|timeout|replay',k,re.I) and not isinstance(v,(dict,list)):
       versions.append({'path':str(p),'key':k,'value':str(v)[:600]})
  except Exception as e:error(p,'json',e)
 elif name.endswith(('.csv','.csv.gz','.tsv')):
  try:
   with reader(p) as f:
    r=csv.reader(f,delimiter='\t' if name.endswith('.tsv') else ',')
    header=next(r,None)
    if header is None:
     profiles.append({'path':str(p),'status':'EMPTY_TABLE','columns':'','rows':'0'});return
    count=0;sample=[];bad=0
    if size<=SMALL:
     for x in r:
      count+=1
      if len(x)!=len(header):bad+=1
      if len(sample)<2:sample.append(x)
     n=count;status='FULL_CSV_STRUCTURE_CHECK'
    else:
     for _ in range(2):
      x=next(r,None)
      if x is not None:sample.append(x)
     n='NOT_COUNTED_LARGE_FILE';status='HEADER_AND_TWO_ROWS_ONLY'
    profiles.append({'path':str(p),'status':status,'rows':n,'columns':json.dumps(header),'bad_width_rows':bad,'sample_rows':json.dumps(sample),'sha256':row['sha256']})
  except Exception as e:error(p,'csv',e)
 elif name.endswith(('.py','.zeek','.txt','.log','.md','.tex','.bib','.bbl','.blg')):
  # stderr is TEXT. An empty stderr is not a missing CSV or evidence of replay success.
  if size==0:
   if 'stderr' in name:quotes.append({'path':str(p),'line':0,'excerpt':'EMPTY_STDERR_TEXT_NOT_A_RESULT_FAILURE'})
   return
  try:
   with open(p,'r',encoding='utf-8',errors='replace') as f:text=f.read(SAMPLE_LIMIT)
   excerpts(text,p)
   if name.endswith(('.tex','.bib','.bbl','.blg')):profiles.append({'path':str(p),'status':'TEXT_SCAN_ONLY_NOT_COMPILED','rows':'','columns':''})
  except Exception as e:error(p,'text_excerpt',e)

print('AUDIT OUTPUT:',OUT,flush=True)
roots=[INPUT,WORK]
for root in roots:
 if not root.is_dir():errors.append({'path':str(root),'stage':'mount','error':'ROOT_ABSENT'});continue
 for cur,dirs,files in os.walk(root,followlinks=False,onerror=lambda e:error(getattr(e,'filename','?'),'walk',e)):
  dirs[:]=[x for x in dirs if x not in ('__pycache__','.git') and (Path(cur)/x)!=OUT]
  for name in sorted(files):
   p=Path(cur)/name
   if str(p) in seen:continue
   seen.add(str(p))
   try:
    st=p.stat();row={'path':str(p),'relative_path':source(p),'bytes':st.st_size,'is_symlink':p.is_symlink(),'suffix':p.suffix.lower(),'sha256':''}
    records.append(row);inspect(p,row)
   except Exception as e:error(p,'file',e)
   if len(records)%5000==0:print('Indexed',len(records),'files',flush=True)

save('01_all_file_inventory.csv',records)
save('02_receipts_and_protocols.csv',receipts)
save('03_table_schemas_and_counts.csv',profiles)
save('04_source_and_log_excerpts.csv',quotes)
save('05_environment_and_setting_evidence.csv',versions)
save('06_archive_member_inventory.csv',archive_rows)
save('07_audit_errors.csv',errors)
# Explicitly retain all copies. Hash equivalence never removes a scientific condition.
hashes=Counter(r['sha256'] for r in records if r['sha256'])
save('08_content_duplicate_copies.csv',[r for r in records if r['sha256'] and hashes[r['sha256']]>1])
candidates=[];summ=[]
for task,rx in RX.items():
 hits=[r for r in records if rx.search(r['relative_path'])]
 for r in hits:candidates.append({'task':task,**r})
 csvhits=[r for r in hits if r['path'].lower().endswith(('.csv','.csv.gz'))]
 summ.append({'task':task,'candidate_files':len(hits),'candidate_csvs':len(csvhits),
 'disposition':'CANDIDATES_FOUND_NOT_YET_MATCHED_OR_VALIDATED' if hits else 'NO_MATCH_IN_VISIBLE_FILENAMES_NOT_PROOF_OF_NONEXECUTION'})
save('09_gap_candidate_files.csv',candidates)
save('10_gap_audit_summary.csv',summ)

print('\n=== 1. MOUNTED ROOTS ===')
if INPUT.exists():
 for owner in sorted(INPUT.iterdir()):
  if owner.is_dir():
   for d in sorted(owner.iterdir()):
    if d.is_dir():print(d)
print('\n=== 2. GAP EVIDENCE SUMMARY ===')
for x in summ:print(x['task'],':',x['candidate_files'],'candidate files;',x['candidate_csvs'],'CSV candidates')
print('\n=== 3. EXACT RESULT FILE LOCATIONS ===')
exact={'M4_windows.csv','M4_verdict.json','M4_period_auroc.csv','M4_purity_proxy.csv','RESULTS.csv',
 'MD3_target_stream_results.csv','MD3_clean_condition_contrasts.csv','test3_alarm_witness_results.csv',
 'new_model_original_unit_predictions.csv','fresh_original_unit_results.csv','MECHANISM_INFORMATION_TABLE.csv','configuration_model_comparison.csv'}
for name in sorted(exact):
 hits=[r for r in records if Path(r['path']).name==name]
 print('\n',name,':',len(hits),'copies')
 for x in hits[:8]:print(' ',x['path'])
print('\n=== 4. RELEVANT COMPLETION / FAILURE RECEIPTS ===')
for r in receipts:
 if r['status']!='NOT_SPECIFIED':print(r['status'],'|',r['path'])
print('\n=== 5. TABLE SCHEMAS FOR UNRESOLVED REVIEWER REQUESTS ===')
for r in profiles:
 if re.search(r'M4_|MD3_|witness|M3A_|unit_detection|membership_10s|benign|matched_model|RESULTS.csv',r['path'],re.I):
  print(r['path'],'\n rows=',r['rows'],'status=',r['status'],'\n columns=',r['columns'])
print('\n=== 6. AVAILABLE EXECUTABLES / LIBRARIES (NO EXECUTION OR INSTALLATION) ===')
runtime={'python':sys.version,'platform':platform.platform(),'cwd':os.getcwd(),
 'tools':{x:shutil.which(x) for x in ('zeek','argus','pdflatex','latexmk','bibtex')},'packages':{}}
for x in ('pandas','numpy','scikit-learn','menelaus','nfstream'):
 try:runtime['packages'][x]=im.version(x)
 except im.PackageNotFoundError:runtime['packages'][x]='NOT_INSTALLED'
(OUT/'runtime.json').write_text(json.dumps(runtime,indent=2));print(json.dumps(runtime,indent=2))
print('\n=== 7. AUDIT ERRORS ===')
print(json.dumps(errors[:30],indent=2));print('total audit errors:',len(errors))
status={'status':'EVIDENCE_AUDIT_FINISHED','files_inventoried':len(records),'receipt_or_protocol_files_read':len(receipts),
 'tables_profiled':len(profiles),'errors':len(errors),'model_fits':0,'PCAP_replays':0,
 'full_content_of_every_file_read':False,'scope':'all visible filenames/stat metadata; bounded relevant JSON/CSV/text content checks',
 'reviewer_gaps_automatically_declared_solved':False}
(OUT/'AUDIT_RECEIPT.json').write_text(json.dumps(status,indent=2))
(OUT/'READ_ME.md').write_text('# Reviewer-gap evidence audit\n\nThis is evidence discovery, not missing-experiment execution.\nAll paths and copies are retained. Read errors are explicit.\nFilename matches, status strings, hashes and internal counter checks are not independent scientific validation.\nNo model, PCAP, or attached Python code was executed.\nA second extractor, matched baseline comparison, same-cohort rule sensitivity, independent ledger validation and benign-unit alarm accounting require content-level review before completion can be declared.\n')
zpath=OUT/'PRIVATE_REVIEWER_AUDIT.zip'
with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(OUT.iterdir()):
  if p.is_file() and p!=zpath:z.write(p,p.name)
with zipfile.ZipFile(zpath) as z:
 bad=z.testzip()
 if bad:raise RuntimeError('Audit ZIP CRC failed: '+bad)
print('\n=== FINAL AUDIT RECEIPT ===\n'+json.dumps(status,indent=2))
print('PACKAGE:',zpath,'\nSHA256:',sha(zpath))
