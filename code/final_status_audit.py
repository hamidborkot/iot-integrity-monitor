"""Evidence-index audit over ALL uploaded backups + restored working directory. Read-only.
Copies nothing (the earlier audit failed because it copied evidence until its budget ran out).
Name/flag indicators only: NOT_FOUND means not found by these checks; it is not proof of absence or of scientific approval.
"""
import hashlib,json,os,re,zipfile
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd

BASE=Path('/kaggle/input/datasets/mdhamidborkottulla')
WORKING=Path('/kaggle/working')
REQUESTED=['whole-in-one','the-last-update','ran-files','last-day-backup','complete-backup','all-kaggle-work']
EXTRA=['pcaps-of-ciciot-23-and-24','research-closing-code','research-experiment-suite']
ROOTS={n:BASE/n for n in REQUESTED+EXTRA};ROOTS['working_restored']=WORKING
MAX_JSON=2*1024**2;MAX_HASH=64*1024**2;MAX_ZIP_MEMBERS=300000
OUT=WORKING/('FINAL_STATUS_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
KNOWN_BUNDLES={'CICIoT2023_bundle.joblib':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88',
 'CICIoMT2024_bundle.joblib':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473',
 'CSE_bundle.joblib':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3',
 'NSL_bundle.joblib':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29',
 'TONIoT_bundle.joblib':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf'}
NF_RESULT_SHA='0bdab303dca24571116b2b5395c83cfe686e56fd850c2784d7c2161ec5110bfa'
FLAGS=['prospective_protocol_frozen','primary_allocation_frozen','confirmatory_protocol_frozen','final_confirmatory_protocol_frozen',
 'confirmatory_results_generated','independent_confirmation_completed','original_A_to_G_complete','packet_valid_attack_approved',
 'packet_validity_established','independent_corpus_claim_allowed','label_semantics_approved','feature_contract_final_approved',
 'schema_amendment_final_approved','source_contract_approved','detector_attack_efficacy_evaluated']
FROZEN_FLAGS={'prospective_protocol_frozen','primary_allocation_frozen','confirmatory_protocol_frozen','final_confirmatory_protocol_frozen'}

def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()

inventory=[];root_rows=[];missing=[];zip_errors=[]
for label,root in ROOTS.items():
 if not root.is_dir():missing.append(label);continue
 count=size_sum=0
 for directory,dirs,names in os.walk(root,followlinks=False):
  dirs.sort()
  if label=='working_restored':dirs[:]=[d for d in dirs if not d.startswith('FINAL_STATUS_AUDIT_')]
  for name in sorted(names):
   path=os.path.join(directory,name)
   try:st=os.stat(path)
   except OSError:continue
   symlink=os.path.islink(path)
   inventory.append((label,path,name,st.st_size,symlink,False));count+=1;size_sum+=st.st_size
   if name.lower().endswith('.zip') and not symlink:
    try:
     with zipfile.ZipFile(path)as z:
      members=z.infolist()[:MAX_ZIP_MEMBERS]
      for info in members:
       if info.is_dir():continue
       inventory.append((label,path+'!'+info.filename,os.path.basename(info.filename),info.file_size,False,True))
    except Exception as error:zip_errors.append({'root':label,'zip':path,'error':f'{type(error).__name__}: {error}'})
 root_rows.append({'root':label,'files':count,'GiB':round(size_sum/1024**3,3)})
inv=pd.DataFrame(inventory,columns=['root','path','name','size','is_symlink','zip_member'])
inv.to_csv(OUT/'full_file_inventory.csv.gz',index=False,compression='gzip')
pd.DataFrame(root_rows).to_csv(OUT/'root_summary.csv',index=False)
duplicate_names=inv.groupby(['name','size']).root.nunique().gt(1).sum()

def rows(name_regex=None,path_regex=None):
 mask=pd.Series(True,index=inv.index)
 if name_regex:mask&=inv['name'].str.contains(name_regex,case=False,regex=True,na=False)
 if path_regex:mask&=inv['path'].str.contains(path_regex,case=False,regex=True,na=False)
 return inv[mask]

# JSON flag scan, deduplicated by content hash.
flag_obs=defaultdict(list);seen=set();json_errors=0;json_scanned=0
candidates=inv[(inv['name'].str.lower().str.endswith('.json'))&(~inv.zip_member)&(inv['size']<=MAX_JSON)]
for i,row in enumerate(candidates.itertuples(index=False),1):
 try:
  data=Path(row.path).read_bytes();h=hashlib.sha256(data).hexdigest()
  if h in seen:continue
  seen.add(h);obj=json.loads(data.decode('utf-8-sig'));json_scanned+=1
  stack=[obj]
  while stack:
   item=stack.pop()
   if isinstance(item,dict):
    for k,v in item.items():
     if k in FLAGS and isinstance(v,bool):flag_obs[k].append((v,row.path))
     if isinstance(v,(dict,list)):stack.append(v)
   elif isinstance(item,list):stack.extend(x for x in item if isinstance(x,(dict,list)))
 except Exception:json_errors+=1
 if i%25000==0:print('JSON scan',i,'/',len(candidates),flush=True)
flag_table=[]
for key in FLAGS:
 vals=flag_obs.get(key,[]);trues=[p for v,p in vals if v]
 flag_table.append({'flag':key,'unique_receipts_with_flag':len(vals),'true_count':len(trues),'false_count':len(vals)-len(trues),'example_true_path':trues[0] if trues else ''})
flag_df=pd.DataFrame(flag_table);flag_df.to_csv(OUT/'status_flag_scan.csv',index=False)

report=[]
def add(code,category,item,found_rows,note='',found=None):
 ok=bool(len(found_rows)) if found is None else found
 report.append({'id':code,'category':category,'item':item,'status':'FOUND' if ok else 'NOT_FOUND',
  'evidence_files':len(found_rows),'example_path':found_rows.iloc[0]['path'] if len(found_rows) else '','note':note})
def multi(patterns,path_regex=None):
 parts=[rows(p,path_regex)for p in patterns]
 return pd.concat(parts) if all(len(p)for p in parts) else parts[0].iloc[0:0]

# Hash-verified anchors.
bundle_results=[]
for name,expected in KNOWN_BUNDLES.items():
 candidates_b=rows('^'+re.escape(name)+'$');verified=False
 for r in candidates_b[~candidates_b.zip_member].head(4).itertuples(index=False):
  if r.size<=MAX_HASH and sha(r.path)==expected:verified=True;break
 bundle_results.append((name,verified))
add('D01','completed','Five frozen core bundles, hash-verified',inv.iloc[0:0],f"verified={sum(v for _,v in bundle_results)}/5",all(v for _,v in bundle_results))
nf=rows('^boundary_result\\.json$');nf_ok=False
for r in nf[~nf.zip_member].head(4).itertuples(index=False):
 if sha(r.path)==NF_RESULT_SHA:nf_ok=True;break
add('D02','completed','NF locked boundary result, hash-verified',nf,'',nf_ok)
DEV=[('D03','Final development evidence consolidation',[r'^final_development_receipt\.json$'],None),
 ('D04','Aligned-gate adaptive evaluation',[r'^configuration_summary\.csv$'],r'aligned_gate_adaptive'),
 ('D05','Neural replay corrected summary',[r'^all_datasets_corrected_direct_target_summary\.csv$'],None),
 ('D06','MD3 results and identifiability bounds',[r'^all_datasets_md3_results\.csv$',r'^bounds_summary\.csv$'],None),
 ('D07','ALine/GDE computations',[r'.'],r'aline_gde'),
 ('D08','Independent estimator-bank intervals',[r'^paired_conditional_bank_intervals\.csv$'],None),
 ('D09','Algebraic screen / damage retention',[r'^damage_retention_overview\.csv$'],None),
 ('D10','Resource and precision audit',[r'.'],r'resource_quantization'),
 ('D11','Closing analyses',[r'^estimation_summary\.csv$',r'^matched_risk_coverage\.csv$',r'^attribution_summary\.csv$'],None),
 ('D12','Unique-witness corrected comparison',[r'^unique_case_failures\.csv$'],None),
 ('D13','Generic non-identifiability lemma file',[r'(lemma|nonidentifiab)'],None)]
TRACE=[('T01','Zeek-linked candidate receipts',[r'^candidate_receipt\.json$'],None),
 ('T02','Canonical Conn::Info field contract',[r'^B_canonical_Conn_Info_contract\.csv$'],None),
 ('T03','Official v1 label-count reconciliation',[r'^A_v1_release_label_count_reconciliation\.csv$'],None),
 ('T04','C0 packet-transformation pilot results',[r'^paired_validity_results\.csv$'],None),
 ('T05','Scenario inventory / screening output',[r'^scenario_inventory\.csv$'],None)]
for code,item,patterns,path_regex in DEV:add(code,'completed',item,multi(patterns,path_regex))
for code,item,patterns,path_regex in TRACE:add(code,'completed',item,multi(patterns,path_regex))

# Content checks for trace evidence.
cands={};
for r in rows(r'^candidate_receipt\.json$').itertuples(index=False):
 if r.zip_member:continue
 try:
  obj=json.loads(Path(r.path).read_text())
  if obj.get('status')=='FULL_LOG_LINKAGE_COMPUTED':cands[(obj['scenario'],obj['pcap_sha256'])]=obj
 except Exception:pass
validity=[]
for r in rows(r'^paired_validity_results\.csv$').itertuples(index=False):
 if r.zip_member:continue
 try:
  t=pd.read_csv(r.path);t['source_path']=r.path;validity.append(t)
 except Exception:pass
vt=pd.concat(validity,ignore_index=True).drop_duplicates(subset=[c for c in validity[0].columns if c!='source_path']) if validity else pd.DataFrame()
if not vt.empty:vt.to_csv(OUT/'trace_validity_cases_found.csv',index=False)
cases=vt['case'].astype(str).tolist() if 'case'in vt else []
pacing=vt[vt['case'].astype(str).str.contains('pac',case=False)] if cases else pd.DataFrame()
delay_note='; '.join(f"{c}: max_delay_s={d:.3f}" for c,d in zip(pacing['case'],pacing.get('maximum_packet_delay_seconds',[]))) if not pacing.empty else ''

REMAIN=[('R01','Frozen trace-study protocol file',[r'(protocol).*(frozen|prereg|freeze)|(frozen|prereg|freeze).*(protocol)'],None),
 ('R05','Primary confirmatory results (Holm family)',[r'(holm|primary_hypothesis|confirmatory_result)'],None),
 ('R06','Adaptive attack on trace-linked monitor',[r'.'],r'trace.*adaptive|adaptive.*trace'),
 ('R07','IDS-specific / weighted-integrity proof files',[r'(ids_specific|weighted_integrity|admissible_worlds)'],None),
 ('R08','Trace-study detector/monitor training artifacts',[r'.'],r'trace.*(detector|monitor).*(bundle|model)'),
 ('R09','Manuscript draft files',[r'(manuscript|paper|main).*\.(tex|docx)$'],None)]
frozen_true=sum(r['true_count']for r in flag_table if r['flag']in FROZEN_FLAGS)
for code,item,patterns,path_regex in REMAIN:
 found=multi(patterns,path_regex)
 if code=='R01' and frozen_true:
  hit=next((p for key in FROZEN_FLAGS for v,p in flag_obs.get(key,[])if v),'')
  found=pd.DataFrame([{'path':hit}])
 add(code,'remaining_indicator',item,found,'name/flag indicator only; review file contents if found')
add('R02','remaining_indicator','Packet-padding validity suite',rows(None,r'padding'),'also checked case names: '+', '.join(cases)[:300],
 any('pad'in c.lower()for c in cases) or bool(len(rows(None,r'padding'))))
add('R03','remaining_indicator','Packet-injection validity suite',rows(None,r'injection'),'also checked case names',
 any('inject'in c.lower()for c in cases) or bool(len(rows(None,r'injection'))))
add('R04','remaining_indicator','Bounded-delay pacing validity',pacing.head(1)[['source_path']].rename(columns={'source_path':'path'}) if not pacing.empty else inv.iloc[0:0],
 delay_note or 'no pacing case found',found=bool(len(pacing)))
rep=pd.DataFrame(report);rep.to_csv(OUT/'status_checklist.csv',index=False)

# Raw packet assets, especially the CIC PCAP upload.
packet=inv[inv['name'].str.contains(r'\.(pcap|pcapng)(\.gz)?$',case=False,regex=True,na=False)]
packet_summary=packet.groupby('root').agg(files=('path','size'),GiB=('size',lambda s:round(s.sum()/1024**3,3))).reset_index() if len(packet) else pd.DataFrame(columns=['root','files','GiB'])
packet_summary.to_csv(OUT/'packet_capture_inventory.csv',index=False)
cic=packet[packet.root=='pcaps-of-ciciot-23-and-24'].sort_values('size',ascending=False)
cic.head(100).to_csv(OUT/'ciciot_pcap_upload_largest_100.csv',index=False)
source_code=inv[inv['name'].str.endswith('.py',na=False)]
source_summary=source_code.groupby('root').size().reset_index(name='python_files')
source_summary.to_csv(OUT/'python_source_inventory.csv',index=False)

actions={'R01':'Freeze label policy, delay cap, scenario pairs, fresh seeds, windows, inference unit (one document).',
 'R02':'Design and validate padding within MTU bounds; report ValidityRate.',
 'R03':'Design and validate protocol-valid dummy-packet injection; report ValidityRate.',
 'R04':'Re-run pacing with a fixed delay cap; report damage retention after re-extraction.',
 'R05':'Run the frozen primary tests once; Holm correction; report all results.',
 'R06':'Query-based hard-gate attack on the final monitor, descriptive.',
 'R07':'Prove IDS-specific non-identifiability and the weighted-integrity proposition with explicit assumptions.',
 'R08':'Train/evaluate the final trace-linked detector and monitor on frozen allocation.',
 'R09':'Write manuscript only from verified claims.'}
completed=rep[rep.category=='completed'];remaining=rep[rep.category=='remaining_indicator']
lines=['# Final status audit (indicator-based)\n','NOT_FOUND means not found by these checks in the scanned roots; it is not proof of absence and FOUND is not scientific approval.\n',
 f"Completed-item indicators found: {int((completed.status=='FOUND').sum())}/{len(completed)}\n",'## Completed-item indicators\n',completed[['id','item','status','evidence_files','note']].to_markdown(index=False),
 '\n## Remaining-work indicators\n',remaining[['id','item','status','evidence_files','note']].assign(action=lambda d:d.id.map(actions)).to_markdown(index=False),
 '\n## Status flags in receipts\n',flag_df.to_markdown(index=False),'\n## Packet-capture inventory\n',packet_summary.to_markdown(index=False)]
(OUT/'FINAL_STATUS_REPORT.md').write_text('\n'.join(lines),encoding='utf-8')
receipt={'output_directory':str(OUT),'roots_scanned':[r['root']for r in root_rows],'roots_missing':missing,'files_indexed':len(inv),
 'zip_members_indexed':int(inv.zip_member.sum()),'zip_errors':len(zip_errors),'duplicate_name_size_across_roots':int(duplicate_names),
 'unique_json_scanned':json_scanned,'json_errors':json_errors,'unique_trace_candidates_with_full_linkage':len(cands),
 'models_trained':False,'attacks_executed':False,'files_copied':False,'scientific_completion_determined':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print('\nROOT SUMMARY');print(pd.DataFrame(root_rows).to_string(index=False))
print('\nCOMPLETED-ITEM INDICATORS');print(completed[['id','item','status','evidence_files','note']].to_string(index=False))
print('\nREMAINING-WORK INDICATORS');print(remaining[['id','item','status','evidence_files','note']].assign(action=lambda d:d.id.map(actions)).to_string(index=False))
print('\nSTATUS FLAGS IN RECEIPTS');print(flag_df.to_string(index=False))
print('\nTRACE VALIDITY CASES FOUND');print(vt[[c for c in ['case','original_records','unique_label_linked_records','maximum_packet_delay_seconds','mean_duration_change_seconds','full_unique_mapping'] if c in vt]].to_string(index=False) if not vt.empty else 'None')
print('\nPACKET CAPTURE INVENTORY');print(packet_summary.to_string(index=False))
print('\nCIC PCAP UPLOAD (largest 20)');print(cic.head(20)[['path','size']].to_string(index=False) if len(cic) else 'No pcap files found in that root or root not mounted')
print('\nPYTHON SOURCE FILES BY ROOT');print(source_summary.to_string(index=False))
if missing:print('\nROOTS NOT MOUNTED:',missing)
if zip_errors:print('\nZIP ERRORS',zip_errors[:5])
