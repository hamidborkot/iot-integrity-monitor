"""Two closing analyses: class-balanced rule discrepancies + stable-field compatibility.
Reads already computed full-log summaries/receipts; no Zeek reruns or large indexes.
No labels replaced, no models, no attack, no automatic confirmatory approval.
"""
import csv,gzip,hashlib,json,zipfile
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd

WORK=Path('/kaggle/working');STREAM=WORK/'TRACE_LINKAGE_STREAM_v2';OLD=WORK/'TRACE_LINKAGE_BATCH_v1'
SRC=WORK/'TRACE_LABEL_RECOVERY_20261011T153846517131Z'
OUT=WORK/('TRACE_CLOSING_PAIR_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)
SCENARIOS=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-7-1','CTU-IoT-Malware-Capture-8-1','CTU-IoT-Malware-Capture-9-1']
CORE=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
EXCLUDE=['conn_state','history','service','local_orig','local_resp','tunnel_parents','ip_proto']

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def save_json(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf-8')

# A: inspect the full-population confusion already computed, not just overall agreement.
metrics=[];confusions=[];errors=[];sources=[]
for scenario in SCENARIOS:
 paths=[STREAM/scenario/'reference_summary.json',OLD/scenario/'reference_index_receipt.json']
 path=next((p for p in paths if p.is_file()),None)
 if path is None:errors.append({'task':'A','scenario':scenario,'error':'Completed full reference confusion not found'});continue
 obj=json.loads(path.read_text());sources.append({'role':'full_reference_confusion','scenario':scenario,'path':str(path),'sha256':sha(path)})
 rows=int(obj['rows']);matrix={}
 for row in obj['confusion']:
  a=str(row['published']).lower();b=str(row['rule']).lower();n=int(row['records'])
  matrix[(a,b)]=matrix.get((a,b),0)+n
  confusions.append({'scenario':scenario,'published_label':a,'rule_label':b,'records':n})
 if sum(matrix.values())!=rows:raise RuntimeError('Confusion total does not equal full reference count: '+scenario)
 benign=sum(n for(a,b),n in matrix.items()if a=='benign')
 malicious=sum(n for(a,b),n in matrix.items()if a=='malicious')
 correct_b=matrix.get(('benign','benign'),0);correct_m=matrix.get(('malicious','malicious'),0)
 correct=sum(n for(a,b),n in matrix.items()if a==b)
 b_recall=correct_b/benign if benign else None;m_recall=correct_m/malicious if malicious else None
 unsupported=sum(n for(a,b),n in matrix.items()if a not in {'benign','malicious'})
 background=sum(n for(a,b),n in matrix.items()if b=='background')
 unmatched=sum(n for(a,b),n in matrix.items()if b=='unmatched')
 metrics.append({'scenario':scenario,'full_reference_rows':rows,'benign_records':benign,'malicious_records':malicious,
  'overall_agreement':correct/rows if rows else None,'benign_class_agreement':b_recall,'malicious_class_agreement':m_recall,
  'balanced_class_agreement':(b_recall+m_recall)/2 if b_recall is not None and m_recall is not None else None,
  'disagreements':rows-correct,'rule_background_predictions':background,'rule_unmatched_predictions':unmatched,
  'unsupported_published_labels':unsupported,'binary_rule_identity_on_all_reference_records':correct==rows and unsupported==0,
  'published_labels_replaced':False,'publisher_tool_fidelity_approved':False})
pd.DataFrame(metrics).to_csv(OUT/'A_class_balanced_rule_fidelity.csv',index=False)
pd.DataFrame(confusions).to_csv(OUT/'A_full_binary_confusions.csv',index=False)

# B: test a proposed extractor-version-stable core on ALL uniquely linked rows,
# using saved full-comparison counts. No new training/outcome selection.
# This is a disclosed schema amendment proposal, not a claim that dropped fields reproduce.
summary=pd.read_csv(STREAM/'candidate_linkage_summary.csv',keep_default_na=False)
if not {'linked_records_path','scenario','capture'}.issubset(summary.columns):raise RuntimeError('Unexpected completed summary schema.')
receipts=[];seen=set()
for root in [STREAM,OLD]:
 for path in root.rglob('candidate_receipt.json'):
  obj=json.loads(path.read_text())
  if obj.get('status')!='FULL_LOG_LINKAGE_COMPUTED':continue
  ident=(obj['scenario'],obj['pcap_sha256'],obj['reference_sha256'])
  if ident in seen:continue
  seen.add(ident);receipts.append((path,obj))
expected=set(zip(summary.scenario,summary.pcap_sha256,summary.reference_sha256))
if seen!=expected:raise RuntimeError('Saved candidate receipts disagree with completed batch summary.')
compatibility=[];manifest=[]
for path,obj in receipts:
 linked=Path(obj['linked_records_path'])
 if not linked.is_file()or sha(linked)!=obj['linked_records_sha256']:raise RuntimeError('Saved linked output missing/changed: '+str(linked))
 differences=obj['predictor_difference_counts'];unstable={k:v for k,v in differences.items()if k in EXCLUDE};core_diff={k:v for k,v in differences.items()if k in CORE}
 if any(k not in CORE+EXCLUDE for k in differences):raise RuntimeError('Unknown compared predictor in receipt.')
 # Check recorded CSV schema without rebuilding/copying data.
 opener=gzip.open(linked,'rt',encoding='utf-8',newline='')if linked.name.endswith('.gz')else linked.open('r',encoding='utf-8',newline='')
 with opener as f:columns=next(csv.reader(f))
 if not set(CORE+['published_label','reference_line','generated_line']).issubset(columns):raise RuntimeError('Core/schema/label lineage fields absent: '+str(linked))
 row={'scenario':obj['scenario'],'capture':Path(obj['capture']).name,'reference_rows':obj['reference_rows'],
  'generated_rows':obj['generated_rows'],'unique_exact_key_matches':obj['unique_exact_key_matches'],
  'unlinked_reference_rows':obj['reference_rows']-obj['unique_exact_key_matches'],
  'unlinked_generated_rows':obj['generated_rows']-obj['unique_exact_key_matches'],
  'ambiguous_generated_rows':obj['ambiguous_generated_rows'],
  'mapped_reference_fraction':obj['unique_exact_key_matches']/obj['reference_rows'],
  'mapped_generated_fraction':obj['unique_exact_key_matches']/obj['generated_rows'],
  'unstable_field_difference_counts':json.dumps(unstable),'stable_core_difference_counts':json.dumps(core_diff),
  'stable_core_identical_on_all_uniquely_linked_rows':not core_diff,
  'full_population_bijection':obj['unique_exact_key_matches']==obj['reference_rows']==obj['generated_rows'],
  'dropped_rows_are_reported_not_hidden':True,'automatic_label_or_protocol_approval':False}
 compatibility.append(row)
 manifest.append({'scenario':obj['scenario'],'pcap_path':obj['capture'],'pcap_sha256':obj['pcap_sha256'],
  'reference_log_sha256':obj['reference_sha256'],'linked_records_path':str(linked),'linked_records_sha256':obj['linked_records_sha256'],
  'candidate_receipt':str(path),'candidate_receipt_sha256':sha(path),'stable_core_columns':CORE,
  'label_column':'published_label','identity_columns_metadata_only':['reference_line','generated_line','source_scenario','pcap_sha256','reference_log_sha256'],
  'eligible_for_training_by_this_code':False,'reason':'Stable-core compatibility does not itself approve label provenance, capture allocation, or independence.'})
 sources.append({'role':'candidate_receipt','scenario':obj['scenario'],'path':str(path),'sha256':sha(path)})
pd.DataFrame(compatibility).to_csv(OUT/'B_stable_core_compatibility.csv',index=False)
save_json(OUT/'B_noncopying_dataset_manifest.json',manifest)

schema=[]
for feature in CORE:
 if feature=='duration':view='timing';kind='connection interval';unit='seconds';action='Re-extract after permitted timestamp transformation; never directly edit CSV.'
 elif feature=='proto':view='protocol';kind='protocol category';unit='categorical';action='Immutable under padding/pacing action.'
 elif feature=='missed_bytes':view='capture_quality';kind='extraction quality indicator';unit='bytes';action='Quality constraint; not an attacker-optimizable numeric coordinate.'
 else:view='directional_volume';kind='extracted directional counter';unit='packets'if 'pkts'in feature else'bytes';action='Re-extract after permitted packet transformation; never independently edit counter.'
 schema.append({'feature':feature,'candidate_view':view,'role':kind,'candidate_unit':unit,'candidate_action_policy':action,
  'semantics_status':'REQUIRES_VERSIONED_ZEEK_SOURCE_CONFIRMATION_BEFORE_FINAL_SCHEMA',
  'source_verified':False,'candidate_only':True})
for feature in EXCLUDE:
 schema.append({'feature':feature,'candidate_view':'EXCLUDED_FROM_STABLE_CORE','role':'version-dependent or unverified field',
  'candidate_unit':'','candidate_action_policy':'Preserve in extraction evidence, omit from proposed cross-version core.',
  'semantics_status':'EXCLUSION_BASED_ON_EXTRACTION_FIDELITY; NOT TARGET_MODEL_PERFORMANCE','source_verified':False,'candidate_only':True})
pd.DataFrame(schema).to_csv(OUT/'B_proposed_stable_feature_contract.csv',index=False)
pd.DataFrame(sources).to_csv(OUT/'evidence_sources.csv',index=False)
pd.DataFrame(errors,columns=['task','scenario','error']).to_csv(OUT/'explicit_errors.csv',index=False)
receipt={'output_directory':str(OUT),'closing_analyses_completed':['A_CLASS_BALANCED_RULE_FIDELITY','B_STABLE_CORE_COMPATIBILITY'],
 'scenarios_rule_analyzed':len(metrics),'candidate_linkages_checked':len(compatibility),
 'stable_core_fields':CORE,'new_predictor_fidelity_claim_scope':'uniquely linked rows only; unmatched/ambiguous rows remain counted',
 'schema_amendment_final_approved':False,'publisher_label_rules_auto_approved':False,
 'published_labels_replaced':False,'data_copied':False,'Zeek_rerun':False,'models_trained':False,'attacks_executed':False,
 'NF_changed':False,'explicit_errors':len(errors),'next_step':'Use class-balanced disagreements and stable-core evidence to resolve label/version policy; then approve a source-backed allocation/action contract before any confirmatory outcomes.'}
save_json(OUT/'receipt.json',receipt)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED)as z:
 for p in sorted(OUT.iterdir()):
  if p.is_file():z.write(p,p.name)
with zipfile.ZipFile(package)as z:
 if z.testzip()is not None:raise RuntimeError('Private review ZIP integrity failure.')
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package)},indent=2))
print('\nA — CLASS-BALANCED RULE FIDELITY');print(pd.DataFrame(metrics).to_string(index=False))
print('\nA — FULL BINARY CONFUSIONS');print(pd.DataFrame(confusions).to_string(index=False))
print('\nB — STABLE-CORE LINKAGE COMPATIBILITY');print(pd.DataFrame(compatibility).to_string(index=False))
print('\nEXPLICIT ERRORS');print(pd.DataFrame(errors).to_string(index=False)if errors else'None')
