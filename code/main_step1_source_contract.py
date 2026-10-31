"""Main Step 1: build a source-quotation workbench for the two primary datasets.
Reads verified bundle metadata and existing cached non-statistical source excerpts.
No classifier fitting, predictions, attacks, corpus loading, or automatic provenance approval.
"""
import hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
import joblib
import pandas as pd
ROOT=Path('/kaggle/working/resume_verified_20261011T144807877506Z')
BASE=ROOT/'development'
OUT=ROOT/('main_source_contract_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
BUNDLES={
 'CICIoT2023':('CICIoT2023/CICIoT2023_bundle.joblib','29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88'),
 'CICIoMT2024':('CICIoMT2024/CICIoMT2024_bundle.joblib','7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473')}
SEARCH_ROOTS=[ROOT,Path('/kaggle/input/datasets/mdhamidborkottulla/the-last-update'),
 Path('/kaggle/input/datasets/mdhamidborkottulla/complete-backup'),
 Path('/kaggle/input/datasets/mdhamidborkottulla/whole-in-one')]
EVIDENCE_NAMES={'nonstatistical_definition_excerpts.csv','definition_excerpts_with_explicit_reconciliation.csv','actual_source_quotations.csv'}

def norm(value):return re.sub(r'[^a-z0-9]','',str(value).lower())
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def value(row,names):
 for name in names:
  if name in row and str(row[name]).strip():return str(row[name])
 return ''

features={};metadata_rows=[]
for dataset,(relative,expected) in BUNDLES.items():
 path=BASE/relative
 if not path.is_file() or sha(path)!=expected:raise RuntimeError('Verified bundle mismatch: '+dataset)
 bundle=joblib.load(path)
 columns=list(bundle['primary_features'])
 features[dataset]=columns
 membership={feature:view for view,fields in bundle['semantic_views'].items() for feature in fields}
 for position,feature in enumerate(columns,start=1):
  metadata_rows.append({'dataset':dataset,'feature':feature,'position':position,
   'current_saved_view':membership.get(feature,'primary_only'),
   'historically_mutable':feature in bundle['mutable_columns'],'bundle_sha256':expected})
 del bundle
pd.DataFrame(metadata_rows).to_csv(OUT/'exact_primary_feature_inputs.csv',index=False)

paths=set()
for root in SEARCH_ROOTS:
 if root.is_dir():
  paths.update(path for path in root.rglob('*.csv') if path.name in EVIDENCE_NAMES and path.is_file() and not path.is_symlink())
seen_files=set();evidence=[];errors=[]
for path in sorted(paths,key=str):
 try:
  digest=sha(path)
  if digest in seen_files:continue
  seen_files.add(digest)
  table=pd.read_csv(path,keep_default_na=False)
  if 'dataset' not in table.columns:
   errors.append({'path':str(path),'error':'No dataset column; rows not inferred from filename.'});continue
  for index,row in table.iterrows():
   dataset_match=[d for d in BUNDLES if norm(d)==norm(row['dataset'])]
   if len(dataset_match)!=1:continue
   dataset=dataset_match[0]
   documented=value(row,['raw_feature','document_feature','feature','model_feature'])
   matches=[f for f in features[dataset] if norm(f)==norm(documented)]
   if len(matches)!=1:continue
   quote=value(row,['exact_quote','verbatim_quote','verbatim_table_row','quote','definition_text'])
   definition=value(row,['definition_text','description'])
   if not quote:continue
   if re.search(r'recaptcha|checking your browser|access denied',quote,re.I):continue
   evidence.append({'dataset':dataset,'feature':matches[0],'source_url':value(row,['source_url','requested_url']),
    'source_document_sha256':value(row,['source_sha256','document_sha256','sourcesha256']),
    'locator':value(row,['locator','table_context']),'exact_quote':quote,'definition_text':definition,
    'cache_file':str(path),'cache_file_sha256':digest,'cache_row':int(index)+2,
    'source_verified_by_this_code':False})
 except Exception as error:errors.append({'path':str(path),'error':f'{type(error).__name__}: {error}'})
evidence_table=pd.DataFrame(evidence,columns=['dataset','feature','source_url','source_document_sha256','locator',
 'exact_quote','definition_text','cache_file','cache_file_sha256','cache_row','source_verified_by_this_code'])
if not evidence_table.empty:
 evidence_table=evidence_table.drop_duplicates(['dataset','feature','source_url','source_document_sha256','exact_quote'])
evidence_table.to_csv(OUT/'exact_source_quotations.csv',index=False)

ledger=[];summary=[]
for row in metadata_rows:
 subset=evidence_table[(evidence_table.dataset==row['dataset'])&(evidence_table.feature==row['feature'])]
 ttl=bool(subset.exact_quote.str.contains(r'\bttl\b|time\s*[- ]?to\s*[- ]?live',case=False,regex=True).any()) if len(subset) else False
 ledger.append({**row,'source_excerpt_count':len(subset),'source_quote_status':'EXCERPTS_FOR_REVIEW' if len(subset) else 'NO_CACHED_EXACT_EXCERPT',
  'TTL_word_present_in_quote':ttl,'semantic_view_final':'','units':'','primitive_source':'','derived_from':'',
  'permitted_report_corruption_action':'','executable_dependency_rule':'','review_decision':'PENDING',
  'source_verified':False,'traffic_or_packet_transform_approved':False})
ledger=pd.DataFrame(ledger);ledger.to_csv(OUT/'primary_feature_contract_REVIEW.csv',index=False)
for dataset in BUNDLES:
 rows=ledger[ledger.dataset==dataset]
 summary.append({'dataset':dataset,'predictors':len(rows),'with_exact_cached_excerpt':int((rows.source_excerpt_count>0).sum()),
  'without_exact_cached_excerpt':int((rows.source_excerpt_count==0).sum()),
  'historically_mutable_without_excerpt':int((rows.historically_mutable&(rows.source_excerpt_count==0)).sum()),
  'final_source_contract_approved':False})
pd.DataFrame(summary).to_csv(OUT/'source_contract_coverage.csv',index=False)
pd.DataFrame(errors,columns=['path','error']).to_csv(OUT/'evidence_read_errors.csv',index=False)

review='# Primary-dataset exact source quotations\n\nCached excerpts are evidence to review, not automatic approval. No cross-dataset transfer or invented definitions.\n'
for row in evidence_table.to_dict('records'):
 review+=f"\n## {row['dataset']} / {row['feature']}\nURL: {row['source_url']}\nDocument SHA256: {row['source_document_sha256']}\nLocator: {row['locator']}\nCache: {row['cache_file']} / row {row['cache_row']}\n\n{row['exact_quote']}\n"
(OUT/'PRIMARY_SOURCE_QUOTATIONS.md').write_text(review,encoding='utf-8')
receipt={'output_directory':str(OUT),'active_development_base':str(BASE),'cached_evidence_files_considered':len(paths),
 'deduplicated_evidence_files_read':len(seen_files),'exact_source_excerpt_rows':len(evidence_table),
 'bundles_loaded_for_schema_metadata_only':True,'predictions_computed':False,'models_trained':False,
 'NF_experiments_repeated':False,'source_contract_approved':False,'prospective_protocol_frozen':False,
 'no_definition_invented':True,'read_errors':len(errors)}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print('\nPRIMARY SOURCE-CONTRACT COVERAGE');print(pd.DataFrame(summary).to_string(index=False))
print('\nHISTORICAL MUTABLE FIELDS — ACTUAL QUOTES')
mutable=set(zip(ledger.loc[ledger.historically_mutable,'dataset'],ledger.loc[ledger.historically_mutable,'feature']))
for row in evidence_table.to_dict('records'):
 if (row['dataset'],row['feature']) in mutable:
  print('\n',row['dataset'],row['feature']);print(row['source_url']);print(row['exact_quote'])
print('\nUPLOAD DOCUMENT:',OUT/'PRIMARY_SOURCE_QUOTATIONS.md')
