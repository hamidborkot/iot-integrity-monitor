"""TRACE CONFIRMATORY STEP 2A: target asset resolution only. No target model predictions, no target detector outcomes, no attacks, no Zeek replay.
Reads target file names, hashes, CSV headers and first rows to bind each frozen E1 target to its original slice, clean log, and label-mapping artifact.
"""
import glob,hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';OUT=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1'
if not PROTO.is_file() or not SOURCE.is_file():raise FileNotFoundError('Frozen protocol or source model bundle missing.')
if OUT.exists():raise RuntimeError('Target asset resolution already exists; do not overwrite.')
P=json.loads(PROTO.read_text());expected=P['target_scenarios'];e1=Path(P['e1_directory'])
if not e1.is_dir():raise FileNotFoundError(e1)
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def header(path):
 try:
  if path.name.endswith('.csv'):return pd.read_csv(path,nrows=3,keep_default_na=False).columns.tolist()
  if 'conn.log' in path.name:
   with open(path,encoding='utf-8',errors='replace')as f:
    for line in f:
     if line.startswith('#fields'):return line.strip().split()[1:]
  return []
 except Exception:return []
# Only E1 output paths or a manifest-path reference are allowed. No whole corpus search.
manifest=e1/'blind_target_manifest.csv'
if not manifest.is_file():
 candidates=list(e1.glob('*.csv'));raise FileNotFoundError('blind target manifest missing: '+str(candidates))
targets=pd.read_csv(manifest,keep_default_na=False);targets=targets[targets.status.eq('ACCEPTED')]
rows=[];ambiguous=[]
for _,r in targets.iterrows():
 s=r.scenario;scenario_dirs=[p for p in e1.rglob('*') if p.is_dir() and s in str(p)]
 files=[]
 for d in scenario_dirs:
  files.extend([p for p in d.rglob('*') if p.is_file() and not p.is_symlink()])
 # also allow pcap/log paths explicitly recorded in the E1 manifest, if those columns exist.
 for col in targets.columns:
  if any(token in col.lower() for token in ['pcap_path','slice_path','conn_log_path','mapping_path']):
   v=str(r[col]);p=Path(v)
   if p.is_file():files.append(p)
 files=list(dict.fromkeys(files))
 pcaps=[p for p in files if p.name.lower().endswith(('.pcap','.pcapng','.pcap.gz'))]
 logs=[p for p in files if 'conn.log' in p.name.lower()]
 maps=[]
 for p in files:
  if p.suffix.lower()!='.csv':continue
  cols=header(p)
  if 'published_label' in cols or ('label' in cols and ('generated_line' in cols or 'reference_line' in cols)):maps.append((p,cols))
 result={'scenario':s,'manifest_accepted_plan':r.accepted_plan,'manifest_mapped_fraction':float(r.mapped_fraction),'files_under_E1_scenario_path':len(files),
  'pcap_candidates':len(pcaps),'conn_log_candidates':len(logs),'label_mapping_candidates':len(maps),
  'pcap_path':str(pcaps[0]) if len(pcaps)==1 else '','conn_log_path':str(logs[0]) if len(logs)==1 else '',
  'mapping_path':str(maps[0][0]) if len(maps)==1 else '',
  'pcap_sha256':sha(pcaps[0]) if len(pcaps)==1 else '','pcap_bytes':pcaps[0].stat().st_size if len(pcaps)==1 else None,
  'conn_log_sha256':sha(logs[0]) if len(logs)==1 else '','mapping_sha256':sha(maps[0][0]) if len(maps)==1 else '',
  'mapping_columns':'|'.join(maps[0][1]) if len(maps)==1 else '',
  'asset_resolution_status':'RESOLVED' if len(pcaps)==len(logs)==len(maps)==1 else 'AMBIGUOUS_OR_MISSING'}
 rows.append(result)
 if result['asset_resolution_status']!='RESOLVED':ambiguous.append({'scenario':s,'files': [str(p) for p in files][:200],'pcaps':[str(p)for p in pcaps],'logs':[str(p)for p in logs],'maps':[str(p)for p,_ in maps]})
OUT.mkdir();pd.DataFrame(rows).to_csv(OUT/'target_asset_resolution.csv',index=False);(OUT/'ambiguous_assets.json').write_text(json.dumps(ambiguous,indent=2))
receipt={'output_directory':str(OUT),'protocol_sha256':sha(PROTO),'source_model_sha256':sha(SOURCE),'frozen_targets':len(expected),'resolved_targets':sum(x['asset_resolution_status']=='RESOLVED'for x in rows),'ambiguous_targets':len(ambiguous),
 'target_payloads_read':False,'target_model_predictions_computed':False,'target_outcomes_inspected_for_model_evaluation':False,'attacks_executed':False,'Zeek_rerun':False,'NF_changed':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nTARGET ASSET RESOLUTION');print(pd.DataFrame(rows)[['scenario','asset_resolution_status','pcap_candidates','conn_log_candidates','label_mapping_candidates','pcap_bytes','mapping_columns']].to_string(index=False))
if ambiguous:print('\nAMBIGUOUS ASSETS');print(json.dumps(ambiguous,indent=2)[:15000])
