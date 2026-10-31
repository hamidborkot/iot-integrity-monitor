"""TRACE STEP 2A.1: corrected target resolver. Fix: E1 features.csv.gz is the frozen label+feature mapping artifact.
No target predictions, model use, Zeek replay or transformations. Reads only gzip CSV headers and first 3 rows.
"""
import gzip,hashlib,json
from pathlib import Path
import pandas as pd
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';OUT=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1_1'
if not PROTO.is_file() or not SOURCE.is_file():raise FileNotFoundError('Frozen protocol/source bundle missing.')
if OUT.exists():raise RuntimeError('Corrected asset resolution exists; do not overwrite.')
P=json.loads(PROTO.read_text());E1=Path(P['e1_directory']);manifest=E1/'blind_target_manifest.csv';targets=pd.read_csv(manifest,keep_default_na=False);targets=targets[targets.status.eq('ACCEPTED')]
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def cols(p):
 try:
  return pd.read_csv(p,nrows=3,compression='gzip' if p.name.endswith('.gz') else None,keep_default_na=False).columns.tolist()
 except Exception as e:return ['__ERROR__'+type(e).__name__]
rows=[];errors=[]
for _,r in targets.iterrows():
 d=E1/r.scenario;pcap=d/'slice.pcap';log=d/'conn.log.gz';feat=d/'features.csv.gz';c=cols(feat)
 missing=[str(p)for p in [pcap,log,feat]if not p.is_file()]
 required={'published_label','proto','duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'}
 missing_cols=sorted(required-set(c))
 status='RESOLVED' if not missing and not missing_cols else 'MISSING_FILE_OR_REQUIRED_COLUMNS'
 rows.append({'scenario':r.scenario,'status':status,'pcap_path':str(pcap),'conn_log_path':str(log),'features_path':str(feat),'pcap_bytes':pcap.stat().st_size if pcap.is_file() else None,
  'pcap_sha256':sha(pcap)if pcap.is_file()else'','conn_log_sha256':sha(log)if log.is_file()else'','features_sha256':sha(feat)if feat.is_file()else'',
  'features_columns':'|'.join(c),'missing_files':'|'.join(missing),'missing_required_columns':'|'.join(missing_cols),'manifest_mapped_fraction':float(r.mapped_fraction)})
 if status!='RESOLVED':errors.append({'scenario':r.scenario,'missing':missing,'missing_cols':missing_cols,'columns':c})
OUT.mkdir();pd.DataFrame(rows).to_csv(OUT/'target_asset_resolution.csv',index=False);(OUT/'errors.json').write_text(json.dumps(errors,indent=2))
receipt={'output_directory':str(OUT),'protocol_sha256':sha(PROTO),'source_model_sha256':sha(SOURCE),'frozen_targets':len(targets),'resolved_targets':sum(x['status']=='RESOLVED'for x in rows),'errors':len(errors),
 'target_model_predictions_computed':False,'target_outcomes_inspected_for_model_evaluation':False,'attacks_executed':False,'Zeek_rerun':False,'NF_changed':False,'next_step':'If all eight resolved, run frozen real-PCAP transformation validity/preparation.'}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print(pd.DataFrame(rows)[['scenario','status','pcap_bytes','manifest_mapped_fraction','missing_required_columns']].to_string(index=False))
if errors:print(json.dumps(errors,indent=2)[:12000])
