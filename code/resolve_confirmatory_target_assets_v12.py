"""TRACE STEP 2A.2: final target asset resolver. In E1, y is the frozen binary published-label field (0 benign, 1 malicious); it is not synthetic.
No target model use, predictions, replay or transformation."""
import gzip,hashlib,json
from pathlib import Path
import pandas as pd
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';OUT=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1_2'
if not PROTO.is_file() or not SOURCE.is_file():raise FileNotFoundError('Frozen protocol/source bundle missing.')
if OUT.exists():raise RuntimeError('Final asset resolution exists; do not overwrite.')
P=json.loads(PROTO.read_text());E1=Path(P['e1_directory']);targets=pd.read_csv(E1/'blind_target_manifest.csv',keep_default_na=False);targets=targets[targets.status.eq('ACCEPTED')]
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def inspect(p):
 t=pd.read_csv(p,nrows=3,compression='gzip',keep_default_na=False);return list(t.columns),t
need={'ks','ts','resp_p','proto','duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','y'}
rows=[];errors=[]
for _,r in targets.iterrows():
 d=E1/r.scenario;pcap=d/'slice.pcap';log=d/'conn.log.gz';feat=d/'features.csv.gz';c,t=inspect(feat);missing=sorted(need-set(c));valid_y=not missing and set(pd.to_numeric(t.y,errors='coerce').dropna().unique()).issubset({0,1})
 status='RESOLVED' if pcap.is_file() and log.is_file() and feat.is_file() and valid_y else 'MISSING_FILE_OR_SCHEMA'
 rows.append({'scenario':r.scenario,'status':status,'pcap_path':str(pcap),'conn_log_path':str(log),'features_path':str(feat),'pcap_bytes':pcap.stat().st_size if pcap.is_file()else None,
 'pcap_sha256':sha(pcap)if pcap.is_file()else'','conn_log_sha256':sha(log)if log.is_file()else'','features_sha256':sha(feat)if feat.is_file()else'',
 'features_columns':'|'.join(c),'label_field':'y (0=benign, 1=malicious)','manifest_mapped_fraction':float(r.mapped_fraction),'missing_required_columns':'|'.join(missing)})
 if status!='RESOLVED':errors.append({'scenario':r.scenario,'missing':missing,'preview':t.to_dict('records')})
OUT.mkdir();pd.DataFrame(rows).to_csv(OUT/'target_asset_resolution.csv',index=False);(OUT/'errors.json').write_text(json.dumps(errors,indent=2))
receipt={'output_directory':str(OUT),'protocol_sha256':sha(PROTO),'source_model_sha256':sha(SOURCE),'frozen_targets':len(targets),'resolved_targets':sum(x['status']=='RESOLVED'for x in rows),'errors':len(errors),
 'target_label_representation':'Existing E1 y column; 0=benign and 1=malicious; labels are frozen published-label mapping values.','target_model_predictions_computed':False,'target_outcomes_inspected_for_model_evaluation':False,'attacks_executed':False,'Zeek_rerun':False,'NF_changed':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print(pd.DataFrame(rows)[['scenario','status','pcap_bytes','manifest_mapped_fraction','label_field','missing_required_columns']].to_string(index=False))
if errors:print(json.dumps(errors,indent=2)[:12000])
