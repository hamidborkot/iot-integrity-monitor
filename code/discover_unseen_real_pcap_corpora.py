"""Real-PCAP candidate discovery only. No packet bytes, labels, outcomes, models or attacks are read.
Inventories mounted original capture/log/rule assets outside known IoT-23 design/target result directories, so we can choose a genuinely unseen confirmation corpus.
"""
import os,re,json
from collections import defaultdict
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd
ROOT=Path('/kaggle/input');OUT=Path('/kaggle/working')/('UNSEEN_REAL_PCAP_DISCOVERY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
EXCLUDE=['E1_BLIND_TARGETS','TRACE_','all-kaggle-work','complete-backup','whole-in-one','last-day-backup','the-last-update','ran-files','research-']
assets=[]
for d,dirs,names in os.walk(ROOT,followlinks=False):
 dirs[:]=[x for x in dirs if not any(z.lower() in str(Path(d)/x).lower() for z in EXCLUDE)]
 for n in names:
  p=Path(d)/n
  if p.is_symlink():continue
  low=n.lower();kind=''
  if low.endswith(('.pcap','.pcapng','.pcap.gz','.pcapng.gz')):kind='pcap'
  elif 'conn.log' in low or low.endswith(('.zeek','.bro')):kind='zeek_log'
  elif 'label' in low or 'groundtruth' in low or 'ground_truth' in low:kind='label_artifact'
  elif low in {'readme.md','readme.txt','readme.html'}:kind='metadata'
  if kind:assets.append({'path':str(p),'kind':kind,'bytes':p.stat().st_size,'dataset_root':'/'.join(p.relative_to(ROOT).parts[:4])})
df=pd.DataFrame(assets);df.to_csv(OUT/'raw_asset_inventory.csv',index=False)
summary=df.groupby(['dataset_root','kind']).agg(files=('path','count'),bytes=('bytes','sum')).reset_index() if len(df) else pd.DataFrame()
summary.to_csv(OUT/'raw_asset_summary.csv',index=False)
wide=summary.pivot_table(index='dataset_root',columns='kind',values='files',fill_value=0,aggfunc='sum').reset_index() if len(summary) else pd.DataFrame()
if len(wide):
 for c in ['pcap','zeek_log','label_artifact','metadata']:
  if c not in wide:wide[c]=0
 wide['candidate_full_triplet']=(wide.pcap>0)&(wide.zeek_log>0)&(wide.label_artifact>0)
wide.to_csv(OUT/'candidate_corpus_summary.csv',index=False)
receipt={'output_directory':str(OUT),'roots_scanned':[str(ROOT)],'asset_rows':len(df),'candidate_corpora_with_pcap_log_label':int(wide.candidate_full_triplet.sum()) if len(wide) else 0,
 'pcap_payloads_read':False,'label_rows_read':False,'models_trained':False,'predictions_computed':False,'attacks_executed':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nCANDIDATE CORPORA');print(wide.sort_values(['candidate_full_triplet','pcap'],ascending=False).to_string(index=False) if len(wide) else 'None')
