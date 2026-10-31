"""Read-only diagnosis of a failed frozen confirmation. No retry, no deletion, no model or attack computation."""
import json,shutil
from pathlib import Path
import pandas as pd
WORK=Path('/kaggle/working');OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'
if not OUT.is_dir():raise FileNotFoundError(OUT)
fail=OUT/'failures.csv';partial=OUT/'all_target_seed_estimator_results.csv'
print('DISK FREE GiB:',round(shutil.disk_usage(WORK).free/1024**3,3))
if fail.is_file():
 f=pd.read_csv(fail,keep_default_na=False);print('\nFAILURES');print(f[['scenario','error']].to_string(index=False));
 for r in f.itertuples(index=False):
  print('\nTRACE FOR',r.scenario);print(str(r.trace)[-4000:] if hasattr(r,'trace') else '')
else:print('failures.csv missing')
if partial.is_file():
 p=pd.read_csv(partial);print('\nPARTIAL RESULT ROWS:',len(p));print(p.groupby(['scenario','attack']).size().to_string())
else:print('\nNo partial result rows written.')
print('\nTARGET JOB STATE')
rows=[]
for d in sorted(OUT.glob('CTU-*')):
 for a in sorted(d.iterdir()):
  if not a.is_dir():continue
  rows.append({'scenario':d.name,'attack':a.name,'receipt':(a/'receipt.json').is_file(),'pcap':(a/'transformed.pcap').exists(),'conn_log':(a/'conn.log').exists(),'files':[x.name for x in a.iterdir()]})
print(pd.DataFrame(rows).to_string(index=False))
