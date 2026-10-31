"""Transformability census for padding/injection design. Reads existing linked records only.
No Zeek, no models, no attacks, no selection by model outcome. Descriptive counts of what the frozen trace data can support.
"""
import glob,json,re
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd

WORK=Path('/kaggle/working')
OUT=WORK/('TRACE_TRANSFORMABILITY_CENSUS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
sources=[]
for p in sorted(glob.glob(str(WORK/'TRACE_LINKAGE_BATCH_v1/*/*/linked_records.csv'))):
 sources.append((Path(p).parts[-3],p,'batch_v1_linked_records'))
for p in sorted(glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/unique_exact_key_mapping.csv'))):
 sel=Path(p).parent/'smoke_selection.json'
 name=json.loads(sel.read_text())['scenario'] if sel.is_file() else 'UNKNOWN'
 sources.append((name,p,'clean_replay_mapping'))
if not sources:raise FileNotFoundError('No restored linked-record sources found.')

def bucket(x):
 if pd.isna(x):return 'missing'
 return '1' if x<=1 else '2-3' if x<=3 else '4-10' if x<=10 else '>10'
proto_counts={};pkt_counts={};inventory=[]
for scenario,path,kind in sources:
 header=pd.read_csv(path,nrows=0).columns.tolist()
 pkt='orig_pkts' if 'orig_pkts' in header else 'orig_pkts_generated' if 'orig_pkts_generated' in header else None
 if 'proto' not in header or 'published_label' not in header or pkt is None:
  inventory.append({'scenario':scenario,'path':path,'status':'SCHEMA_INCOMPATIBLE','rows':0});continue
 rows=0
 for chunk in pd.read_csv(path,usecols=['proto','published_label',pkt],dtype=str,chunksize=500000):
  rows+=len(chunk)
  chunk['proto']=chunk['proto'].str.lower();chunk['label']=chunk['published_label'].str.lower()
  chunk['pkt_bucket']=pd.to_numeric(chunk[pkt],errors='coerce').map(bucket)
  for key,n in chunk.groupby(['proto','label']).size().items():proto_counts[(scenario,path,)+key]=proto_counts.get((scenario,path,)+key,0)+int(n)
  for key,n in chunk.groupby(['pkt_bucket','label']).size().items():pkt_counts[(scenario,path,)+key]=pkt_counts.get((scenario,path,)+key,0)+int(n)
 inventory.append({'scenario':scenario,'path':path,'status':'COUNTED','rows':rows})
proto=pd.DataFrame([{'scenario':a,'source':b,'proto':c,'label':d,'flows':n}for (a,b,c,d),n in proto_counts.items()])
pkts=pd.DataFrame([{'scenario':a,'source':b,'orig_pkt_bucket':c,'label':d,'flows':n}for (a,b,c,d),n in pkt_counts.items()])
proto.to_csv(OUT/'proto_by_label.csv',index=False);pkts.to_csv(OUT/'orig_packets_by_label.csv',index=False)
inv=pd.DataFrame(inventory);inv.to_csv(OUT/'sources_counted.csv',index=False)
summary=[]
for (scenario,source),g in proto.groupby(['scenario','source']):
 mal=g[g.label=='malicious'].flows.sum();ben=g[g.label=='benign'].flows.sum()
 def frac(label,protocol):
  total=g[g.label==label].flows.sum()
  return float(g[(g.label==label)&(g.proto==protocol)].flows.sum()/total) if total else None
 p=pkts[(pkts.scenario==scenario)&(pkts.source==source)]
 mt=p[p.label=='malicious'].flows.sum()
 summary.append({'scenario':scenario,'rows':int(mal+ben),'malicious':int(mal),'benign':int(ben),
  'malicious_tcp_fraction':frac('malicious','tcp'),'malicious_udp_fraction':frac('malicious','udp'),'malicious_icmp_fraction':frac('malicious','icmp'),
  'benign_tcp_fraction':frac('benign','tcp'),'benign_udp_fraction':frac('benign','udp'),
  'malicious_single_packet_fraction':float(p[(p.label=='malicious')&(p.orig_pkt_bucket=='1')].flows.sum()/mt) if mt else None,
  'malicious_over_3_packets_fraction':float(p[(p.label=='malicious')&(p.orig_pkt_bucket.isin(['4-10','>10']))].flows.sum()/mt) if mt else None})
sm=pd.DataFrame(summary);sm.to_csv(OUT/'transformability_summary.csv',index=False)
receipt={'output_directory':str(OUT),'sources_counted':int((inv.status=='COUNTED').sum()),'sources_incompatible':int((inv.status!='COUNTED').sum()),
 'models_trained':False,'attacks_executed':False,'Zeek_rerun':False,'selection_by_model_outcome':False,'purpose':'Design evidence for padding/injection feasibility only'}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2));print('\nSOURCES');print(inv.to_string(index=False))
print('\nTRANSFORMABILITY SUMMARY');print(sm.round(4).to_string(index=False))
print('\nPROTO x LABEL');print(proto.sort_values(['scenario','flows'],ascending=[True,False]).to_string(index=False))
print('\nORIG PACKETS x LABEL');print(pkts.sort_values(['scenario','flows'],ascending=[True,False]).to_string(index=False))
