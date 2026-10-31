"""REAL-PACKET pacing validation on Capture-8-1 (design data). Cheapest-evasion profile said: +100 s duration flips LR(ALL9) on all eligible flows.
Transformation: delay every packet of an eligible malicious TCP flow EXCEPT its first by d seconds (bytes/order untouched), stable re-sort, re-extract with Zeek,
evaluate detectors on RE-EXTRACTED features. d=0 is the pipeline null control. Not prospective confirmation; no TCP/application-semantics claim."""
import bisect,glob,hashlib,ipaddress,json,struct,subprocess,warnings
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');ZEEK='/opt/zeek/bin/zeek';SEED=7;TRAIN_PER_CLASS=40000;DELAYS=[0.0,1.0,10.0,100.0];GATE_DROP=0.05
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'];PROTOS=['tcp','udp','icmp']
MAGICS={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def zkey(ts,o,op,r,rp,pr):return (int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),o,str(op),r,str(rp),pr.lower())
def parse_zeek(path):
 fields=None;rows=[]
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   rows.append(dict(zip(fields,line.rstrip().split())))
 return pd.DataFrame(rows)
def read_pcap(path):
 data=Path(path).read_bytes();magic=data[:4]
 if magic not in MAGICS:raise ValueError('Only classic pcap supported (pcapng refused).')
 endian,unit=MAGICS[magic];header=data[:24];network=struct.unpack(endian+'I',data[20:24])[0];pos=24;packets=[]
 while pos+16<=len(data):
  sec,frac,incl,orig=struct.unpack(endian+'IIII',data[pos:pos+16]);pos+=16;payload=data[pos:pos+incl];pos+=incl
  if len(payload)!=incl:raise ValueError('Truncated pcap record.')
  packets.append((sec*10**9+frac*unit,orig,payload))
 if pos!=len(data):raise ValueError('Trailing bytes after last pcap record.')
 return header,endian,unit,network,packets
def write_pcap(path,header,endian,unit,packets,order,new_ts):
 with open(path,'wb')as f:
  f.write(header)
  for i in order:
   _,orig,payload=packets[i];t=new_ts[i];f.write(struct.pack(endian+'IIII',t//10**9,(t%10**9)//unit,len(payload),orig));f.write(payload)
def parse_tcp(payload,network):
 try:
  if network==1:
   et=struct.unpack('!H',payload[12:14])[0];off=14
   while et in(0x8100,0x88a8):et=struct.unpack('!H',payload[off+2:off+4])[0];off+=4
  elif network==113:et=struct.unpack('!H',payload[14:16])[0];off=16
  elif network==101:off=0;et=0x0800 if payload[0]>>4==4 else 0x86dd
  else:return None
  ip=payload[off:]
  if et==0x0800:
   if len(ip)<20 or ip[9]!=6:return None
   ihl=(ip[0]&15)*4;src=str(ipaddress.IPv4Address(ip[12:16]));dst=str(ipaddress.IPv4Address(ip[16:20]));tcp=ip[ihl:]
  elif et==0x86dd:
   if len(ip)<40 or ip[6]!=6:return None
   src=str(ipaddress.IPv6Address(ip[8:24]));dst=str(ipaddress.IPv6Address(ip[24:40]));tcp=ip[40:]
  else:return None
  if len(tcp)<4:return None
  sport,dport=struct.unpack('!HH',tcp[:4]);return src,sport,dst,dport
 except Exception:return None
def assign_packets(packets,network,flows):
 table=defaultdict(list)
 for fi,row in enumerate(flows.itertuples(index=False)):
  if row.proto.lower()!='tcp':continue
  start=int(Decimal(row.ts)*Decimal(10**9));dur=0 if row.duration=='-' else int(Decimal(row.duration)*Decimal(10**9))
  tup=tuple(sorted([(row._2,int(row._3)),(row._4,int(row._5))]))
  table[tup].append((start,start+dur+1_000_000,fi))
 starts={}
 for tup in table:table[tup].sort();starts[tup]=[x[0] for x in table[tup]]
 per_flow=defaultdict(list)
 for i,(ts,_,payload) in enumerate(packets):
  p=parse_tcp(payload,network)
  if p is None:continue
  tup=tuple(sorted([(p[0],p[1]),(p[2],p[3])]))
  if tup not in table:continue
  j=bisect.bisect_right(starts[tup],ts)-1
  if j>=0 and ts<=table[tup][j][1]:per_flow[table[tup][j][2]].append(i)
 for fi in per_flow:per_flow[fi].sort(key=lambda i:(packets[i][0],i))
 return per_flow
def transform(packets,per_flow,selected,d_seconds):
 new=[p[0] for p in packets];delta=int(round(d_seconds*10**9))
 for fi in selected:
  plist=per_flow.get(fi,[])
  for i in plist[1:]:new[i]+=delta
 order=sorted(range(len(packets)),key=lambda i:(new[i],i));return new,order
def verify_packets(original,new_path,order,new,per_flow,selected):
 _,_,_,_,out=read_pcap(new_path);ok={}
 ok['packet_count_equal']=len(out)==len(original)
 ok['packet_bytes_multiset_equal']=Counter(hashlib.sha1(p[2]).hexdigest()+str(p[1]) for p in original)==Counter(hashlib.sha1(p[2]).hexdigest()+str(p[1]) for p in out)
 pos={idx:k for k,idx in enumerate(order)}
 ok['per_flow_packet_order_preserved']=all(all(pos[a]<pos[b] for a,b in zip(pl,pl[1:])) for pl in per_flow.values())
 ok['no_packet_advanced']=all(new[i]>=original[i][0] for i in range(len(original)))
 ok['nonselected_timestamps_unchanged']=all(new[i]==original[i][0] for fi,pl in per_flow.items() if fi not in selected for i in pl)
 ok['output_timestamps_nondecreasing']=all(out[k][0]<=out[k+1][0] for k in range(len(out)-1))
 return ok
def clean(df):
 df=df.copy();df['proto']=df['proto'].astype(str).str.lower();df['label']=df['published_label'].astype(str).str.lower()
 df=df[df.label.isin(['benign','malicious'])]
 for c in NUM:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 df['y']=(df.label=='malicious').astype(int);return df[NUM+['proto','y']].reset_index(drop=True)
def load_linked(s):
 files=sorted(glob.glob(str(WORK/f'TRACE_LINKAGE_BATCH_v1/{s}/*/linked_records.csv')),key=lambda p:Path(p).stat().st_size,reverse=True)
 return clean(pd.read_csv(files[0],usecols=NUM+['proto','published_label'],dtype=str))
def matrix(df,fs,log=False):
 parts=[];x=df[NUM].to_numpy(float);parts.append(np.log1p(x) if log else x)
 parts.append(np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS]));return np.hstack(parts)
def sample_train(frames):
 parts=[]
 for df in frames:
  for y in(0,1):
   part=df[df.y==y];parts.append(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED))
 return pd.concat(parts,ignore_index=True)
def detectors(train):
 hgb=HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(matrix(train,'ALL9'),train.y)
 sc=StandardScaler().fit(matrix(train,'ALL9',True));lr=LogisticRegression(max_iter=300,class_weight='balanced').fit(sc.transform(matrix(train,'ALL9',True)),train.y)
 return {'LOSO_HGB_ALL9':lambda d:hgb.predict(matrix(d,'ALL9')),'LOSO_LR_ALL9':lambda d:lr.predict(sc.transform(matrix(d,'ALL9',True)))}
def features(conn,labels):
 conn=conn.copy();conn['k']=[zkey(r.ts,r._2,r._3,r._4,r._5,r.proto) for r in conn.rename(columns={'id.orig_h':'_2','id.orig_p':'_3','id.resp_h':'_4','id.resp_p':'_5'}).itertuples(index=False)]
 conn['published_label']=conn.k.map(labels);matched=conn[conn.published_label.notna()].copy()
 frame=clean(matched[NUM+['proto','published_label']]);frame['k']=matched.loc[matched.published_label.str.lower().isin(['benign','malicious']),'k'].values
 return frame,len(conn)-len(matched)
def main():
 OUT=WORK/('TRACE_PACKET_PACING_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
 dirs=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json')) if json.loads(Path(p).read_text()).get('scenario')=='CTU-IoT-Malware-Capture-8-1']
 if len(dirs)!=1:raise RuntimeError('Expected one Capture-8-1 clean replay.')
 sel=json.loads((dirs[0]/'smoke_selection.json').read_text());capture=Path(sel['capture'])
 if not capture.is_file() or sha(capture)!=sel['pcap_sha256']:raise RuntimeError('Capture missing or changed.')
 gen=parse_zeek(dirs[0]/'clean_replay/conn.log');mp=pd.read_csv(dirs[0]/'unique_exact_key_mapping.csv',dtype=str)
 labels={(int(a),b,c,e,f,g.lower()):l for a,b,c,e,f,g,l in zip(mp.timestamp_microseconds,mp.orig_h,mp.orig_p,mp.resp_h,mp.resp_p,mp.proto,mp.published_label)}
 gen['k']=[zkey(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto']) for _,r in gen.iterrows()]
 gen['label']=gen.k.map(labels).str.lower()
 if gen.label.isna().any():raise RuntimeError('Unlabeled original flow.')
 flows=gen.rename(columns={'id.orig_h':'_2','id.orig_p':'_3','id.resp_h':'_4','id.resp_p':'_5'})[['ts','proto','_2','_3','_4','_5','duration']].copy()
 flows=flows[['ts','proto','_2','_3','_4','_5','duration']]
 flows.columns=['ts','proto','_2','_3','_4','_5','duration']
 header,endian,unit,network,packets=read_pcap(capture)
 # namedtuple fields starting with underscore are renamed by itertuples; use positional names via explicit columns
 flows=flows.rename(columns={'_2':'o_h','_3':'o_p','_4':'r_h','_5':'r_p'})
 class R:  # lightweight row view for assign_packets
  def __init__(s,t):s.ts,s.proto,s._2,s._3,s._4,s._5,s.duration=t
 flow_rows=pd.DataFrame({'ts':flows.ts,'proto':flows.proto,'o_h':flows.o_h,'o_p':flows.o_p,'r_h':flows.r_h,'r_p':flows.r_p,'duration':flows.duration})
 per_flow=assign_packets(packets,network,pd.DataFrame(flow_rows.values,columns=['ts','proto','_2','_3','_4','_5','duration']))
 pk=pd.to_numeric(gen.orig_pkts.replace('-',np.nan),errors='coerce').fillna(0)+pd.to_numeric(gen.resp_pkts.replace('-',np.nan),errors='coerce').fillna(0)
 selected=set(np.flatnonzero(((gen.label=='malicious')&(gen.proto.str.lower()=='tcp')&(pk>=2)).to_numpy()))
 consistent=np.mean([len(per_flow.get(fi,[]))==int(pk.iloc[fi]) for fi in selected]) if selected else 0
 train=sample_train([load_linked('CTU-IoT-Malware-Capture-1-1'),load_linked('CTU-IoT-Malware-Capture-3-1')]);models=detectors(train)
 baseline=None;rows=[]
 for d in DELAYS:
  job=OUT/f'delay_{d:g}s';job.mkdir();new,order=transform(packets,per_flow,selected,d);pcap=job/'transformed.pcap'
  write_pcap(pcap,header,endian,unit,packets,order,new);checks=verify_packets(packets,pcap,order,new,per_flow,selected)
  run=subprocess.run([ZEEK,'-C','-r',str(pcap)],cwd=job,capture_output=True,text=True,timeout=900)
  if run.returncode or not (job/'conn.log').is_file():raise RuntimeError('Zeek failed: '+run.stderr[-500:])
  conn=parse_zeek(job/'conn.log');frame,unmatched=features(conn,labels);frame=frame.set_index('k')
  if d==0.0:baseline=frame
  common=frame.index.intersection(baseline.index);cur=frame.loc[common];base=baseline.loc[common]
  sel_keys={gen.k.iloc[i] for i in selected};sel_mask=cur.index.isin(sel_keys)
  numeric_same=np.isclose(cur[NUM].to_numpy(float),base[NUM].to_numpy(float)).all(axis=1)
  dur_inc=(cur.loc[sel_mask,'duration']-base.loc[sel_mask,'duration']) if sel_mask.any() else pd.Series(dtype=float)
  counters=[c for c in NUM if c!='duration'];counters_same=np.isclose(cur.loc[sel_mask,counters].to_numpy(float),base.loc[sel_mask,counters].to_numpy(float)).all(axis=1).mean() if sel_mask.any() else np.nan
  for name,predict in models.items():
   p0=predict(base);p1=predict(cur);mal=cur.y.to_numpy()==1;det=(p0==1)&mal;eligible=sel_mask&mal
   rec0=((p0==1)&mal).sum()/mal.sum();rec1=((p1==1)&mal).sum()/mal.sum()
   rows.append({'delay_s':d,'detector':name,'matched_flows':len(common),'unmatched_or_new_flows':unmatched,'selected_flows':len(sel_mask[sel_mask]),
    'baseline_malicious_recall':rec0,'recall_after_real_packet_transform':rec1,'real_recall_drop':rec0-rec1,
    'evaded_fraction_of_detected_eligible':float(((p1==0)&det&eligible).sum()/max((det&eligible).sum(),1)),
    'median_selected_duration_increase_s':float(dur_inc.median()) if len(dur_inc) else np.nan,
    'selected_counters_unchanged_fraction':float(counters_same),'nonselected_any_change_fraction':float((~numeric_same[~sel_mask]).mean()) if (~sel_mask).any() else np.nan,
    'packet_flow_assignment_consistency_selected':float(consistent),**{f'check_{k}':v for k,v in checks.items()}})
 res=pd.DataFrame(rows);res.to_csv(OUT/'real_packet_pacing_results.csv',index=False)
 valid=res[[c for c in res if c.startswith('check_')]].all(axis=None)
 big=res[(res.delay_s>0)&(res.real_recall_drop>=GATE_DROP)]
 gate='REAL_PACKET_DAMAGE_CONFIRMED_FOR_PACING' if valid and len(big) else ('PACKET_CHECKS_FAILED' if not valid else 'NO_REAL_PACKET_DAMAGE_ABOVE_THRESHOLD')
 receipt={'output_directory':str(OUT),'gate_result':gate,'selected_eligible_flows':len(selected),'packet_assignment_consistency':float(consistent),'all_packet_checks_passed':bool(valid),
  'bound_to_compare_LR_8_1':0.2501,'models_for_confirmatory_use_trained':False,'prospective_confirmation':False,'TCP_semantic_validity_certified':False,'application_functionality_tested':False}
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 print('\nREAL-PACKET PACING RESULTS (Capture-8-1; d=0 is pipeline null control)');print(res.drop(columns=[c for c in res if c.startswith('check_')]).round(4).to_string(index=False))
 print('\nPACKET VALIDITY CHECKS');print(res[['delay_s']+[c for c in res if c.startswith('check_')]].drop_duplicates('delay_s').to_string(index=False))
if __name__=='__main__' or True:main()
