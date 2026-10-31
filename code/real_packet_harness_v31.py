"""REAL-PACKET harness v3.1 on Capture-8-1 (design data). Fix: baseline recalls are kept for every detector (v3 reset them and raised KeyError).
Label inheritance for flows Zeek splits off; unique keys; finer delays; injection harness. Zeek's default SYN timeout is 5 s, so delays above ~5 s may SPLIT unanswered-SYN flows.
Pacing = delay all packets of eligible malicious TCP flows except the first; injection = duplicate the last header-only originator packet k times, 1 microsecond apart.
Pacing d=0 is the pipeline null control. Not prospective confirmation; no TCP/application-semantics claim."""
import bisect,glob,hashlib,ipaddress,json,struct,subprocess,traceback,warnings
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');ZEEK='/opt/zeek/bin/zeek';SEED=7;TRAIN_PER_CLASS=40000;GATE_DROP=0.05
DELAYS=[0.0,1.0,3.0,4.5,6.0,10.0,100.0];INJECT_K=[1,3]
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'];PROTOS=['tcp','udp','icmp']
MAGICS={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def zkey(ts,o,op,r,rp,pr):return (int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),o,str(op),r,str(rp),pr.lower())
def skey(k):return '|'.join(map(str,k))
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
   ihl=(ip[0]&15)*4;total=struct.unpack('!H',ip[2:4])[0];src=str(ipaddress.IPv4Address(ip[12:16]));dst=str(ipaddress.IPv4Address(ip[16:20]));tcp=ip[ihl:];hdr=ihl
  elif et==0x86dd:
   if len(ip)<40 or ip[6]!=6:return None
   total=40+struct.unpack('!H',ip[4:6])[0];src=str(ipaddress.IPv6Address(ip[8:24]));dst=str(ipaddress.IPv6Address(ip[24:40]));tcp=ip[40:];hdr=40
  else:return None
  if len(tcp)<14:return None
  sport,dport=struct.unpack('!HH',tcp[:4]);data_off=(tcp[12]>>4)*4
  return {'src':src,'sport':sport,'dst':dst,'dport':dport,'flags':tcp[13],'payload_len':max(total-hdr-data_off,0),'ip_total':total}
 except Exception:return None
def assign_packets(packets,network,flow_list):
 table=defaultdict(list)
 for fi,(ts,proto,oh,op,rh,rp,duration) in enumerate(flow_list):
  if proto.lower()!='tcp':continue
  start=int(Decimal(ts)*Decimal(10**9));dur=0 if duration=='-' else int(Decimal(duration)*Decimal(10**9))
  table[tuple(sorted([(oh,int(op)),(rh,int(rp))]))].append((start,start+dur+1_000_000,fi))
 starts={}
 for tup in table:table[tup].sort();starts[tup]=[x[0] for x in table[tup]]
 per_flow=defaultdict(list);info={}
 for i,(ts,_,payload) in enumerate(packets):
  p=parse_tcp(payload,network)
  if p is None:continue
  info[i]=p;tup=tuple(sorted([(p['src'],p['sport']),(p['dst'],p['dport'])]))
  if tup not in table:continue
  j=bisect.bisect_right(starts[tup],ts)-1
  if j>=0 and ts<=table[tup][j][1]:per_flow[table[tup][j][2]].append(i)
 for fi in per_flow:per_flow[fi].sort(key=lambda i:(packets[i][0],i))
 return per_flow,info
def transform_pacing(packets,per_flow,selected,d_seconds):
 new=[p[0] for p in packets];delta=int(round(d_seconds*10**9))
 for fi in selected:
  for i in per_flow.get(fi,[])[1:]:new[i]+=delta
 return packets,new,sorted(range(len(packets)),key=lambda i:(new[i],i)),{}
def transform_injection(packets,per_flow,info,flow_list,selected,k):
 out=list(packets);new=[p[0] for p in packets];injected={}
 for fi in sorted(selected):
  oh,op=flow_list[fi][2],int(flow_list[fi][3]);cand=[i for i in per_flow.get(fi,[]) if i in info and info[i]['src']==oh and info[i]['sport']==op and info[i]['payload_len']==0]
  if not cand:continue
  i=cand[-1];ts,orig,payload=packets[i];injected[fi]=(i,info[i]['ip_total'])
  for j in range(1,k+1):out.append((ts+j*1000,orig,payload));new.append(ts+j*1000)
 return out,new,sorted(range(len(out)),key=lambda i:(new[i],i)),injected
def verify(original,new_path,order,new,per_flow,injected,k):
 _,_,_,_,read=read_pcap(new_path);sig=lambda ps:Counter(hashlib.sha1(p[2]).hexdigest()+str(p[1]) for p in ps);ok={}
 expected=sig(original)
 for fi,(i,_) in injected.items():expected[hashlib.sha1(original[i][2]).hexdigest()+str(original[i][1])]+=k
 n=len(original);ok['packet_multiset_as_designed']=sig(read)==expected and len(read)==n+k*len(injected)
 ok['original_timestamps_not_advanced']=all(new[i]>=original[i][0] for i in range(n))
 pos={idx:q for q,idx in enumerate(order)}
 ok['per_flow_original_order_preserved']=all(all(pos[a]<pos[b] for a,b in zip(pl,pl[1:])) for pl in per_flow.values())
 ok['output_timestamps_nondecreasing']=all(read[q][0]<=read[q+1][0] for q in range(len(read)-1))
 return ok
def clean(df):
 df=df.copy();df['proto']=df['proto'].astype(str).str.lower();df['label']=df['published_label'].astype(str).str.lower()
 df=df[df.label.isin(['benign','malicious'])]
 for c in NUM:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 df['y']=(df.label=='malicious').astype(int);return df
def load_linked(s):
 files=sorted(glob.glob(str(WORK/f'TRACE_LINKAGE_BATCH_v1/{s}/*/linked_records.csv')),key=lambda p:Path(p).stat().st_size,reverse=True)
 if not files:raise FileNotFoundError(s)
 return clean(pd.read_csv(files[0],usecols=NUM+['proto','published_label'],dtype=str))[NUM+['proto','y']].reset_index(drop=True)
def matrix(df,log=False):
 x=df[NUM].to_numpy(float);return np.hstack([np.log1p(x) if log else x,np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS])])
def sample_train(frames):
 parts=[]
 for df in frames:
  for y in(0,1):
   part=df[df.y==y];parts.append(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED))
 return pd.concat(parts,ignore_index=True)
def detectors(train):
 hgb=HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(matrix(train),train.y)
 sc=StandardScaler().fit(matrix(train,True));lr=LogisticRegression(max_iter=300,class_weight='balanced').fit(sc.transform(matrix(train,True)),train.y)
 return {'LOSO_HGB_ALL9':lambda d:hgb.predict(matrix(d)),'LOSO_LR_ALL9':lambda d:lr.predict(sc.transform(matrix(d,True)))}
def build_parents(gen,labels_by_row):
 parents=defaultdict(list)
 for r,(ts,pr,oh,op,rh,rp,du) in enumerate(zip(gen['ts'],gen['proto'],gen['id.orig_h'],gen['id.orig_p'],gen['id.resp_h'],gen['id.resp_p'],gen['duration'])):
  start=int((Decimal(ts)*Decimal(10**6)).to_integral_value(rounding=ROUND_HALF_EVEN));dur=0 if du=='-' else int((Decimal(du)*Decimal(10**6)).to_integral_value(rounding=ROUND_HALF_EVEN))
  parents[(tuple(sorted([(oh,str(op)),(rh,str(rp))])),pr.lower())].append((start,start+dur,labels_by_row[r],skey(zkey(ts,oh,op,rh,rp,pr))))
 starts={}
 for k in parents:parents[k].sort();starts[k]=[x[0] for x in parents[k]]
 return parents,starts
def features(conn,labels,parents,starts,shift_us):
 conn=conn.copy();kt=[zkey(a,b,c,d,e,f) for a,b,c,d,e,f in zip(conn['ts'],conn['id.orig_h'],conn['id.orig_p'],conn['id.resp_h'],conn['id.resp_p'],conn['proto'])]
 lab=[];inh=[];par=[]
 for k in kt:
  if k in labels:lab.append(labels[k]);inh.append(0);par.append('');continue
  tup=(tuple(sorted([(k[1],k[2]),(k[3],k[4])])),k[5]);t=k[0]-shift_us;label=None;parent=''
  if tup in parents:
   j=bisect.bisect_right(starts[tup],t)-1
   if j>=0 and t<=parents[tup][j][1]+1000:label,parent=parents[tup][j][2],parents[tup][j][3]
  lab.append(label);inh.append(1 if label else 0);par.append(parent)
 conn['published_label']=lab;conn['inherited']=inh;conn['parent']=par;conn['ks']=[skey(k) for k in kt]
 unlabeled=int(conn.published_label.isna().sum());conn=conn[conn.published_label.notna()]
 frame=clean(conn);dup=int(frame.ks.duplicated(keep=False).sum());frame=frame[~frame.ks.duplicated(keep=False)].set_index('ks')
 return frame,unlabeled,dup
def main():
 OUT=WORK/('TRACE_PACKET_HARNESS_V31_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
 dirs=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json')) if json.loads(Path(p).read_text()).get('scenario')=='CTU-IoT-Malware-Capture-8-1']
 if len(dirs)!=1:raise RuntimeError('Expected one Capture-8-1 clean replay.')
 sel=json.loads((dirs[0]/'smoke_selection.json').read_text());capture=Path(sel['capture'])
 if not capture.is_file() or sha(capture)!=sel['pcap_sha256']:raise RuntimeError('Capture missing or changed.')
 gen=parse_zeek(dirs[0]/'clean_replay/conn.log');mp=pd.read_csv(dirs[0]/'unique_exact_key_mapping.csv',dtype=str)
 labels={(int(a),b,c,e,f,g.lower()):l for a,b,c,e,f,g,l in zip(mp.timestamp_microseconds,mp.orig_h,mp.orig_p,mp.resp_h,mp.resp_p,mp.proto,mp.published_label)}
 kt=[zkey(a,b,c,d,e,f) for a,b,c,d,e,f in zip(gen['ts'],gen['id.orig_h'],gen['id.orig_p'],gen['id.resp_h'],gen['id.resp_p'],gen['proto'])]
 row_labels=[labels.get(k) for k in kt]
 if any(l is None for l in row_labels):raise RuntimeError('Unlabeled original flow.')
 gen['label']=[l.lower() for l in row_labels]
 header,endian,unit,network,packets=read_pcap(capture)
 flow_list=list(zip(gen['ts'],gen['proto'],gen['id.orig_h'],gen['id.orig_p'],gen['id.resp_h'],gen['id.resp_p'],gen['duration']))
 per_flow,info=assign_packets(packets,network,flow_list)
 pk=pd.to_numeric(gen.orig_pkts.replace('-',np.nan),errors='coerce').fillna(0)+pd.to_numeric(gen.resp_pkts.replace('-',np.nan),errors='coerce').fillna(0)
 opk=pd.to_numeric(gen.orig_pkts.replace('-',np.nan),errors='coerce').fillna(0)
 base_ok=((gen.label=='malicious')&(gen.proto.str.lower()=='tcp')).to_numpy()
 sel_pace=set(np.flatnonzero(base_ok&(pk>=2).to_numpy()).tolist());sel_inj=set(np.flatnonzero(base_ok&(opk>=2).to_numpy()).tolist())
 consistent=float(np.mean([len(per_flow.get(fi,[]))==int(pk.iloc[fi]) for fi in sel_pace])) if sel_pace else 0.0
 parents,starts=build_parents(gen,[l.lower() for l in row_labels])
 models=detectors(sample_train([load_linked('CTU-IoT-Malware-Capture-1-1'),load_linked('CTU-IoT-Malware-Capture-3-1')]))
 runs=[('pacing',d) for d in DELAYS]+[('injection',k) for k in INJECT_K];baseline=None;base_all={};rows=[];failures=[];injected_count=0
 for kind,param in runs:
  try:
   job=OUT/f'{kind}_{param:g}';job.mkdir()
   if kind=='pacing':selected=sel_pace;out_packets,new,order,injected=transform_pacing(packets,per_flow,selected,param);shift=int(round(param*10**6));k=0
   else:out_packets,new,order,injected=transform_injection(packets,per_flow,info,flow_list,sel_inj,int(param));selected=set(injected);shift=0;k=int(param);injected_count=len(injected)
   pcap=job/'transformed.pcap';write_pcap(pcap,header,endian,unit,out_packets,order,new);checks=verify(packets,pcap,order,new,per_flow,injected,k)
   run=subprocess.run([ZEEK,'-C','-r',str(pcap)],cwd=job,capture_output=True,text=True,timeout=900)
   if run.returncode or not (job/'conn.log').is_file():raise RuntimeError('Zeek failed: '+run.stderr[-500:])
   frame,unlabeled,dup=features(parse_zeek(job/'conn.log'),labels,parents,starts,shift)
   is_baseline=(kind=='pacing' and param==0.0)
   if is_baseline:baseline=frame
   if baseline is None:raise RuntimeError('Pipeline null control must run first.')
   sel_keys={skey(kt[i]) for i in selected};exact=frame[frame.inherited==0];common=exact.index.intersection(baseline.index);cur=exact.loc[common];base=baseline.loc[common]
   sel_mask=cur.index.isin(sel_keys);same=np.isclose(cur[NUM].to_numpy(float),base[NUM].to_numpy(float)).all(axis=1)
   children=frame[frame.inherited==1];split_parents=int(children.parent[children.parent.isin(sel_keys)].nunique())
   dd=cur.loc[sel_mask,'duration']-base.loc[sel_mask,'duration'];dpk=cur.loc[sel_mask,'orig_pkts']-base.loc[sel_mask,'orig_pkts'];dib=cur.loc[sel_mask,'orig_ip_bytes']-base.loc[sel_mask,'orig_ip_bytes']
   exp_ok=np.nan
   if kind=='injection' and sel_mask.any():
    expected_bytes={skey(kt[fi]):k*injected[fi][1] for fi in injected};ids=[ix for ix in dpk.index if ix in expected_bytes]
    exp_ok=float(np.mean([(dpk.loc[ix]==k) and (dib.loc[ix]==expected_bytes[ix]) for ix in ids])) if ids else np.nan
   for name,predict in models.items():
    p0=predict(base);p1=predict(cur);mal=cur.y.to_numpy()==1;det=(p0==1)&mal;elig=sel_mask&mal
    rec0=((p0==1)&mal).sum()/max(mal.sum(),1);rec1=((p1==1)&mal).sum()/max(mal.sum(),1)
    all_now=predict(frame);yb=frame.y.to_numpy()==1;rec_all=((all_now==1)&yb).sum()/max(yb.sum(),1)
    if is_baseline:base_all[name]=rec_all
    rows.append({'transformation':kind,'parameter':param,'detector':name,'flows_after':len(frame),'new_flows_label_inherited':int(frame.inherited.sum()),'new_flows_unlabeled':unlabeled,'duplicate_key_rows_removed':dup,
     'selected_flows':len(selected),'selected_parents_that_split':split_parents,'selected_split_fraction':split_parents/max(len(selected),1),
     'orig_view_recall_before':rec0,'orig_view_recall_after':rec1,'orig_view_recall_drop':rec0-rec1,'evaded_fraction_of_detected_eligible':float(((p1==0)&det&elig).sum()/max((det&elig).sum(),1)),
     'all_flows_recall_baseline':base_all[name],'all_flows_recall_after':rec_all,'all_flows_recall_drop':base_all[name]-rec_all,
     'median_selected_duration_change_s':float(dd.median()) if len(dd) else np.nan,'median_selected_orig_pkts_delta':float(dpk.median()) if len(dpk) else np.nan,
     'median_selected_orig_ip_bytes_delta':float(dib.median()) if len(dib) else np.nan,'injection_counters_as_expected_fraction':exp_ok,
     'nonselected_any_change_fraction':float((~same[~sel_mask]).mean()) if (~sel_mask).any() else np.nan,'packet_flow_assignment_consistency':consistent,**{'check_'+q:v for q,v in checks.items()}})
  except Exception as error:
   failures.append({'transformation':kind,'parameter':param,'error':f'{type(error).__name__}: {error}','trace':traceback.format_exc()[-1500:]})
   if kind=='pacing' and param==0.0:break
 res=pd.DataFrame(rows);res.to_csv(OUT/'real_packet_harness_v31_results.csv',index=False);pd.DataFrame(failures).to_csv(OUT/'run_failures.csv',index=False)
 checks_cols=[c for c in res if c.startswith('check_')]
 valid=bool(len(res) and res[checks_cols].all(axis=None))
 big=res[(res.all_flows_recall_drop>=GATE_DROP)|(res.orig_view_recall_drop>=GATE_DROP)] if len(res) else res
 gate='RUN_FAILED_SEE_FAILURES' if failures and not len(res) else ('REAL_PACKET_DAMAGE_OBSERVED' if valid and len(big) else ('PACKET_CHECKS_FAILED' if not valid else 'NO_REAL_PACKET_DAMAGE_ABOVE_THRESHOLD'))
 receipt={'output_directory':str(OUT),'gate_result':gate,'run_failures':len(failures),'eligible_pacing_flows':len(sel_pace),'eligible_injection_flows':len(sel_inj),
  'injection_flows_with_header_only_originator_packet':injected_count,'packet_assignment_consistency':consistent,'all_packet_checks_passed':valid,'zeek_SYN_timeout_default_s':5.0,
  'models_for_confirmatory_use_trained':False,'prospective_confirmation':False,'TCP_semantic_validity_certified':False,'application_functionality_tested':False}
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 if failures:print('\nRUN FAILURES');print(pd.DataFrame(failures)[['transformation','parameter','error']].to_string(index=False))
 if len(res):
  cols=['transformation','parameter','detector','flows_after','new_flows_label_inherited','new_flows_unlabeled','selected_flows','selected_split_fraction','orig_view_recall_drop','all_flows_recall_drop','median_selected_duration_change_s','median_selected_orig_pkts_delta','median_selected_orig_ip_bytes_delta','injection_counters_as_expected_fraction','nonselected_any_change_fraction']
  print('\nREAL-PACKET RESULTS (null control = pacing 0)');print(res[cols].round(4).to_string(index=False))
  print('\nPACKET CHECKS');print(res[['transformation','parameter']+checks_cols].drop_duplicates(['transformation','parameter']).to_string(index=False))
main()
