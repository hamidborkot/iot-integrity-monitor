"""REAL-PACKET injection on Capture-1-1 (DESIGN data) against WITHIN-scenario HGB detectors (the 32.85-point upper-bound case).
Injection (validated on 8-1: Zeek counters rose exactly as designed): duplicate the LAST header-only originator packet of each eligible malicious TCP flow in the
held-out half b, k times, 1 microsecond apart. Detector split/training reproduce the attack-surface experiment (seed 7). Baseline = original Zeek conn.log of the same pcap.
Not prospective confirmation; no TCP/application-semantics claim."""
import bisect,glob,hashlib,ipaddress,json,struct,subprocess,traceback,warnings
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');ZEEK='/opt/zeek/bin/zeek';SEED=7;TRAIN_PER_CLASS=40000;GATE_DROP=0.05;INJECT_K=[1,3];ZEEK_TIMEOUT=3300
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'];PROTOS=['tcp','udp','icmp']
BOUNDS={'WITHIN_HGB_ALL9':0.3285,'WITHIN_HGB_NO_PROTO':0.3369}
MAGICS={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def zkey(ts,o,op,r,rp,pr):return (int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),o,str(op),r,str(rp),pr.lower())
def skey(k):return '|'.join(map(str,k))
def read_conn(path):
 fields=None;skip=0
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#'):
    skip+=1
    if line.startswith('#fields'):fields=line.rstrip('\n').split('\t')[1:]
   else:break
 if fields is None:raise ValueError('No #fields line in '+str(path))
 return pd.read_csv(path,sep='\t',comment='#',header=None,names=fields,dtype=str,keep_default_na=False),skip
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
  return {'src':src,'sport':sport,'dst':dst,'dport':dport,'payload_len':max(total-hdr-data_off,0),'ip_total':total}
 except Exception:return None
def assign_packets(packets,network,flow_list,selected):
 wanted={tuple(sorted([(flow_list[fi][2],int(flow_list[fi][3])),(flow_list[fi][4],int(flow_list[fi][5]))])) for fi in selected}
 table=defaultdict(list)
 for fi,(ts,proto,oh,op,rh,rp,duration) in enumerate(flow_list):
  if proto.lower()!='tcp':continue
  tup=tuple(sorted([(oh,int(op)),(rh,int(rp))]))
  if tup not in wanted:continue
  start=int(Decimal(ts)*Decimal(10**9));dur=0 if duration=='-' else int(Decimal(duration)*Decimal(10**9));table[tup].append((start,start+dur+1_000_000,fi))
 starts={}
 for tup in table:table[tup].sort();starts[tup]=[x[0] for x in table[tup]]
 per_flow=defaultdict(list);info={}
 for i,(ts,_,payload) in enumerate(packets):
  p=parse_tcp(payload,network)
  if p is None:continue
  tup=tuple(sorted([(p['src'],p['sport']),(p['dst'],p['dport'])]))
  if tup not in table:continue
  info[i]=p;j=bisect.bisect_right(starts[tup],ts)-1
  if j>=0 and ts<=table[tup][j][1]:per_flow[table[tup][j][2]].append(i)
 for fi in per_flow:per_flow[fi].sort(key=lambda i:(packets[i][0],i))
 return per_flow,info
def transform_injection(packets,per_flow,info,flow_list,selected,k):
 out=list(packets);new=[p[0] for p in packets];injected={}
 for fi in sorted(selected):
  oh,op=flow_list[fi][2],int(flow_list[fi][3]);cand=[i for i in per_flow.get(fi,[]) if i in info and info[i]['src']==oh and info[i]['sport']==op and info[i]['payload_len']==0]
  if not cand:continue
  i=cand[-1];ts,orig,payload=packets[i];injected[fi]=(i,info[i]['ip_total'])
  for j in range(1,k+1):out.append((ts+j*1000,orig,payload));new.append(ts+j*1000)
 return out,new,sorted(range(len(out)),key=lambda i:(new[i],i)),injected
def verify(original,new_path,order,new,per_flow,injected,k):
 _,_,_,_,read=read_pcap(new_path);sig=lambda ps:Counter(hashlib.sha1(p[2]).digest()+struct.pack('!I',p[1]) for p in ps);ok={}
 expected=sig(original)
 for fi,(i,_) in injected.items():expected[hashlib.sha1(original[i][2]).digest()+struct.pack('!I',original[i][1])]+=k
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
def matrix(df,fs):
 x=df[NUM].to_numpy(float);parts=[x]
 if fs=='ALL9':parts.append(np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS]))
 return np.hstack(parts)
def sample_train(df):
 parts=[]
 for y in(0,1):
  part=df[df.y==y];parts.append(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED))
 return pd.concat(parts,ignore_index=True)
def frame_from_conn(conn):
 keys=[skey(zkey(a,b,c,d,e,f)) for a,b,c,d,e,f in zip(conn['ts'],conn['id.orig_h'],conn['id.orig_p'],conn['id.resp_h'],conn['id.resp_p'],conn['proto'])]
 f=pd.DataFrame({c:pd.to_numeric(conn[c].replace('-',np.nan),errors='coerce').fillna(0.0).values for c in NUM});f['proto']=conn['proto'].str.lower().values;f['ks']=keys
 dup=int(f.ks.duplicated(keep=False).sum());return f[~f.ks.duplicated(keep=False)].set_index('ks'),keys,dup
def main():
 OUT=WORK/('TRACE_PACKET_INJECTION_1_1_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
 receipts=[(p,json.loads(p.read_text())) for p in WORK.glob('TRACE_LINKAGE_BATCH_v1/CTU-IoT-Malware-Capture-1-1/*/candidate_receipt.json')]
 receipts=[(p,r) for p,r in receipts if r.get('status')=='FULL_LOG_LINKAGE_COMPUTED' and r.get('scenario')=='CTU-IoT-Malware-Capture-1-1']
 if len(receipts)!=1:raise RuntimeError('Expected exactly one completed Capture-1-1 receipt.')
 rpath,rec=receipts[0];capture=Path(rec['capture']);conn_path=rpath.parent/'replay/conn.log';linked=Path(rec['linked_records_path'])
 if sha(capture)!=rec['pcap_sha256'] or sha(linked)!=rec['linked_records_sha256']:raise RuntimeError('Capture or linked records changed.')
 if not conn_path.is_file() or sha(conn_path)!=rec['generated_log_sha256']:raise RuntimeError('Generated conn.log missing or changed; cannot use as baseline.')
 conn,skip=read_conn(conn_path);lk=clean(pd.read_csv(linked,usecols=NUM+['proto','published_label','generated_line'],dtype=str))[NUM+['proto','y','generated_line']].reset_index(drop=True)
 lk['generated_line']=lk.generated_line.astype(int)
 a,b=train_test_split(lk,test_size=0.5,stratify=lk.y,random_state=SEED);train=sample_train(a.reset_index(drop=True))
 models={}
 for name,fs in [('WITHIN_HGB_ALL9','ALL9'),('WITHIN_HGB_NO_PROTO','NO_PROTO')]:
  clf=HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(matrix(train,fs),train.y);models[name]=(lambda d,clf=clf,fs=fs:clf.predict(matrix(d,fs)))
 y_by_line=dict(zip(lk.generated_line.tolist(),lk.y.tolist()));b_lines=set(b.generated_line.tolist())
 baseline,keys,dup0=frame_from_conn(conn);lines=np.arange(len(conn))+skip+1
 y_row=np.array([y_by_line.get(int(l),-1) for l in lines]);b_row=np.array([int(l) in b_lines for l in lines])
 key_y=pd.Series(y_row,index=keys);key_y=key_y[~key_y.index.duplicated(keep=False)];b_keys=pd.Index([k for k,inb,yy in zip(keys,b_row,y_row) if inb and yy>=0]).intersection(baseline.index)
 opk=pd.to_numeric(conn.orig_pkts.replace('-',np.nan),errors='coerce').fillna(0).to_numpy()
 sel=set(np.flatnonzero((y_row==1)&b_row&(conn.proto.str.lower().to_numpy()=='tcp')&(opk>=2)).tolist())
 header,endian,unit,network,packets=read_pcap(capture)
 flow_list=list(zip(conn['ts'],conn['proto'],conn['id.orig_h'],conn['id.orig_p'],conn['id.resp_h'],conn['id.resp_p'],conn['duration']))
 per_flow,info=assign_packets(packets,network,flow_list,sel);rows=[];failures=[]
 for k in INJECT_K:
  try:
   job=OUT/f'injection_{k}';job.mkdir();out_packets,new,order,injected=transform_injection(packets,per_flow,info,flow_list,sel,k)
   pcap=job/'transformed.pcap';write_pcap(pcap,header,endian,unit,out_packets,order,new);checks=verify(packets,pcap,order,new,per_flow,injected,k)
   run=subprocess.run([ZEEK,'-C','-r',str(pcap)],cwd=job,capture_output=True,text=True,timeout=ZEEK_TIMEOUT)
   if run.returncode or not (job/'conn.log').is_file():raise RuntimeError('Zeek failed: '+run.stderr[-500:])
   cc,_=read_conn(job/'conn.log');frame,_,dup=frame_from_conn(cc);common=frame.index.intersection(baseline.index);cur=frame.loc[common];base=baseline.loc[common]
   inj_keys={skey(zkey(*flow_list[fi][:1],flow_list[fi][2],flow_list[fi][3],flow_list[fi][4],flow_list[fi][5],flow_list[fi][1])):injected[fi] for fi in injected}
   inj_idx=common.intersection(pd.Index(list(inj_keys)));dpk=cur.loc[inj_idx,'orig_pkts']-base.loc[inj_idx,'orig_pkts'];dib=cur.loc[inj_idx,'orig_ip_bytes']-base.loc[inj_idx,'orig_ip_bytes']
   exp=float(np.mean([(dpk.loc[ix]==k) and (dib.loc[ix]==k*inj_keys[ix][1]) for ix in inj_idx])) if len(inj_idx) else np.nan
   non=common.difference(inj_idx);same=np.isclose(cur.loc[non,NUM].to_numpy(float),base.loc[non,NUM].to_numpy(float)).all(axis=1)
   bk=b_keys.intersection(common);yb=key_y.reindex(bk).to_numpy()==1;elig=bk.isin(pd.Index(list(inj_keys)))
   for name,predict in models.items():
    p0=predict(base.loc[bk]);p1=predict(cur.loc[bk]);det=(p0==1)&yb
    rec0=((p0==1)&yb).sum()/max(yb.sum(),1);rec1=((p1==1)&yb).sum()/max(yb.sum(),1)
    rows.append({'injected_packets_per_flow':k,'detector':name,'flows_after':len(frame),'flows_before':len(baseline),'new_or_missing_keys':int(len(frame.index.symmetric_difference(baseline.index))),
     'eligible_flows':len(sel),'injected_flows':len(injected),'injection_counters_as_expected_fraction':exp,'heldout_malicious_flows':int(yb.sum()),
     'recall_before':rec0,'recall_after':rec1,'real_recall_drop':rec0-rec1,'evaded_fraction_of_detected_injected':float(((p1==0)&det&elig).sum()/max((det&elig).sum(),1)),
     'upper_bound_reference':BOUNDS[name],'noninjected_any_change_fraction':float((~same).mean()) if len(same) else np.nan,'duplicate_key_rows_removed':dup,**{'check_'+q:v for q,v in checks.items()}})
  except Exception as error:failures.append({'injected_packets_per_flow':k,'error':f'{type(error).__name__}: {error}','trace':traceback.format_exc()[-1500:]})
 res=pd.DataFrame(rows);res.to_csv(OUT/'real_packet_injection_1_1_results.csv',index=False);pd.DataFrame(failures).to_csv(OUT/'run_failures.csv',index=False)
 cc_=[c for c in res if c.startswith('check_')];valid=bool(len(res) and res[cc_].all(axis=None))
 gate='RUN_FAILED_SEE_FAILURES' if failures and not len(res) else ('PACKET_CHECKS_FAILED' if not valid else ('REAL_PACKET_DAMAGE_OBSERVED' if (res.real_recall_drop>=GATE_DROP).any() else 'NO_REAL_PACKET_DAMAGE_ABOVE_THRESHOLD'))
 receipt={'output_directory':str(OUT),'gate_result':gate,'run_failures':len(failures),'eligible_flows':len(sel),'flows_with_header_only_originator_packet':int(len(injected)) if 'injected' in dir() else None,
  'heldout_flows':len(b_keys),'all_packet_checks_passed':valid,'models_for_confirmatory_use_trained':False,'prospective_confirmation':False,'TCP_semantic_validity_certified':False,'application_functionality_tested':False}
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 if failures:print('\nRUN FAILURES');print(pd.DataFrame(failures)[['injected_packets_per_flow','error']].to_string(index=False))
 if len(res):print('\nREAL-PACKET INJECTION RESULTS (Capture-1-1, within-scenario detectors)');print(res.drop(columns=cc_).round(4).to_string(index=False));print('\nPACKET CHECKS');print(res[['injected_packets_per_flow']+cc_].drop_duplicates('injected_packets_per_flow').to_string(index=False))
main()
