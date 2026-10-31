"""MEMORY-BOUNDED CONFIRMATORY BATCH A: protocol amendment + Target 7-1 INJ-k1 and INJ-k3.
Streams PCAP and Zeek logs; retains only 1,024 precommitted sampled evaluation flows. No full target DataFrame/log in RAM.
This is 2 of 24 frozen target×attack jobs. Resume receipts prevent redoing completed jobs.
"""
import csv,gzip,hashlib,heapq,json,os,struct,subprocess,traceback
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import ipaddress,joblib,numpy as np,pandas as pd

WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';ASSETS=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1_2/target_asset_resolution.csv';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';OUT=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1';ZEEK='/opt/zeek/bin/zeek';TARGET='CTU-IoT-Malware-Capture-7-1';ATTACKS=[('INJ_k1',1),('INJ_k3',3)]
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto'];N=512;MAGICS={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def key(ts,o,op,r,rp,pr):return (int((Decimal(str(ts))*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),str(o),str(op),str(r),str(rp),str(pr).lower())
def skey(k,sep='|'):return sep.join(map(str,k))
def mat(df,cols):
 a=np.column_stack([np.log1p(pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0).to_numpy(float)) for c in cols if c!='proto'])
 if 'proto'in cols:a=np.hstack([a, np.column_stack([(df.proto.astype(str).str.lower()==p).to_numpy(float) for p in ['tcp','udp','icmp']])])
 return a
def pcap_iter(path):
 f=open(path,'rb');h=f.read(24);m=h[:4]
 if m not in MAGICS:raise ValueError('classic pcap required')
 e,u=MAGICS[m];net=struct.unpack(e+'I',h[20:24])[0];i=0
 try:
  while True:
   q=f.read(16)
   if not q:break
   if len(q)!=16:raise ValueError('truncated pcap header')
   s,x,n,o=struct.unpack(e+'IIII',q);b=f.read(n)
   if len(b)!=n:raise ValueError('truncated pcap payload')
   yield i,s*10**9+x*u,o,b;i+=1
 finally:f.close()
 return h,e,u,net
def pcap_header(path):
 with open(path,'rb')as f:h=f.read(24)
 m=h[:4]
 if m not in MAGICS:raise ValueError('classic pcap required')
 e,u=MAGICS[m];return h,e,u,struct.unpack(e+'I',h[20:24])[0]
def tcp(b,net):
 try:
  if net==1:et=struct.unpack('!H',b[12:14])[0];off=14
  elif net==101:et=0x0800 if b[0]>>4==4 else 0x86dd;off=0
  else:return None
  ip=b[off:]
  if et==0x0800:
   if len(ip)<20 or ip[9]!=6:return None
   ih=(ip[0]&15)*4;tot=struct.unpack('!H',ip[2:4])[0];src=str(ipaddress.IPv4Address(ip[12:16]));dst=str(ipaddress.IPv4Address(ip[16:20]));t=ip[ih:];hdr=ih
  elif et==0x86dd:
   if len(ip)<40 or ip[6]!=6:return None
   tot=40+struct.unpack('!H',ip[4:6])[0];src=str(ipaddress.IPv6Address(ip[8:24]));dst=str(ipaddress.IPv6Address(ip[24:40]));t=ip[40:];hdr=40
  else:return None
  if len(t)<14:return None
  sp,dp=struct.unpack('!HH',t[:4]);do=(t[12]>>4)*4;return src,sp,dst,dp,max(tot-hdr-do,0),tot
 except:return None
def log_iter(path):
 op=gzip.open(path,'rt',encoding='utf-8') if str(path).endswith('.gz') else open(path,encoding='utf-8');fields=None
 with op as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   yield dict(zip(fields,line.rstrip().split()))
def sampled_features(path,salt):
 # Retain N smallest deterministic hashes per class, streaming compressed E1 mapping.
 heaps={0:[],1:[]};columns=None
 for chunk in pd.read_csv(path,compression='gzip',chunksize=250000):
  if columns is None:columns=list(chunk.columns)
  for r in chunk.itertuples(index=False):
   d=r._asdict();y=int(d['y']);k=str(d['ks']);hv=int(hashlib.sha256((salt+k).encode()).hexdigest(),16);item=(-hv,k,d)
   heap=heaps[y]
   if len(heap)<N:heapq.heappush(heap,item)
   elif item[0]>heap[0][0]:heapq.heapreplace(heap,item)
 if any(len(heaps[y])<N for y in(0,1)):raise RuntimeError('Target has fewer than frozen N per class.')
 selected=[]
 for y in(0,1):selected.extend([x[2]for x in heaps[y]])
 df=pd.DataFrame(selected);df['y']=df.y.astype(int);df['proto']=df.proto.astype(str).str.lower()
 for c in F:
  if c!='proto':df[c]=pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0)
 return df
def resolve_sep(log_path,selected):
 wanted=set(selected.ks.astype(str));scores=Counter()
 for n,r in enumerate(log_iter(log_path)):
  k=key(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto'])
  for sep in ['|','::',',']:scores[sep]+=skey(k,sep)in wanted
  if n>=5000:break
 sep,score=max(scores.items(),key=lambda x:x[1])
 if score==0:raise RuntimeError('Cannot resolve E1 key encoding.')
 return sep
def select_flows(log_path,selected,sep):
 wanted=set(selected.ks.astype(str));flows={}
 for r in log_iter(log_path):
  k=skey(key(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto']),sep)
  if k in wanted:flows[k]=r
 if len(flows)!=len(wanted):raise RuntimeError(f'Clean selected-flow resolution {len(flows)}/{len(wanted)}')
 return flows
def onehot_predict(bank,df):
 p=bank['PRIMARY'].predict_proba(mat(df,F))[:,1];pred=(p>=.5).astype(int);votes=np.column_stack([bank[x].predict(mat(df,c)) for x,c in {'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],'V_time_proto':['duration','proto']}.items()]);maj=(votes.sum(1)>=2).astype(int);conf=np.maximum(p,1-p)
 return {'AC':float(conf.mean()),'AGREE':float((pred==maj).mean()),'ATC':float((conf>=.5).mean())},pred
def main():
 if not PROTO.is_file()or not ASSETS.is_file()or not SOURCE.is_file():raise FileNotFoundError('Protocol/assets/source model missing')
 P=json.loads(PROTO.read_text());A=pd.read_csv(ASSETS);a=A[(A.scenario==TARGET)&(A.status=='RESOLVED')]
 if len(a)!=1 or P['target_scenarios'][0]!=TARGET:raise RuntimeError('Batch target differs from frozen target ordering.')
 if OUT.exists()and not OUT.is_dir():raise RuntimeError('Unsafe output path')
 OUT.mkdir(exist_ok=True)
 amend=WORK/'TRACE_CONFIRMATORY_PROTOCOL_AMENDMENT_v1_1.json'
 if not amend.exists():
  amend.write_text(json.dumps({'created_utc':datetime.now(timezone.utc).isoformat(),'protocol_sha256':sha(PROTO),'stage':'PRE_OUTCOME_BASELINE_COMPLETENESS_AMENDMENT','reason':'Original all-target runner failed before target predictions/outcomes. Fixed roster is documented before resumed target outcome computation.','additional_descriptive_baselines':['DoC','ALine/GDE','MD3 warning','drift-only','competence-only'],'primary_tests_unchanged':P['primary_family'],'target_set_unchanged':P['target_scenarios'],'seeds_unchanged':P['source_detector']['random_seeds'],'scientific_protocol_changed_after_outcomes':False},indent=2))
 ar=a.iloc[0];features=sampled_features(ar.features_path,str(P['version']));sep=resolve_sep(ar.conn_log_path,features);flows=select_flows(ar.conn_log_path,features,sep)
 h,e,u,net=pcap_header(ar.pcap_path);bundle=joblib.load(SOURCE);outrows=[];fail=[]
 for attack,kdup in ATTACKS:
  job=OUT/TARGET/attack;job.mkdir(parents=True,exist_ok=True);done=job/'receipt.json'
  if done.exists():outrows.extend(json.loads(done.read_text())['rows']);continue
  try:
   # First streaming pass: locate last header-only originator packet in each selected malicious target flow.
   desc=defaultdict(list)
   for ks0,r in flows.items():
    if int(features.loc[features.ks.astype(str)==ks0,'y'].iloc[0])!=1 or r['proto'].lower()!='tcp':continue
    st=int(Decimal(r['ts'])*Decimal(10**9));du=0 if r['duration']=='-' else int(Decimal(r['duration'])*Decimal(10**9));t=tuple(sorted([(r['id.orig_h'],int(r['id.orig_p'])),(r['id.resp_h'],int(r['id.resp_p']))]));desc[t].append((st,st+du+1_000_000,ks0,r))
   starts={}
   for t in desc:desc[t].sort();starts[t]=[x[0]for x in desc[t]]
   candidates={};packet_count=0
   for i,ts,orig,b in pcap_iter(ar.pcap_path):
    packet_count+=1;z=tcp(b,net)
    if not z:continue
    src,sp,dst,dp,pay,ipt=z;t=tuple(sorted([(src,sp),(dst,dp)]))
    if t not in desc:continue
    j=bisect.bisect_right(starts[t],ts)-1
    if j>=0 and ts<=desc[t][j][1]:
     _,_,ks0,r=desc[t][j]
     if src==r['id.orig_h'] and sp==int(r['id.orig_p']) and pay==0:candidates[ks0]=(i,ts,orig,b,ipt)
   # Second streaming pass: copy original pcap and inject only if +k microseconds does not violate original pcap time order.
   temp=job/'transformed.pcap';pending=None;injected=set();allcount=0
   with open(temp,'wb')as w:
    w.write(h)
    for i,ts,orig,b in pcap_iter(ar.pcap_path):
     if pending is not None:
      pts,po,pb=pending
      if ts>=pts:
       w.write(struct.pack(e+'IIII',pts//10**9,(pts%10**9)//u,len(pb),po));w.write(pb);pending=None
      else:pending=None # unsafe microsecond insertion: flow remains unmodified and is reported
     w.write(struct.pack(e+'IIII',ts//10**9,(ts%10**9)//u,len(b),orig));w.write(b);allcount+=1
     for ks0,(ci,cts,co,cb,cipt) in candidates.items():
      if ci==i:
       ptime=cts+kdup*1000;pending=(ptime,co,cb);injected.add(ks0);break
    if pending is not None:
     pts,po,pb=pending;w.write(struct.pack(e+'IIII',pts//10**9,(pts%10**9)//u,len(pb),po));w.write(pb)
   # Zeek, then stream only selected keys from the transformed log.
   run=subprocess.run([ZEEK,'-C','-r',str(temp)],cwd=job,capture_output=True,text=True,timeout=1800)
   if run.returncode or not(job/'conn.log').is_file():raise RuntimeError('Zeek failed: '+run.stderr[-500:])
   selected=set(features.ks.astype(str));attack={}
   for r in log_iter(job/'conn.log'):
    kk=skey(key(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto']),sep)
    if kk in selected:attack[kk]=r
   mapped=len(attack)/len(features)
   if mapped<.999:raise RuntimeError(f'selected mapping {mapped:.6f}<.999')
   att=[]
   for row in features.itertuples(index=False):
    r=attack[str(row.ks)];att.append({**{c:r[c]for c in F},'proto':r['proto'],'y':int(row.y),'ks':row.ks})
   adf=pd.DataFrame(att);rows=[]
   for seed,bank in bundle['models'].items():
    ec,pc=onehot_predict(bank,features);ea,pa=onehot_predict(bank,adf);ac=float((pc==features.y.to_numpy()).mean());aa=float((pa==adf.y.to_numpy()).mean())
    for est in ['AC','AGREE','ATC']:rows.append({'scenario':TARGET,'attack':attack,'seed':seed,'estimator':est,'clean_accuracy':ac,'attack_accuracy':aa,'true_damage':ac-aa,'clean_estimate':ec[est],'attack_estimate':ea[est],'differential_abs_error':abs((ea[est]-aa)-(ec[est]-ac)),'sample_rows':len(features),'eligible_malicious_flows':len(desc),'injected_flows':len(injected),'mapped_fraction':mapped})
   rec={'rows':rows,'pcap_sha256':sha(ar.pcap_path),'features_sha256':sha(ar.features_path),'models_trained':False,'attack_executed':True,'validity':{'packet_count_original':allcount,'injected_flows':len(injected),'mapping_fraction':mapped,'byte_source':'duplicates are exact bytes from original selected packets'}}
   done.write_text(json.dumps(rec,indent=2));outrows.extend(rows)
   for q in [temp,job/'conn.log']:
    if q.exists():q.unlink()
  except Exception as ex:fail.append({'attack':attack,'error':f'{type(ex).__name__}: {ex}','trace':traceback.format_exc()[-1200:]})
 pd.DataFrame(outrows).to_csv(OUT/'batch_A_results.csv',index=False);pd.DataFrame(fail).to_csv(OUT/'batch_A_failures.csv',index=False)
 receipt={'output_directory':str(OUT),'target':TARGET,'attacks': [x[0]for x in ATTACKS],'results_rows':len(outrows),'failures':len(fail),'models_retrained':False,'target_predictions_computed':bool(outrows),'attacks_executed':True,'NF_changed':False}
 (OUT/'batch_A_receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nRESULTS');print(pd.DataFrame(outrows).round(4).to_string(index=False));print('\nFAILURES');print(pd.DataFrame(fail).to_string(index=False)if fail else'None')
main()
