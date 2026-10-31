"""FROZEN TRACE CONFIRMATORY RUNNER. Uses the eight frozen original PCAP slices, frozen source model bank, and exactly INJ_k1/INJ_k3/PACE_1s.
No parameter tuning. Per target×attack receipts are resumable. Temporary pcaps/logs are deleted only after result receipt is written.
"""
import bisect,gzip,hashlib,ipaddress,itertools,json,os,struct,subprocess,traceback
from collections import Counter,defaultdict
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import joblib,numpy as np,pandas as pd
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';ASSETS=WORK/'TRACE_CONFIRMATORY_TARGET_ASSETS_v1_2/target_asset_resolution.csv';SOURCE=WORK/'TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/frozen_source_models.joblib';OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1';ZEEK='/opt/zeek/bin/zeek'
if not PROTO.is_file() or not ASSETS.is_file() or not SOURCE.is_file():raise FileNotFoundError('Frozen protocol/assets/source bundle missing.')
if OUT.exists():raise RuntimeError('Confirmatory result directory exists; do not overwrite it.')
P=json.loads(PROTO.read_text());A=pd.read_csv(ASSETS,keep_default_na=False);A=A[A.status.eq('RESOLVED')].copy()
if len(A)!=8 or A.scenario.tolist()!=P['target_scenarios']:raise RuntimeError('Resolved targets differ from frozen protocol.')
F=P['source_detector']['primary_features'];V=P['monitor']['views'];SEEDS=P['source_detector']['random_seeds'];N=P['evaluation_sampling']['per_target_per_class_records'];MAGICS={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def key(ts,o,op,r,rp,pr):return (int((Decimal(str(ts))*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),str(o),str(op),str(r),str(rp),str(pr).lower())
def ks(k):return '|'.join(map(str,k))
def mat(df,cols):
 x=np.column_stack([np.log1p(pd.to_numeric(df[c],errors='coerce').fillna(0).clip(lower=0).to_numpy(float)) for c in cols if c!='proto'])
 if 'proto' in cols:x=np.hstack([x, np.column_stack([(df.proto.astype(str).str.lower()==p).to_numpy(float) for p in ['tcp','udp','icmp']])])
 return x
def pcap_read(path):
 data=Path(path).read_bytes();m=data[:4]
 if m not in MAGICS:raise ValueError('classic pcap required')
 e,u=MAGICS[m];h=data[:24];net=struct.unpack(e+'I',data[20:24])[0];p=24;out=[]
 while p+16<=len(data):
  s,f,n,o=struct.unpack(e+'IIII',data[p:p+16]);p+=16;b=data[p:p+n];p+=n
  if len(b)!=n:raise ValueError('truncated pcap')
  out.append((s*10**9+f*u,o,b))
 return h,e,u,net,out
def pcap_write(path,h,e,u,packets,order,times):
 with open(path,'wb')as f:
  f.write(h)
  for i in order:
   _,o,b=packets[i];t=times[i];f.write(struct.pack(e+'IIII',t//10**9,(t%10**9)//u,len(b),o));f.write(b)
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
def logread(path):
 op=gzip.open(path,'rt',encoding='utf-8') if str(path).endswith('.gz') else open(path,encoding='utf-8');fields=None;rows=[]
 with op as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#') or not line.strip():continue
   rows.append(dict(zip(fields,line.rstrip().split())))
 return rows
def select(df):
 out=[]
 for y in(0,1):
  x=df[df.y==y].copy();x['_h']=x.ks.map(lambda s:int(hashlib.sha256((str(P['protocol_version'])+s).encode()).hexdigest(),16));out.append(x.sort_values('_h').head(N))
 r=pd.concat(out);return r
# Find E1 key encoding by comparing the clean log with mapping keys.
def resolve_keys(rows,feature_keys):
 candidates=[]
 for sep in ['|','::',',']:
  vals=[sep.join(map(str,key(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto']))) for r in rows[:1000]];candidates.append((sum(v in feature_keys for v in vals),sep))
 score,sep=max(candidates)
 if score==0:raise RuntimeError('Cannot resolve E1 ks format from clean conn.log.')
 return lambda r:sep.join(map(str,key(r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto'])))
def exact_p(rows,vals):
 return np.array([vals[r] for r in rows])
def estim(df,bank):
 pp=bank['PRIMARY'].predict_proba(mat(df,F))[:,1];pred=(pp>=.5).astype(int);votes=np.column_stack([bank[n].predict(mat(df,c)) for n,c in V.items()]);maj=(votes.sum(1)>=2).astype(int)
 conf=np.maximum(pp,1-pp);return {'AC':float(conf.mean()),'AGREE':float((pred==maj).mean()),'ATC':float((conf>=.5).mean())},pred
OUT.mkdir();bundle=joblib.load(SOURCE);allrows=[];fail=[]
for ar in A.itertuples(index=False):
 try:
  feat=pd.read_csv(ar.features_path,compression='gzip');feat['y']=pd.to_numeric(feat.y,errors='raise').astype(int);feat['proto']=feat.proto.astype(str).str.lower();sample=select(feat)
  cleanrows=logread(ar.conn_log_path);keyfn=resolve_keys(cleanrows,set(feat.ks.astype(str)));clean_by={keyfn(r):r for r in cleanrows};sample=sample[sample.ks.astype(str).isin(clean_by)].copy()
  if sample.y.value_counts().min()<N:raise RuntimeError('Clean exact-key sample lost a class.')
  # Selected malicious original conn rows; these are the only flows modified.
  selected_keys=set(sample[(sample.y==1)&(sample.proto=='tcp')].ks.astype(str));flow=[];bytuple=defaultdict(list)
  for i,r in enumerate(cleanrows):
   k=keyfn(r);flow.append((r,k));
   if k not in selected_keys:continue
   start=int(Decimal(r['ts'])*Decimal(10**9));dur=0 if r['duration']=='-' else int(Decimal(r['duration'])*Decimal(10**9));tup=tuple(sorted([(r['id.orig_h'],int(r['id.orig_p'])),(r['id.resp_h'],int(r['id.resp_p']))]));bytuple[tup].append((start,start+dur+1_000_000,i,k))
  for t in bytuple:bytuple[t].sort()
  h,e,u,net,packets=pcap_read(ar.pcap_path);per=defaultdict(list);info={}
  starts={t:[z[0] for z in v]for t,v in bytuple.items()}
  for pi,(ts,_,payload) in enumerate(packets):
   z=tcp(payload,net)
   if not z:continue
   src,sp,dst,dp,pay,ipt=z;tup=tuple(sorted([(src,sp),(dst,dp)]))
   if tup not in bytuple:continue
   j=bisect.bisect_right(starts[tup],ts)-1
   if j>=0 and ts<=bytuple[tup][j][1]:
    _,_,fi,k=bytuple[tup][j];per[fi].append(pi);info[pi]=(src,sp,pay,ipt,k)
  for fi in per:per[fi].sort(key=lambda i:(packets[i][0],i))
  sample_keys=set(sample.ks.astype(str));clean_df=sample[F+['proto','y']].copy();eligible={'INJ_k1':set(),'INJ_k3':set(),'PACE_1s':set()}
  for fi,pl in per.items():
   if not pl:continue
   k=flow[fi][1];r=flow[fi][0];orig=[i for i in pl if info[i][0]==r['id.orig_h'] and info[i][1]==int(r['id.orig_p'])]
   if len(orig)>=2:eligible['PACE_1s'].add(fi)
   if len(orig)>=2 and any(info[i][2]==0 for i in orig):eligible['INJ_k1'].add(fi);eligible['INJ_k3'].add(fi)
  for attack,param in [('INJ_k1',1),('INJ_k3',3),('PACE_1s',1)]:
   job=OUT/ar.scenario/attack;job.mkdir(parents=True,exist_ok=True);receipt_path=job/'receipt.json'
   if receipt_path.exists():
    rr=json.loads(receipt_path.read_text());allrows.extend(rr['rows']);continue
   out=list(packets);times=[x[0]for x in packets];inj={}
   if attack.startswith('INJ'):
    for fi in eligible[attack]:
     r=flow[fi][0];orig=[i for i in per[fi]if info[i][0]==r['id.orig_h']and info[i][1]==int(r['id.orig_p'])and info[i][2]==0]
     i=orig[-1];inj[fi]=(i,info[i][3])
     for q in range(1,param+1):out.append((times[i]+q*1000,packets[i][1],packets[i][2]));times.append(times[i]+q*1000)
   else:
    for fi in eligible[attack]:
     for i in per[fi][1:]:times[i]+=1_000_000_000
   order=sorted(range(len(out)),key=lambda i:(times[i],i));pcap=job/'transformed.pcap';pcap_write(pcap,h,e,u,out,order,times)
   # byte multiset validation
   sig=lambda a:Counter(hashlib.sha1(x[2]).digest()+str(x[1]).encode()for x in a);expect=sig(packets)
   for fi,(i,_)in inj.items():expect[hashlib.sha1(packets[i][2]).digest()+str(packets[i][1]).encode()]+=param
   run=subprocess.run([ZEEK,'-C','-r',str(pcap)],cwd=job,capture_output=True,text=True,timeout=3600)
   if run.returncode or not(job/'conn.log').is_file():raise RuntimeError('Zeek failed: '+run.stderr[-500:])
   outrows=logread(job/'conn.log');outby={keyfn(r):r for r in outrows};matched=sample[sample.ks.astype(str).isin(outby)].copy()
   mapped=len(matched)/len(sample)
   if mapped<.999:raise RuntimeError(f'Mapped selected evaluation fraction {mapped:.6f}<.999')
   adf=[]
   for k in matched.ks.astype(str):
    r=outby[k];adf.append({**{c:r[c]for c in F},'proto':r['proto'],'y':int(matched.loc[matched.ks.astype(str)==k,'y'].iloc[0])})
   att=pd.DataFrame(adf);check={'packet_multiset_as_designed':sig(pcap_read(pcap)[4])==expect,'original_timestamps_not_advanced':all(times[i]>=packets[i][0]for i in range(len(packets))),'output_timestamps_nondecreasing':all(times[order[i]]<=times[order[i+1]]for i in range(len(order)-1))}
   if not all(check.values()):raise RuntimeError('Packet validity check failed.')
   rows=[]
   for seed,bank in bundle['models'].items():
    ec,pc=estim(clean_df,bank);ea,pa=estim(att,bank);ac=float((pc==clean_df.y.to_numpy()).mean());aa=float((pa==att.y.to_numpy()).mean())
    for est in ['AC','AGREE','ATC']:
     de=abs((ea[est]-aa)-(ec[est]-ac));rows.append({'scenario':ar.scenario,'attack':attack,'seed':seed,'estimator':est,'clean_accuracy':ac,'attack_accuracy':aa,'true_damage':ac-aa,'clean_estimate':ec[est],'attack_estimate':ea[est],'differential_abs_error':de,'mapped_fraction':mapped,'eligible_flows':len(eligible[attack]),**check})
   receipt={'scenario':ar.scenario,'attack':attack,'rows':rows,'pcap_sha256':sha(ar.pcap_path),'features_sha256':sha(ar.features_path),'transformed_pcap_sha256':sha(pcap),'models_trained':False,'target_validity_established':True}
   receipt_path.write_text(json.dumps(receipt,indent=2));allrows.extend(rows)
   # Preserve receipt/results; drop large intermediates.
   for q in [pcap,job/'conn.log']:
    if q.exists():q.unlink()
 except Exception as ex:fail.append({'scenario':ar.scenario,'error':f'{type(ex).__name__}: {ex}','trace':traceback.format_exc()[-1000:]})
pd.DataFrame(allrows).to_csv(OUT/'all_target_seed_estimator_results.csv',index=False);pd.DataFrame(fail).to_csv(OUT/'failures.csv',index=False)
if fail:raise RuntimeError('At least one target failed; inspect failures.csv. Do not choose replacements.')
r=pd.DataFrame(allrows);primary=[]
for attack in ['INJ_k1','INJ_k3','PACE_1s']:
 x=r[(r.attack==attack)&(r.estimator.isin(['AC','AGREE']))].pivot_table(index=['scenario','seed'],columns='estimator',values='differential_abs_error').reset_index();x['gain']=x.AC-x.AGREE
 for scenario,g in x.groupby('scenario'):primary.append({'attack':attack,'scenario':scenario,'mean_gain_over_seeds':g.gain.mean(),'positive':bool(g.gain.mean()>0)})
pr=pd.DataFrame(primary);pr.to_csv(OUT/'scenario_level_primary_gains.csv',index=False)
def signp(v):
 obs=np.mean(v);vals=[]
 for bits in itertools.product([-1,1],repeat=len(v)):vals.append(np.mean(np.array(bits)*v))
 return float(np.mean(np.array(vals)>=obs-1e-15))
tests=[]
for a,g in pr.groupby('attack'):tests.append({'attack':a,'mean_gain':g.mean_gain.mean(),'positive_scenarios':int(g.positive.sum()),'n':len(g),'exact_one_sided_p':signp(g.mean_gain.to_numpy())})
t=pd.DataFrame(tests).sort_values('exact_one_sided_p').reset_index(drop=True);t['holm_threshold']=[.05/(3-i)for i in range(3)];t['holm_reject']=t.exact_one_sided_p<=t.holm_threshold;t.to_csv(OUT/'primary_holm_results.csv',index=False)
receipt={'output_directory':str(OUT),'protocol_sha256':sha(PROTO),'targets_completed':8,'attacks_completed':3,'seeds':SEEDS,'primary_units':8,'models_retrained':False,'target_predictions_computed':True,'target_outcomes_inspected':True,'attacks_executed':True,'NF_changed':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2));print('\nPRIMARY HOLM RESULTS');print(t.to_string(index=False));print('\nSCENARIO GAINS');print(pr.to_string(index=False));print('\nFAILURES');print(pd.DataFrame(fail).to_string(index=False)if fail else'None')
