"""Seven reviewer requests, one executable runner; no silent scientific substitutions.
Dependencies may be installed when missing; existing NumPy/sklearn are never upgraded.
No IDS retraining. All task results and exact blockers are printed and saved separately.
"""
import os,sys,json,csv,gzip,re,hashlib,struct,socket,subprocess,shutil,time,zipfile,traceback,inspect,importlib.metadata as im
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter,defaultdict
from decimal import Decimal,ROUND_HALF_EVEN
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from threadpoolctl import threadpool_limits

BASE=Path('/kaggle/input/datasets/mdhamidborkottulla')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
WORK=Path('/kaggle/working')
OUT=WORK/('REVIEWER_EXPERIMENTS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MODEL_HASH={'HGB':'adb02fbe0fb4582ce931c5c5bb5d71001647c801142b8a986018ea2983c063d1','LR':'d80a15e78dd076f8b1f9905a627e8a6dab16c06596b6c792498553bda94e90a2'}
CFG={'version':'reviewer-experiments-v1','nfstream_version':'6.6.0','menelaus_version':'0.2.0',
 'cross_extractor_captures':[48,49],'cross_extractor_delays':[0,1,3,10],
 'prefix_bytes':32*1024**2,'max_packets':400000,'nfstream_idle_seconds':[15,300],'nfstream_active_seconds':1800,
 'validation_sample_units':64,'new_conditions_post_exposure':True,
 'MD3_policy':'source-calibrated warning stage; latch warning until end of each condition, no oracle confirmation',
 'MG_positive':'all descendant membership passes original strict rule AND at least one descendant alarms',
 'PW_positive':'at least one alarm-bearing UID has exactly one selected owner and matching selected/event/extractor packet counts',
 'PW_negative':'complete packet mapping AND no associated record alarms',
 'unresolved':'neither positive nor negative justified; never coerce missing outcomes to negative'}
class Block(Exception):pass
FILES=[];LEDGER=[];PROV=[];CACHE={}

def js(p,x):Path(p).write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def loadcsv(p,**kw):
 with open(p,'rb') as f:compressed=f.read(2)==b'\x1f\x8b'
 return pd.read_csv(p,compression='gzip' if compressed else None,float_precision='round_trip',**kw)
def boolean(s,allow_missing=False):
 z=s.astype('string').str.strip().str.lower();valid=z.isin(['true','false','1','0','1.0','0.0'])
 if not (valid | (z.isna() if allow_missing else False)).all():raise Block('Invalid Boolean: '+str(s.name))
 return z.isin(['true','1','1.0']).fillna(False).to_numpy(bool)
def table(name,d):
 d.to_csv(TASK/name,index=False)
 print('\n'+name+'\n'+d.to_string(index=False,max_rows=None,max_cols=None),flush=True)
def candidates(name,part=''):
 return sorted([p for p in FILES if p.name in {name,name+'.gz'} and part.lower() in str(p).lower()],key=lambda p:(len(str(p)),str(p)))
def unique(paths,role):
 if not paths:raise Block('Missing '+role)
 h=defaultdict(list)
 for p in paths:h[sha(p)].append(p)
 if len(h)!=1:raise Block('Conflicting '+role+' copies: '+str([str(x) for x in paths]))
 p=min(paths,key=lambda x:(len(str(x)),str(x)));PROV.append({'task':TASK.name,'role':role,'path':str(p),'sha256':next(iter(h))});return p

def locate(name,part=''):return unique(candidates(name,part),name+' '+part)
def near(folder,name):
 ps=[folder/name,folder/(name+'.gz')]
 return unique([p for p in ps if p.is_file()],str(folder/name))
def package_install(package,version):
 try:
  v=im.version(package)
  if v!=version:raise Block(package+' installed '+v+'; expected '+version+'; not replaced')
 except im.PackageNotFoundError:
  log=TASK/(package+'_install.log')
  with open(log,'w') as f:r=subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-deps',package+'=='+version],stdout=f,stderr=subprocess.STDOUT,timeout=600)
  if r.returncode:raise Block('Install failed: '+log.read_text(errors='replace')[-1200:])

def zeek_binary():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek']:
  if p and Path(p).is_file():
   r=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30)
   if r.returncode==0 and re.search(r'\b8\.0\.10\b',r.stdout+r.stderr):return p
   raise Block('Installed Zeek is not 8.0.10; no replacement version was silently used')
 if os.geteuid()!=0:raise Block('Zeek missing; automatic package installation requires root')
 import urllib.request
 release=dict(x.split('=',1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
 if release.get('ID','').strip('"')!='ubuntu':raise Block('Automatic Zeek install is restricted to Ubuntu')
 ver=release['VERSION_ID'].strip('"');repo='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_'+ver+'/'
 with urllib.request.urlopen(repo+'Release.key',timeout=60) as response:key=response.read()
 if b'BEGIN PGP PUBLIC KEY BLOCK' not in key:raise Block('Invalid repository key')
 kp=Path('/etc/apt/keyrings/reviewer-zeek.asc');kp.parent.mkdir(exist_ok=True);kp.write_bytes(key)
 Path('/etc/apt/sources.list.d/reviewer-zeek.list').write_text(f'deb [signed-by={kp}] {repo} /\n')
 with open(TASK/'zeek_install.log','w') as f:
  q=subprocess.run(['apt-get','update'],stdout=f,stderr=subprocess.STDOUT,timeout=600)
  if q.returncode:raise Block('apt update failed; see Zeek installation log')
  versions=subprocess.check_output(['apt-cache','madison','zeek-8.0'],text=True)
  matches=[x.split('|')[1].strip() for x in versions.splitlines() if len(x.split('|'))>1 and re.search(r'(^|:)8\.0\.10-',x.split('|')[1].strip())]
  if not matches:raise Block('Exact Zeek 8.0.10 unavailable from repository; no substitute installed')
  q=subprocess.run(['apt-get','install','-y','--no-install-recommends','zeek-8.0='+matches[0]],stdout=f,stderr=subprocess.STDOUT,timeout=900)
  if q.returncode:raise Block('Zeek installation failed; see log')
 binary='/opt/zeek/bin/zeek';q=subprocess.run([binary,'--version'],capture_output=True,text=True,timeout=30)
 if q.returncode or not re.search(r'\b8\.0\.10\b',q.stdout+q.stderr):raise Block('Zeek installation verification failed')
 return binary

def norm(d):
 d=d.copy()
 for c in F[:-1]:
  d[c]=pd.to_numeric(d[c].replace('-',0),errors='raise').fillna(0)
  if not np.isfinite(d[c]).all() or (d[c]<0).any():raise Block('Invalid feature '+c)
 d['proto']=d.proto.astype(str).str.lower()
 if not d.proto.isin(['tcp','udp','icmp']).all():raise Block('Unsupported protocol')
 return d
def encode(d,protocol=False):
 a=np.column_stack([d.proto.eq(x).to_numpy(float) for x in ['tcp','udp','icmp']])
 return a if protocol else np.column_stack([np.log1p(d[F[:-1]].to_numpy(float)),a])
def load_model(p):
 import joblib,warnings
 from sklearn.exceptions import InconsistentVersionWarning
 with warnings.catch_warnings(record=True) as seen:
  warnings.simplefilter('always',InconsistentVersionWarning);m=joblib.load(p)
 if any(issubclass(x.category,InconsistentVersionWarning) for x in seen):raise Block('sklearn version mismatch loading '+str(p)+'; not silently changed')
 return m

def fresh48():
 if 'fresh48' not in CACHE:
  # Pin this known completed run rather than choose a newer outcome.
  part='FRESH_RAW_CAPTURE48_20261015T211111491739Z'
  p=locate('fresh_clean_target_sample.csv',part);d=norm(loadcsv(p,dtype={'ks':str}));folder=p.parent
  if len(d)!=1024 or d.ks.duplicated().any() or not d.y.isin([0,1]).all():raise Block('Fresh48 cohort differs')
  CACHE['fresh48']=(folder,d)
 return CACHE['fresh48']
def primary_inputs(name,part):
 ps=candidates(name,part)
 # Wrapper copies are valid only if their actual content agrees; retain no arbitrary selection.
 return unique(ps,name)

def us(v):return int((Decimal(str(v))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def identity(row):return (us(row['ts']),str(row['id.orig_h']),int(row['id.orig_p']),str(row['id.resp_h']),int(row['id.resp_p']),str(row['proto']).lower())
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def pcap_records(path,limit=None,budget=None):
 with open(path,'rb') as f:
  h=f.read(24)
  if len(h)!=24 or h[:4] not in MAGIC:raise Block('Classic PCAP required '+str(path))
  e,u=MAGIC[h[:4]];link=struct.unpack(e+'I',h[20:24])[0]&65535;used=24;i=0
  while limit is None or i<limit:
   off=f.tell();rh=f.read(16)
   if not rh:break
   if len(rh)!=16:raise Block('Truncated PCAP header')
   sec,sub,cap,wire=struct.unpack(e+'IIII',rh)
   if cap>16*1024**2:raise Block('Invalid PCAP packet length')
   if budget is not None and used+16+cap>budget:break
   b=f.read(cap)
   if len(b)!=cap:raise Block('Truncated packet bytes')
   yield i,sec*10**9+sub*u,cap,wire,b,off+16,h,e,u,link
   used+=16+cap;i+=1

def ipv4(b,link):
 if link==1:
  if len(b)<14:return None
  typ=int.from_bytes(b[12:14],'big');o=14
  while typ in (0x8100,0x88a8,0x9100):
   if len(b)<o+4:return None
   typ=int.from_bytes(b[o+2:o+4],'big');o+=4
  if typ!=0x800:return None
 elif link==113:
  if len(b)<16 or b[14:16]!=b'\x08\x00':return None
  o=16
 elif link==276:
  if len(b)<20 or b[:2]!=b'\x08\x00':return None
  o=20
 elif link in (12,101,228):o=0
 else:raise Block('Unsupported PCAP link '+str(link))
 if len(b)<o+20 or b[o]>>4!=4:return None
 ihl=(b[o]&15)*4;pr=b[o+9]
 if ihl<20 or len(b)<o+ihl:return None
 a=socket.inet_ntoa(b[o+12:o+16]);z=socket.inet_ntoa(b[o+16:o+20]);ports=None
 if not (int.from_bytes(b[o+6:o+8],'big')&0x3fff) and pr in (6,17) and len(b)>=o+ihl+4:ports=struct.unpack('!HH',b[o+ihl:o+ihl+4])
 return {'src':a,'dst':z,'id':int.from_bytes(b[o+4:o+6],'big'),'length':int.from_bytes(b[o+2:o+4],'big'),'pr':pr,'ports':ports,'offset':o}
def raw_capture(cap):
 ps=[p for p in RAW.rglob('*.pcap') if f'CTU-IoT-Malware-Capture-{cap}-1' in p.parts]
 if not ps:raise Block('Original PCAP missing for capture '+str(cap))
 return max(ps,key=lambda p:(p.stat().st_size,str(p)))
def published_log(cap):
 ps=[p for p in RAW.rglob('conn.log.labeled') if f'CTU-IoT-Malware-Capture-{cap}-1' in p.parts]
 if len(ps)!=1:raise Block('Expected exactly one labelled log for capture '+str(cap))
 return ps[0]
def logrows(path):
 fields=None
 with open(path,encoding='utf-8') as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:]
   elif line.strip() and not line.startswith('#'):
    if fields is None:raise Block('Missing Zeek field header')
    v=line.rstrip('\n').split('\t')
    if len(v)<len(fields):
     # IoT-23 primary/detailed labels are sometimes space-separated after the final tab field.
     if len(v) and len(v)<len(fields):v=v[:-1]+v[-1].split()
    if len(v)!=len(fields):raise Block('Log width mismatch at '+str(path))
    yield dict(zip(fields,v))

# Source provenance is written before each task. Failed tasks do not erase successful ones.
def run_task(n,title,fn):
 global TASK
 TASK=OUT/f'{n:02d}';TASK.mkdir(exist_ok=True)
 print('\n'+'='*100+'\nTASK '+str(n)+': '+title+'\n'+'='*100,flush=True)
 start=time.monotonic();status='BLOCKED';detail=''
 try:
  detail=fn() or '';status='COMPLETED_FOR_DECLARED_SCOPE'
  if n in (4,7):status='PARTIAL_REVIEWER_REQUEST'
  if n==5:status='COMPLETED_FRESH48_NOT_HISTORICAL49'
 except Block as e:detail=str(e);print('BLOCKED:',detail,flush=True)
 except Exception as e:
  status='FAILED';detail=type(e).__name__+': '+str(e);(TASK/'traceback.txt').write_text(traceback.format_exc());print('FAILED:',detail,flush=True)
 r={'task':n,'title':title,'status':status,'detail':detail,'seconds':time.monotonic()-start};LEDGER.append(r);js(TASK/'receipt.json',r)
 print('TASK RECEIPT:',json.dumps(r),flush=True);js(OUT/'TASK_LEDGER.json',LEDGER)


def task1():
 package_install('nfstream',CFG['nfstream_version'])
 from nfstream import NFStreamer
 zeek=zeek_binary();summ=[]
 scratch=TASK/'scratch';scratch.mkdir()
 for cap in CFG['cross_extractor_captures']:
  src=raw_capture(cap);records=[];first={};groups=set();header=None
  for row in pcap_records(src,limit=CFG['max_packets'],budget=CFG['prefix_bytes']):
   i,ts,ca,wi,b,off,h,e,u,link=row;header=h;x=ipv4(b,link);k=None
   if x and x['pr']==6 and x['ports']:
    k=tuple(sorted(((x['src'],x['ports'][0]),(x['dst'],x['ports'][1]))));first.setdefault(k,i);groups.add(k)
   records.append((ts,ca,wi,b,k))
  if not records:raise Block('Empty count prefix')
  for delay in CFG['cross_extractor_delays']:
   path=scratch/f'{cap}_{delay}.pcap'
   order=sorted(range(len(records)),key=lambda i:(records[i][0]+(delay*10**9 if records[i][4] is not None and first[records[i][4]]!=i else 0),i))
   with open(path,'wb') as f:
    f.write(header)
    for i in order:
     ts,ca,wi,b,k=records[i];ts+=delay*10**9 if k is not None and first[k]!=i else 0
     f.write(struct.pack(e+'IIII',ts//10**9,(ts%10**9)//u,ca,wi));f.write(b)
   ph=sha(path);zf=scratch/f'z_{cap}_{delay}';zf.mkdir();(zf/'count.zeek').write_text('@load base/protocols/conn\nredef LogAscii::use_json = T;\n')
   with open(zf/'stdout.txt','w') as so,open(zf/'stderr.txt','w') as se:
    rr=subprocess.run([zeek,'-C','-r',str(path.resolve()),str((zf/'count.zeek').resolve())],cwd=zf,stdout=so,stderr=se,timeout=1800)
   if rr.returncode or not (zf/'conn.log').is_file():raise Block('Zeek count replay failed')
   counts=Counter();total=0
   with open(zf/'conn.log') as f:
    for line in f:
     r=json.loads(line);total+=1
     if r.get('proto')=='tcp':counts[tuple(sorted(((r['id.orig_h'],int(r['id.orig_p'])),(r['id.resp_h'],int(r['id.resp_p'])))))]+=1
   summ.append({'capture':cap,'delay_seconds':delay,'extractor':'Zeek8.0.10_default','idle_s':300,'active_s':None,'packet_sha256':ph,'total_records':total,'tcp_group_records':sum(counts[k] for k in groups),'tcp_groups':len(groups),'zero_groups':sum(counts[k]==0 for k in groups)})
   shutil.rmtree(zf)
   for idle in CFG['nfstream_idle_seconds']:
    counts=Counter();total=0;start=time.monotonic()
    streamer=NFStreamer(source=str(path),decode_tunnels=False,snapshot_length=65535,idle_timeout=idle,active_timeout=CFG['nfstream_active_seconds'],n_dissections=0,statistical_analysis=False,n_meters=1)
    for f in streamer:
     total+=1
     if int(f.protocol)==6 and int(f.ip_version)==4:counts[tuple(sorted(((f.src_ip,int(f.src_port)),(f.dst_ip,int(f.dst_port)))))]+=1
    summ.append({'capture':cap,'delay_seconds':delay,'extractor':'NFStream'+CFG['nfstream_version'],'idle_s':idle,'active_s':CFG['nfstream_active_seconds'],'packet_sha256':ph,'total_records':total,'tcp_group_records':sum(counts[k] for k in groups),'tcp_groups':len(groups),'zero_groups':sum(counts[k]==0 for k in groups),'seconds':time.monotonic()-start})
   pd.DataFrame(summ).to_csv(TASK/'cross_extractor_counts.csv',index=False);print('COUNT COMPLETED',cap,delay,flush=True);path.unlink()
  del records
 table('cross_extractor_counts.csv',pd.DataFrame(summ));shutil.rmtree(scratch)
 return 'Same packet bytes for Zeek and NFStream; explicit idle/active settings differ. Five-tuple counts, not security recall or equivalent extractor semantics.'


def task3():
 folder,clean=fresh48();model=load_model(near(folder,'fresh_source_models.joblib'))
 keys=set(clean.loc[clean.y.eq(1),'ks']);outputs=[];uidoutputs=[]
 for delay in (0,1,10):
  mp=loadcsv(near(folder,f'packet_uid_mapping_{delay}s.csv'),dtype={'original_ks':str,'uid':str})
  cf=norm(loadcsv(near(folder,f'descendant_features_{delay}s.csv'),dtype={'uid':str}))
  audit=loadcsv(near(folder,f'membership_{delay}s.csv'),dtype={'ks':str}).set_index('ks')
  if mp.packet_index.duplicated().any() or cf.uid.duplicated().any() or set(mp.original_ks)!=keys:raise Block('Malformed fresh48 packet-to-record ledger')
  ep=near(folder,f'condition_{delay}s_events.txt');events=Counter()
  with open(ep,errors='strict') as f:
   for line in f:
    if line.startswith('PACKET|'):
     v=line.rstrip().split('|')
     if len(v)!=12:raise Block('Saved packet event width differs')
     events[v[2]]+=1
  sc=mp.groupby('uid').size();owners=mp.groupby('uid').original_ks.nunique();relations=mp.groupby('original_ks').uid.agg(lambda x:set(x)).to_dict()
  count=(cf.orig_pkts+cf.resp_pkts).to_numpy(int);pure={u:(owners.get(u,0)==1 and sc.get(u,0)==n and events[u]==n) for u,n in zip(cf.uid,count)}
  for u,n in zip(cf.uid,count):uidoutputs.append({'delay_seconds':delay,'uid':u,'owners':int(owners.get(u,0)),'tracked_packets':int(sc.get(u,0)),'record_packets':int(n),'event_packets':events[u],'pure':pure[u]})
  for (family,seed),m in sorted(model.items()):
   if list(m.classes_)!=[0,1]:raise Block('Class order differs')
   alarm=dict(zip(cf.uid,m.predict_proba(encode(cf,family=='PROTOCOL_ONLY_LR'))[:,1]>=.5))
   for k in sorted(keys):
    uu=relations[k];anyalarm=any(alarm[u] for u in uu);pw=any(pure[u] and alarm[u] for u in uu)
    mg=boolean(pd.Series([audit.loc[k,'membership_validated']]))[0]
    complete=int(audit.loc[k,'mapped_packets'])==int(audit.loc[k,'expected_packets']) and int(audit.loc[k,'unresolved_packets'])==0 and bool(uu) and all(u in alarm for u in uu)
    # Original strict MG leaves failed membership unknown even if another record alarms.
    mgstate='DETECTED' if mg and anyalarm else 'MISSED' if mg and not anyalarm else 'UNRESOLVED'
    pwstate='DETECTED' if pw else 'MISSED' if complete and not anyalarm else 'UNRESOLVED'
    outputs.append({'family':family,'seed':seed,'delay_seconds':delay,'ks':k,'MG':mgstate,'PURE_WITNESS':pwstate,'any_overlap_alarm':anyalarm})
 d=pd.DataFrame(outputs);d.to_csv(TASK/'same_cohort_rule_outcomes.csv',index=False)
 table('rule_transition_counts.csv',d.groupby(['family','delay_seconds','MG','PURE_WITNESS']).size().reset_index(name='unit_seed_evaluations'))
 summary=[]
 for (family,seed,delay),g in d.groupby(['family','seed','delay_seconds']):
  for rule in ['MG','PURE_WITNESS']:
   n=len(g);pos=int(g[rule].eq('DETECTED').sum());un=int(g[rule].eq('UNRESOLVED').sum())
   summary.append(dict(family=family,seed=seed,delay_seconds=delay,rule=rule,original_units=n,detected=pos,missed=int(g[rule].eq('MISSED').sum()),unresolved=un,lower=pos/n,upper=(pos+un)/n))
 table('same_cohort_bounds.csv',pd.DataFrame(summary));pd.DataFrame(uidoutputs).to_csv(TASK/'UID_purity_evidence.csv',index=False)
 return 'Same fresh48 malicious cohort, same frozen predictions, both source-derived rules. Seed rows are not independent units. This is not a benign false-alarm evaluation.'


def task4():
 package_install('scapy','2.6.1')
 from scapy.layers.l2 import Ether,CookedLinux
 from scapy.layers.inet import IP,TCP
 folder,clean=fresh48();maps={delay:loadcsv(near(folder,f'packet_uid_mapping_{delay}s.csv'),dtype={'original_ks':str,'uid':str}) for delay in [0,1,10]}
 mp=maps[0]
 if mp.packet_index.duplicated().any():raise Block('Duplicate baseline packet occurrences')
 allkeys=sorted(set(mp.original_ks),key=lambda k:hashlib.sha256(('independent-raw-check-v1'+k).encode()).hexdigest())
 chosen=set(allkeys[:CFG['validation_sample_units']]);sample=mp[mp.original_ks.isin(chosen)].copy();want=dict(zip(sample.packet_index.astype(int),sample.original_ks))
 refs=clean[clean.ks.isin(chosen)].copy();refs['start_us']=refs.ts.map(us);refs['end_us']=refs.start_us+(refs.duration*1e6).round().astype('int64')+1000
 first=mp.groupby('original_ks').packet_index.min().to_dict();targetmaps={};eventmaps={}
 for delay in [0,1,10]:
  m=maps[delay]
  if m.packet_index.duplicated().any():raise Block('Duplicate transformed packet indices')
  targetmaps[delay]=m.set_index('packet_index').uid.to_dict();em=defaultdict(Counter)
  with open(near(folder,f'condition_{delay}s_events.txt')) as f:
   for line in f:
    if not line.startswith('PACKET|'):continue
    x=line.rstrip().split('|')
    if len(x)!=12:raise Block('Saved event format differs')
    key=(us(x[1]),x[3],int(x[4]),x[5],int(x[6]),*(int(z) for z in x[7:12]));em[key][x[2]]+=1
  eventmaps[delay]=em
 src=raw_capture(48);out=[];decoded=0
 for i,ts,ca,wi,b,off,h,e,u,link in pcap_records(src,limit=max(want)+1):
  if i not in want:continue
  if link==1:pkt=Ether(b)
  elif link==113:pkt=CookedLinux(b)
  elif link in (101,228,12):pkt=IP(b)
  else:raise Block('Independent Scapy decoder unsupported link '+str(link))
  if IP not in pkt or TCP not in pkt:raise Block('Selected malicious packet is not independently decodable IPv4 TCP')
  ip=pkt[IP];tr=pkt[TCP];tt=us(Decimal(ts)/Decimal(10**9));possible=[]
  for _,r in refs.iterrows():
   ep=((str(r['id.orig_h']),int(r['id.orig_p'])),(str(r['id.resp_h']),int(r['id.resp_p'])))
   pair=((str(ip.src),int(tr.sport)),(str(ip.dst),int(tr.dport)))
   if r.proto=='tcp' and (pair==ep or pair==ep[::-1]) and r.start_us<=tt<=r.end_us:possible.append(r.ks)
  owner_state='AGREES' if possible==[want[i]] else 'AMBIGUOUS_REFERENCE' if len(possible)>1 else 'DISAGREES'
  for delay in [0,1,10]:
   tnew=tt+(delay*1000000 if i!=int(first[want[i]]) else 0)
   k=(tnew,str(ip.src),int(tr.sport),str(ip.dst),int(tr.dport),int(tr.seq),int(tr.ack),int(tr.flags),int(ip.id),int(ip.len))
   obs=eventmaps[delay].get(k,Counter());expected=targetmaps[delay].get(i)
   state='AGREES' if len(obs)==1 and expected in obs and sum(obs.values())==1 else 'AMBIGUOUS_EVENT' if sum(obs.values())>1 else 'DISAGREES'
   out.append({'packet_index':i,'ks':want[i],'delay_seconds':delay,'independent_owner_state':owner_state,'independent_owner_candidates':json.dumps(possible),
    'saved_target_uid':expected,'independent_event_UIDs':json.dumps(dict(obs)),'target_assignment_state':state})
  decoded+=1
 d=pd.DataFrame(out)
 if decoded!=len(want):raise Block('Independent raw sample incomplete')
 table('independent_packet_assignment_validation.csv',d)
 table('independent_validation_summary.csv',d.groupby(['delay_seconds','independent_owner_state','target_assignment_state']).size().reset_index(name='packet_occurrences'))
 js(TASK/'scope.json',{'sample_units':len(chosen),'sample_original_packets':decoded,'conditions':[0,1,10],
 'independent_component':'Scapy TCP/IP decoder and separately implemented source-interval plus transformed-fingerprint matcher',
 'shared_evidence':'original clean-unit time definitions and retained Zeek packet-event observations',
 'independent_expert_ground_truth':False,'external_lab_ground_truth':False,'not_independent_of_all_Zeek_instrumentation':True})
 return 'Independent implementation/decoder check on fixed 64-unit source and transformed-target sample; retained Zeek event stream is shared evidence, NOT independent expert ground truth.'


def resolve_asset(asset):
 if isinstance(asset,str):asset={'path':asset}
 if not isinstance(asset,dict) or 'path' not in asset:raise Block('Unsupported saved asset reference')
 old=Path(asset['path']);paths=[]
 if old.is_file():paths.append(old)
 suffix=old.name
 paths.extend([x for x in FILES if x.name==suffix and old.parent.name in str(x)])
 if not paths:paths.extend([x for x in FILES if x.name==suffix])
 if asset.get('member'):
  raise Block('Asset is in a nested archive; exact loose-file recovery required: '+str(asset))
 return unique(list(set(paths)),'saved asset '+str(old))

def task2():
 package_install('menelaus',CFG['menelaus_version'])
 from menelaus.concept_drift.md3 import MD3
 part='LINEAGE_MONITOR_BATCH_D_MD3_20261015T204007721129Z'
 svm=load_model(locate('source_only_MD3_SVM.joblib',part));stats=json.loads(locate('MD3_reference_statistics.json',part).read_text())
 man=json.loads(locate('input_manifest.json','LINEAGE_MONITOR_BATCH_A_20261015T202755206014Z').read_text())
 clean=norm(loadcsv(resolve_asset(man['clean']),dtype={'ks':str}));frames={0:clean}
 for cond in man['conditions']:
  d=norm(loadcsv(resolve_asset(cond['candidate_asset']),dtype={'ks':str}));d=d.set_index('ks').loc[clean.ks].reset_index();frames[int(cond['delay_seconds'])]=d
 membership=loadcsv(locate('window_membership.csv','LINEAGE_WINDOW_ORDER_RECONCILIATION_20261015T204807283205Z'),dtype={'ks':str})
 truth=loadcsv(locate('all_order_monitor_windows.csv','LINEAGE_WINDOW_ORDER_RECONCILIATION_20261015T204807283205Z'))
 feature_names=F[:-1]+['proto_tcp','proto_udp','proto_icmp']
 def X(d):return pd.DataFrame(encode(d),columns=feature_names)
 def margin(detector,sample,classifier):
  z=pd.DataFrame(sample,columns=feature_names)
  return int(abs(float(classifier.decision_function(z)[0]))<=1.)
 def new():
  # Use frozen historical source statistics, never refit/tune the reference on targets.
  ob=MD3(svm,margin_calculation_function=margin,sensitivity=2,k=10)
  ob.reference_batch_features=X(clean.iloc[:1]);ob.reference_distribution=stats.copy();ob.curr_margin_density=float(stats['md'])
  return ob
 # Verify against original saved first-warning rows before doing the new window comparison.
 old=loadcsv(locate('MD3_target_stream_results.csv',part));checks=[]
 def stream(frame):
  obj=new();first=None;density=float(stats['md']);rho=float(obj.forgetting_factor);threshold=2*float(stats['md_std'])
  vals=X(frame)
  for i in range(len(vals)):
   obj.update(vals.iloc[[i]])
   if obj.waiting_for_oracle:first=i+1;break
  return first,rho,threshold
 for row in old[old.ordering.eq('SAVED_SAMPLE_ORDER')].itertuples():
  first,rho,threshold=stream(frames[int(row.delay_seconds)])
  expected=None if pd.isna(row.first_warning_row) else int(row.first_warning_row)
  checks.append({'delay_seconds':row.delay_seconds,'saved_first_warning':expected,'reproduced_first_warning':first,'passed':first==expected})
 table('MD3_saved_stream_reproduction.csv',pd.DataFrame(checks))
 if len(checks)!=4 or not all(x['passed'] for x in checks):raise Block('Frozen MD3 source state fails original stream reproduction; no matched result claimed')
 results=[]
 for ordering,g in membership.groupby('ordering'):
  g=g.sort_values(['window','row_in_window']);keys=g.ks.tolist()
  if len(keys)!=1024 or set(keys)!=set(clean.ks):raise Block('Window-order cohort mismatch')
  for delay,frame in sorted(frames.items()):
   ordered=frame.set_index('ks').loc[keys].reset_index();first,rho,threshold=stream(ordered)
   for window,win in g.groupby('window',sort=True):
    target=truth[truth.ordering.eq(ordering)&truth.delay_seconds.eq(delay)&truth.window.eq(window)]
    if target.empty:raise Block('Matched unit target missing')
    for seed,tg in target.groupby('seed'):
     units=tg.original_unit_detection_drop.dropna().unique()
     if len(units)>1:raise Block('Unit target differs across estimator copies')
     value=float(units[0]) if len(units) else np.nan
     end=int(window)*128+len(win);warn=first is not None and first<=end
     results.append({'ordering':ordering,'delay_seconds':delay,'seed':seed,'window':window,'first_warning_row':first,'warning_by_window_end':warn,
       'unit_drop':value,'eligible':np.isfinite(value),'unit_harm':value>=.05 if np.isfinite(value) else None,
       'warning_policy':'latched by end of window; no oracle labels or post-warning adaptation'})
 d=pd.DataFrame(results);d.to_csv(TASK/'matched_MD3_windows.csv',index=False);summ=[]
 for (order,delay),g in d[d.eligible].groupby(['ordering','delay_seconds']):
  t=g.unit_harm.astype(bool);a=g.warning_by_window_end.astype(bool)
  summ.append({'ordering':order,'delay_seconds':delay,'evaluations':len(g),'TP':int((t&a).sum()),'FN':int((t&~a).sum()),'FP':int((~t&a).sum()),'TN':int((~t&~a).sum())})
 table('matched_MD3_warning_results.csv',pd.DataFrame(summ))
 return 'Exact cohort/order/window unit-damage targets; NEW explicit latched MD3 warning policy. Per-seed copies and reordered windows are dependent. No accuracy estimate or oracle confirmation.'


def task6():
 pre=json.loads(locate('PRE_REG_CAPTURE35.json','PAPER_LOCK').read_text());cfg=pre['config']
 if cfg['capture']!=35 or cfg['n_periods']!=4 or cfg['windows_per_period']!=6 or cfg['post_hoc_changes_allowed'] is not False:raise Block('Unexpected M4 protocol; not substituted')
 models={}
 for family in ['HGB','LR']:
  ps=candidates('fresh_'+family+'.joblib','RAW_ONLY_REMEASUREMENT_20261017T130813279947Z')
  ps=[p for p in ps if sha(p)==pre['model_sha256'][family]]
  mp=unique(ps,'frozen M4 '+family);models[family]=load_model(mp)
 path=published_log(35);print('M4 first pass: timestamp span and exact primary labels',flush=True)
 lo=float('inf');hi=-float('inf');total=0;cnt=Counter()
 for r in logrows(path):
  ts=float(r['ts']);lo=min(lo,ts);hi=max(hi,ts);cnt[r['label'].lower()]+=1;total+=1
 if cnt['benign']!=cfg['expected_benign'] or cnt['malicious']!=cfg['expected_malicious']:raise Block('Capture35 label counts differ from frozen contract')
 if hi<=lo:raise Block('No time span')
 dtype=np.dtype([('ts','f8'),('label','i1'),('HGB','f8'),('LR','f8')]);scores=np.lib.format.open_memmap(TASK/'reproduced_scores.npy',mode='w+',dtype=dtype,shape=(total,))
 batch=[];offset=0
 def score_batch(batch,offset):
  d=pd.DataFrame(batch);labels=d.label.astype(str).str.lower().map({'benign':0,'malicious':1})
  if labels.isna().any():raise Block('Unexpected primary labels; no relabelling')
  x=norm(d);n=len(d);scores['ts'][offset:offset+n]=d.ts.astype(float);scores['label'][offset:offset+n]=labels.to_numpy(np.int8)
  with threadpool_limits(limits=2):
   for fam,m in models.items():scores[fam][offset:offset+n]=m.predict_proba(encode(x))[:,1]
  return offset+n
 for r in logrows(path):
  batch.append({k:r.get(k,'-') for k in F+['ts','label']})
  if len(batch)>=int(cfg['chunk']):
   offset=score_batch(batch,offset);batch=[];print('M4 scored',offset,'/',total,flush=True)
 if batch:offset=score_batch(batch,offset)
 scores.flush()
 ts=scores['ts'];period=np.minimum(3,((ts-lo)/(hi-lo)*4).astype(int));windows=[];aucs=[]
 for fam in models:
  pr=scores[fam];yy=scores['label'];cal=pr[(period==0)&(yy==0)];ncal=len(cal)
  if not ncal:raise Block('Period1 has no benign baseline')
  order=np.sort(cal);eps=float(np.sqrt(np.log(1/cfg['delta'])/(2*ncal)))
  for pe in range(4):
   ix=period==pe;y=yy[ix];aucs.append({'model':fam,'period':pe+1,'rows':int(ix.sum()),'benign':int((y==0).sum()),'malicious':int((y==1).sum()),'auroc':float(roc_auc_score(y,pr[ix])) if len(np.unique(y))==2 else np.nan})
  for alpha in cfg['alphas']:
   rank=int(np.ceil((ncal+1)*(1-alpha)));cut=float(order[rank-1]) if rank<=ncal else float('inf');bound=alpha+eps
   for pe in range(1,4):
    start=lo+(hi-lo)*pe/4;span=(hi-lo)/4
    for wi in range(6):
     left=start+span*wi/6;right=start+span*(wi+1)/6
     ix=(period==pe)&(ts>=left)&((ts<=right) if pe==3 and wi==5 else (ts<right))
     y=yy[ix];p=pr[ix];neg=y==0;pos=y==1;al=p>cut;nb=int(neg.sum());nm=int(pos.sum());fp=int((al&neg).sum());tp=int((al&pos).sum());n=len(y)
     fpr=fp/nb if nb else np.nan;eligible=nb>=cfg['min_benign_window'];sample_eps=float(np.sqrt(np.log(1/cfg['delta'])/(2*nb))) if nb else np.nan
     lower=max(0.,float(al.sum())-n*bound)
     windows.append({'model':fam,'alpha':alpha,'period':pe+1,'window':(pe-1)*6+wi,'rows':n,'benign':nb,'malicious':nm,'FP':fp,'TP':tp,
      'cutoff':cut,'bound':bound,'window_benign_epsilon':sample_eps,'FPR':fpr,'recall':tp/nm if nm else np.nan,
      'eligible':eligible,'far_valid':bool(fpr<=bound+sample_eps) if eligible else None,'far_strict':bool(fpr<=bound) if eligible else None,
      'detected_mass_lower_count':lower,'lower_bound_valid':bool(lower<=tp)})
 table('M4_period_AUROC_REPRODUCTION.csv',pd.DataFrame(aucs));table('M4_windows_REPRODUCTION.csv',pd.DataFrame(windows))
 v=pd.DataFrame(windows);summary=[]
 for (fam,alpha),g in v.groupby(['model','alpha']):
  elig=g[g.eligible];testauc=[r['auroc'] for r in aucs if r['model']==fam and r['period']>1 and np.isfinite(r['auroc'])]
  summary.append({'model':fam,'alpha':alpha,'eligible_windows':len(elig),'far_valid_share':elig.far_valid.mean(),'far_strict_share':elig.far_strict.mean(),'lower_bound_valid_share':elig.lower_bound_valid.mean(),'minimum_test_period_AUROC':min(testauc) if testauc else np.nan,'median_recall':elig.recall.median()})
 table('M4_verdict_inputs_REPRODUCTION.csv',pd.DataFrame(summary))
 js(TASK/'M4_reproduction_provenance.json',{'original_pre_registration':pre,'new_run_after_outcome_exposure':True,'not_new_blind_confirmation':True,'labelled_log':str(path),'rows':total,'min_ts':lo,'max_ts':hi,'baseline_rule_reproduced':True,'window_target_labels_used_only_offline':True})
 return 'Reproduction after known outcomes under frozen rules/model hashes; actual per-window CSV now saved. Existing formula validity is evaluated, not assumed or rewritten.'


def task7():
 tex=[p for p in FILES if p.suffix.lower()=='.tex' and p.stat().st_size<8*1024**2]
 mains=[p for p in tex if '\\documentclass' in p.read_text(errors='replace')]
 if len(mains)!=1:raise Block('Need exactly one manuscript main .tex source (including its figures/bib/styles). Candidates='+str([str(p) for p in mains]))
 src=mains[0];dest=TASK/'manuscript';dest.mkdir();root=src.parent
 # Copy the local manuscript tree only; no write to uploaded source.
 size=sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
 if size>256*1024**2:raise Block('Manuscript directory >256 MiB; attach a dedicated source bundle')
 shutil.copytree(root,dest,dirs_exist_ok=True)
 main=dest/src.name;issues=[]
 for p in dest.rglob('*'):
  if p.is_file() and p.suffix.lower() in ('.tex','.bbl','.bib'):
   text=p.read_text(errors='replace')
   for i,line in enumerate(text.splitlines(),1):
    if re.search(r'\\bibitem\s*(?:\[[^]]*\])?\s*\{\s*\}',line):issues.append({'file':str(p.relative_to(dest)),'line':i,'issue':'EMPTY_BIBITEM','text':line})
 pd.DataFrame(issues,columns=['file','line','issue','text']).to_csv(TASK/'source_issues.csv',index=False)
 if shutil.which('latexmk'):
  cmd=['latexmk','-pdf','-no-shell-escape','-interaction=nonstopmode','-halt-on-error',main.name]
  with open(TASK/'compile_stdout.txt','w') as f:r=subprocess.run(cmd,cwd=dest,stdout=f,stderr=subprocess.STDOUT,timeout=600)
 else:
  if not shutil.which('pdflatex'):raise Block('Manuscript source found, but latexmk/pdflatex is not installed. No unverified TeX installation launched')
  rc=0
  with open(TASK/'compile_stdout.txt','w') as f:
   for step in range(3):
    r=subprocess.run(['pdflatex','-no-shell-escape','-interaction=nonstopmode','-halt-on-error',main.name],cwd=dest,stdout=f,stderr=subprocess.STDOUT,timeout=300);rc|=r.returncode
    if step==0 and (dest/(main.stem+'.aux')).is_file() and '\\bibdata' in (dest/(main.stem+'.aux')).read_text(errors='replace'):
     if not shutil.which('bibtex'):raise Block('BibTeX required by manuscript but unavailable')
     q=subprocess.run(['bibtex',main.stem],cwd=dest,stdout=f,stderr=subprocess.STDOUT,timeout=180);rc|=q.returncode
   r.returncode=rc
 log=dest/(main.stem+'.log');text=log.read_text(errors='replace') if log.is_file() else ''
 trouble=[x for x in text.splitlines() if re.search(r'undefined|multiply defined|Fatal error|^!',x,re.I)]
 for x in trouble:print(x,flush=True)
 js(TASK/'compile_checks.json',{'return_code':r.returncode,'PDF_exists':(dest/(main.stem+'.pdf')).is_file(),'unresolved_log_messages':trouble,'empty_bibitem_entries':issues,'bibliographic_metadata_independently_verified':False})
 if r.returncode or trouble or issues:raise Block('Compile/source issues remain; see preserved logs. No manuscript text was auto-deleted')
 return 'PDF compiled with no detected undefined refs/citations or empty bibitems. DOI/author/venue accuracy still requires bibliographic verification; successful compilation does not prove it.'


# New benign-unit extension on the SAME fresh48 1,024-row cohort. It needs instrumented replay,
# because the old retained packet ledger tracks malicious units only.
def task5():
 binary=zeek_binary();folder,clean=fresh48();models=load_model(near(folder,'fresh_source_models.joblib'))
 proofs=json.loads(near(folder,'condition_provenance.json').read_text());proofs={int(x['delay_seconds']):x for x in proofs}
 if not {0,10}.issubset(proofs):raise Block('Frozen fresh48 packet hashes/conditions absent')
 n=int(proofs[0]['packets']);src=raw_capture(48)
 if shutil.disk_usage(WORK).free<3*1024**3:raise Block('Need 3 GiB free for full historical-prefix accounting extension')
 scratch=TASK/'scratch';scratch.mkdir();basepcap=scratch/'prefix.pcap'
 # Store packet offsets, not payloads. The unchanged prefix must reproduce its saved hash.
 from array import array
 stamps=array('q');offsets=array('q');caps=array('I');wires=array('I');header=None
 with open(basepcap,'wb') as dst:
  for i,ts,ca,wi,b,off,h,e,u,link in pcap_records(src,limit=n):
   if header is None:header=h;dst.write(h)
   dst.write(struct.pack(e+'IIII',ts//10**9,(ts%10**9)//u,ca,wi));dst.write(b)
   stamps.append(ts);offsets.append(off);caps.append(ca);wires.append(wi)
 if len(stamps)!=n or sha(basepcap)!=proofs[0]['condition_pcap_sha256']:raise Block('Original fresh48 prefix hash did not reproduce; no new cohort substituted')
 watched=set()
 for _,r in clean.iterrows():
  for a,b,ap,bp in [(r['id.orig_h'],r['id.resp_h'],r['id.orig_p'],r['id.resp_p']),(r['id.resp_h'],r['id.orig_h'],r['id.resp_p'],r['id.orig_p'])]:
   watched.add(f'{a}|{int(ap)}|{b}|{int(bp)}|{r.proto}')
 tap="""@load base/protocols/conn
redef LogAscii::use_json = T;
const watched: set[string] = { ENTRIES };
event new_packet(c: connection, p: pkt_hdr) {
 if (! p?$ip) return;
 local k = fmt("%s|%d|%s|%d|%s", c$id$orig_h, port_to_count(c$id$orig_p), c$id$resp_h, port_to_count(c$id$resp_p), get_port_transport_proto(c$id$orig_p));
 if (k !in watched) return;
 print fmt("PKT|%.6f|%s|%s|%s|%d|%d|%s", network_time(), c$uid, p$ip$src, p$ip$dst, p$ip$id, p$ip$len, get_port_transport_proto(c$id$orig_p));
}
""".replace('ENTRIES',','.join(json.dumps(x) for x in sorted(watched)))
 # Frozen 10-second action is reconstructed from original selected malicious packet indices.
 oldmap=loadcsv(near(folder,'packet_uid_mapping_0s.csv'),dtype={'original_ks':str});first=oldmap.groupby('original_ks').packet_index.min().to_dict();delayed=set()
 for r in oldmap.itertuples():
  if int(r.packet_index)!=int(first[r.original_ks]):delayed.add(int(r.packet_index))
 traced={0:basepcap};newpath=scratch/'paced10.pcap';dt=np.zeros(n,dtype=np.int64);dt[list(delayed)]=10*10**9
 tsarray=np.asarray(stamps,dtype=np.int64)+dt;order=np.argsort(tsarray,kind='stable')
 with open(src,'rb') as sf,open(newpath,'wb') as dst:
  dst.write(header)
  for i in order:
   i=int(i);sf.seek(offsets[i]);b=sf.read(caps[i]);tt=int(tsarray[i]);dst.write(struct.pack(e+'IIII',tt//10**9,(tt%10**9)//u,caps[i],wires[i]));dst.write(b)
 if sha(newpath)!=proofs[10]['condition_pcap_sha256']:raise Block('Historical paced-prefix hash did not reproduce; no changed transformation silently used')
 traced[10]=newpath;states={};uid_to_unit=None;reference_owner={};raw_matches=defaultdict(list);keys=set(clean.ks)
 def fp(ts,srcip,dstip,ident,length,proto):return (us(ts),str(srcip),str(dstip),int(ident),int(length),str(proto))
 for delay in (0,10):
  case=scratch/f'delay{delay}';case.mkdir();sp=case/'tap.zeek';sp.write_text(tap)
  with open(case/'compile.txt','w') as f:rc=subprocess.run([binary,'-b',str(sp.resolve())],cwd=case,stdout=f,stderr=subprocess.STDOUT,timeout=60)
  if rc.returncode:raise Block('New all-cohort instrumentation did not compile; see '+str(case/'compile.txt'))
  with open(case/'events.txt','w') as so,open(case/'stderr.txt','w') as se:
   rc=subprocess.run([binary,'-C','-r',str(traced[delay].resolve()),str(sp.resolve())],cwd=case,stdout=so,stderr=se,timeout=1800)
  if rc.returncode or not (case/'conn.log').is_file():raise Block('All-cohort extraction failed')
  ev=defaultdict(Counter);ec=Counter()
  with open(case/'events.txt') as f:
   for line in f:
    if not line.startswith('PKT|'):continue
    x=line.rstrip().split('|')
    if len(x)!=8:raise Block('Packet-event format differs')
    k=fp(x[1],x[3],x[4],x[5],x[6],x[7]);ev[k][x[2]]+=1;ec[x[2]]+=1
  records={};clean_ids={};cleanrows={}
  lookup={identity(r):r['ks'] for r in clean.to_dict('records')}
  with open(case/'conn.log') as f:
   for line in f:
    r=json.loads(line)
    try:k=identity(r)
    except Exception:continue
    if r['uid'] in ec:
     rr={c:r.get(c,0) for c in F};rr['uid']=r['uid'];records[r['uid']]=rr
    if delay==0 and k in lookup:
     if lookup[k] in clean_ids:raise Block('Nonunique clean reference identity')
     clean_ids[lookup[k]]=r['uid'];cleanrows[lookup[k]]=r
  if delay==0:
   if set(clean_ids)!=keys:raise Block('All 1,024 original clean identities were not retained; denominator not reduced')
   uid_to_unit={v:k for k,v in clean_ids.items()}
   # Verify clean predictors against frozen original sample, before using the new ledger.
   z=norm(pd.DataFrame([cleanrows[k] for k in clean.ks]));orig=norm(clean)
   if not np.allclose(z[F[:-1]].to_numpy(float),orig[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(z.proto,orig.proto):raise Block('New clean replay features differ from frozen sample')
   for i,ts,ca,wi,b,off,h,ee,uu,ll in pcap_records(src,limit=n):
    x=ipv4(b,ll)
    if x is None:continue
    proto={6:'tcp',17:'udp',1:'icmp'}.get(x['pr'])
    if proto is None:continue
    k=fp(Decimal(ts)/Decimal(10**9),x['src'],x['dst'],x['id'],x['length'],proto)
    if k in ev:raw_matches[k].append(i)
   for k,indices in raw_matches.items():
    cnt=ev[k]
    if len(cnt)==1 and sum(cnt.values())==len(indices):
     own=uid_to_unit.get(next(iter(cnt)),'OUTSIDE_SELECTED')
    else:own='AMBIGUOUS'
    for i in indices:reference_owner[i]=own
  predicted=defaultdict(list)
  for k,indices in raw_matches.items():
   for i in indices:
    kk=(k[0]+(10*1000000 if delay and i in delayed else 0),)+k[1:]
    predicted[kk].append((i,reference_owner[i]))
  relation=defaultdict(set);owned=defaultdict(set);mapped=Counter();bad=Counter();tracked=Counter()
  for k,cnt in ev.items():
   entries=predicted.get(k,[]);owners={x[1] for x in entries}
   valid=sum(cnt.values())==len(entries) and len(owners)==1 and 'AMBIGUOUS' not in owners
   if valid:
    owner=next(iter(owners))
    for uid,number in cnt.items():
     owned[uid].add(owner)
     if owner in keys:relation[owner].add(uid);mapped[owner]+=number;tracked[uid]+=number
   else:
    for uid in cnt:owned[uid].add('AMBIGUOUS')
    for _,owner in entries:
     if owner in keys:bad[owner]+=1
  for k,entries in predicted.items():
   if k not in ev:
    for _,owner in entries:
     if owner in keys:bad[owner]+=1
  cf=norm(pd.DataFrame(records.values()));expected={r.ks:int(r.orig_pkts+r.resp_pkts) for r in clean.itertuples()}
  pure={r.uid:owned[r.uid] in ({k} for k in keys) and tracked[r.uid]==int(r.orig_pkts+r.resp_pkts)==ec[r.uid] for r in cf.itertuples()}
  complete={k:mapped[k]==expected[k] and bad[k]==0 and bool(relation[k]) and relation[k].issubset(records) for k in keys}
  states[delay]=(cf,relation,pure,complete,owned,tracked,expected)
  print('All-cohort ledger built:',delay,'seconds; complete units',sum(complete.values()),'/',len(keys),flush=True)
 results=[];unitrows=[];ben=clean[clean.y.eq(0)].ks.tolist()
 for (family,seed),model in sorted(models.items()):
  for delay,(cf,rel,pure,complete,owned,tracked,expected) in states.items():
   alarm=dict(zip(cf.uid,model.predict_proba(encode(cf,family=='PROTOCOL_ONLY_LR'))[:,1]>=.5));cfidx=cf.set_index('uid');nben=len(ben)
   for rule in ['ANY_OVERLAP','MG','PURE_WITNESS']:
    yes=no=un=0
    for k in ben:
     uu=rel[k];has=any(alarm.get(u,False) for u in uu);pw=any(alarm.get(u,False) and pure.get(u,False) for u in uu)
     strict=complete[k] and all(owned[u]=={k} for u in uu) and sum(int(cfidx.loc[u,'orig_pkts']+cfidx.loc[u,'resp_pkts']) for u in uu)==expected[k]
     if rule=='ANY_OVERLAP':a=has;b=complete[k] and not has
     elif rule=='MG':a=strict and has;b=strict and not has
     else:a=pw;b=complete[k] and not has
     state='ALARM' if a else 'NO_ALARM' if b else 'UNRESOLVED';yes+=state=='ALARM';no+=state=='NO_ALARM';un+=state=='UNRESOLVED'
     unitrows.append({'family':family,'seed':seed,'delay_seconds':delay,'rule':rule,'ks':k,'label':0,'state':state})
    results.append({'family':family,'seed':seed,'delay_seconds':delay,'rule':rule,'benign_original_units':nben,'definite_alarm':yes,'no_alarm':no,'unresolved':un,'benign_alarm_lower':yes/nben,'benign_alarm_upper':(yes+un)/nben})
 table('benign_descendant_alarm_bounds.csv',pd.DataFrame(results));pd.DataFrame(unitrows).to_csv(TASK/'benign_original_unit_outcomes.csv',index=False)
 js(TASK/'scope.json',{'cohort':'exact original fresh48 1,024-row cohort; 512 benign units','model_file':str(near(folder,'fresh_source_models.joblib')),
 'input_packet_hashes_verified_against_original':True,'conditions':[0,10],'new_all_cohort_instrumentation':True,'not_the_historical_capture49_cohort':True,
 'labels_not_inherited_by_mixed_records':True})
 shutil.rmtree(scratch)
 return 'Matched benign original-unit denominators on fresh48 under three explicit descendant policies. This is NOT a historical capture49 benign-FPR result; no cross-cohort substitution claimed.'


def main():
 js(OUT/'PREEXECUTION_PROTOCOL.json',CFG)
 env={'python':sys.version,'platform':__import__('platform').platform(),'packages':{}}
 for package in ['numpy','pandas','scikit-learn','joblib','menelaus','nfstream','scapy']:
  try:env['packages'][package]=im.version(package)
  except im.PackageNotFoundError:env['packages'][package]='NOT_INSTALLED'
 js(OUT/'START_ENVIRONMENT.json',env)
 if globals().get('__file__') and Path(__file__).is_file():
  shutil.copyfile(__file__,OUT/'executed_runner.py');js(OUT/'CODE_IDENTITY.json',{'sha256':sha(Path(__file__))})
 for root in [Path('/kaggle/input/datasets'),WORK]:
  if not root.is_dir():continue
  for cur,dirs,names in os.walk(root,followlinks=False):
   dirs[:]=[x for x in dirs if (Path(cur)/x)!=OUT and x not in ('.git','__pycache__')]
   for name in names:FILES.append(Path(cur)/name)
 print('Visible artifacts indexed:',len(FILES),flush=True)
 with threadpool_limits(limits=2):
  for n,title,fn in [(1,'Second extractor: NFStream vs Zeek on identical count-prefix PCAPs',task1),
   (2,'Published MD3 warning stage against matched saved unit-damage windows',task2),
   (3,'Same-cohort MG and pure-witness sensitivity on fresh48',task3),
   (4,'Independent decoder/reference-owner validation sample',task4),
   (5,'Benign original-unit descendant alarms: fresh48 all-cohort replay',task5),
   (6,'Capture35 frozen-protocol reproduction with saved window outputs',task6),
   (7,'Actual manuscript source compilation and reference-log checks',task7)]:run_task(n,title,fn)
 pd.DataFrame(PROV).to_csv(OUT/'INPUT_PROVENANCE.csv',index=False)
 pd.DataFrame(LEDGER).to_csv(OUT/'TASK_LEDGER.csv',index=False)
 # These explicit residual scopes cannot be certified away by a parser or a compile command.
 residual={'independent_target_ground_truth_adjudication':'NOT_PERFORMED; task4 checks clean packet ownership with an independent decoder, not transformed-target ground truth',
 'historical_capture49_benign_descendant_FPR':'NOT_REPLACED by task5 fresh48 benign-unit extension',
 'bibliographic_metadata_authenticity':'NOT_VERIFIED by compilation; publisher/DOI checks remain distinct',
 'all_seven_reviewer_requests_automatically_closed':False}
 js(OUT/'SCIENTIFIC_SCOPE_CHECK.json',residual)
 print('\nFINAL TASK LEDGER\n'+pd.DataFrame(LEDGER).to_string(index=False,max_colwidth=None),flush=True)
 print('\nSCIENTIFIC SCOPE\n'+json.dumps(residual,indent=2),flush=True)
 (OUT/'README.md').write_text('# Reviewer experiment batch\n\nAll task-specific outputs and blockers are preserved.\nNo result is fabricated and no input conflict is resolved by outcome selection.\nTask completion is scoped, not equivalent to all reviewer requests solved.\nSee SCIENTIFIC_SCOPE_CHECK.json.\nNew evaluation policies are post-exposure and are not retroactive confirmation.\n')
 zpath=OUT/'PRIVATE_REVIEWER_EXPERIMENTS.zip'
 with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(OUT.rglob('*')):
   if p.is_file() and p!=zpath and 'scratch' not in p.relative_to(OUT).parts and p.suffix not in ('.pcap','.npy'):
    z.write(p,str(p.relative_to(OUT)))
 with zipfile.ZipFile(zpath) as z:
  bad=z.testzip()
  if bad:raise RuntimeError('ZIP CRC failed '+bad)
 print('PACKAGE:',zpath,'\nSHA256:',sha(zpath),flush=True)

if __name__=='__main__':main()
