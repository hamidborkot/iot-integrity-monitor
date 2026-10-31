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
 raise Block('Zeek 8.0.10 not installed in current runtime; completed backups do not install an executable')
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
 except Block as e:detail=str(e);print('BLOCKED:',detail,flush=True)
 except Exception as e:
  status='FAILED';detail=type(e).__name__+': '+str(e);(TASK/'traceback.txt').write_text(traceback.format_exc());print('FAILED:',detail,flush=True)
 r={'task':n,'title':title,'status':status,'detail':detail,'seconds':time.monotonic()-start};LEDGER.append(r);js(TASK/'receipt.json',r)
 print('TASK RECEIPT:',json.dumps(r),flush=True);js(OUT/'TASK_LEDGER.json',LEDGER)
