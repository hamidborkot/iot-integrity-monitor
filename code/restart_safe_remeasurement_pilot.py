# Restart-safe remeasurement pilot. No notebook history, no implicit retraining.
from pathlib import Path,PurePosixPath
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from collections import defaultdict,Counter
from contextlib import contextmanager
import gc,gzip,hashlib,io,json,math,os,re,shutil,socket,sqlite3,struct,subprocess,time,traceback,urllib.request,warnings,zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
BACKUP_NAMES=['batch5','all-kaggle-work','extractor','complete-backup','full-backup','last-day-backup','one-last','ran-files','the-last-update','whole-in-one','the-last-days-backup']
BACKUPS=[Path('/kaggle/input/datasets/mdhamidborkottulla')/n for n in BACKUP_NAMES]
OUT=W/('REMEASUREMENT_RESTART_V2_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
CFG={'captures':[34,49,7],'prefix_MiB':64,'max_packets':1500000,'conditions_seconds':[0,10],
 'timeouts_seconds':[5,15],'reference_units':2048,'label_row_limit':4000000,
 'window_seconds':60,'grace_seconds':30,'tail_seconds':120,'seed':99101,
 'policy_budgets':[.1,.25,.5,1.],'random_schedules':100,'minimum_helpful_units':20,
 'minimum_informative_captures':2,'auto_install_exact_zeek':True}
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
class Stop(Exception):pass
REPORT={'status':'STARTED','output_directory':str(OUT),'model_fits':0,'scientific_decision':'NOT_ESTABLISHED'}

def js(p,x):
 p=Path(p);tmp=p.with_name(p.name+'.tmp');tmp.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8');tmp.replace(p)
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))

def num(x):
    v=0. if x in ['-','',None] else float(x)
    if not math.isfinite(v) or v<0:raise ValueError('Invalid predictor')
    return v

def features(r):
    x={c:num(r[c]) for c in F[:-1]};x['proto']=r['proto'].lower()
    if x['proto'] not in ['tcp','udp','icmp']:raise ValueError('Unsupported protocol')
    return x

def record_key(r):
    x=[us(r['ts']),r['id.orig_h'],int(r['id.orig_p']),r['id.resp_h'],int(r['id.resp_p']),r['proto'].lower()]
    return hashlib.sha256(json.dumps(x,separators=(',',':')).encode()).hexdigest()

def logs(path,labelled=False):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):
                fields=line.strip().split()[1:]
                if labelled and 'label' not in fields:raise Stop('Original primary label not parsed')
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Zeek field header missing')
                values=line.rstrip().split()
                if len(values)!=len(fields):raise Stop('Zeek row width differs from header')
                yield dict(zip(fields,values))

def header(path):
    with open(path,'rb') as f:h=f.read(24)
    if len(h)!=24 or h[:4] not in MAGIC:raise Stop('Classic PCAP required')
    e,u=MAGIC[h[:4]];link=struct.unpack(e+'I',h[20:24])[0]&65535
    if link not in [1,113,276,101,228,12]:raise Stop('Unsupported PCAP link type')
    return h,e,u,link

def packets(path):
    h,e,u,link=header(path)
    with open(path,'rb') as f:
        f.seek(24);i=0;off=24
        while True:
            rh=f.read(16)
            if not rh:break
            if len(rh)!=16:raise Stop('Truncated PCAP header')
            sec,sub,cap,wire=struct.unpack(e+'IIII',rh)
            if cap>16*1024**2:raise Stop('Implausible packet size')
            b=f.read(cap)
            if len(b)!=cap:raise Stop('Truncated packet bytes')
            yield i,sec*10**9+sub*u,cap,wire,b,off+16
            i+=1;off+=16+cap

def ip_packet(b,link):
    if link==1:
        if len(b)<14:return None
        typ=int.from_bytes(b[12:14],'big');o=14
        while typ in [0x8100,0x88a8,0x9100]:
            if len(b)<o+4:return None
            typ=int.from_bytes(b[o+2:o+4],'big');o+=4
        if typ!=0x800:return None
    elif link==113:
        if len(b)<16 or b[14:16]!=b'\x08\x00':return None
        o=16
    elif link==276:
        if len(b)<20 or b[:2]!=b'\x08\x00':return None
        o=20
    else:o=0
    if len(b)<o+20 or b[o]>>4!=4:return None
    ihl=(b[o]&15)*4
    if ihl<20 or len(b)<o+ihl:return None
    proto={6:'tcp',17:'udp'}.get(b[o+9])
    if proto is None:return None
    src=socket.inet_ntoa(b[o+12:o+16]);dst=socket.inet_ntoa(b[o+16:o+20])
    ident=int.from_bytes(b[o+4:o+6],'big');length=int.from_bytes(b[o+2:o+4],'big')
    fragment=int.from_bytes(b[o+6:o+8],'big')&0x3fff
    ports=None
    if not fragment and len(b)>=o+ihl+4:ports=struct.unpack('!HH',b[o+ihl:o+ihl+4])
    return src,dst,ident,length,proto,ports

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])


_BANK_NAMES={'five_seed_models_and_calibrators.joblib','frozen_five_seed_bank.joblib'}
_PANEL_NAMES={'source_panel_with_network_groups.csv.gz','source_panel_with_network_groups.csv'}
_RECOVERY_ERRORS=[]

@contextmanager
def asset_open(a):
 chain=a.get('zip_chain',[])
 if chain:
  with zipfile.ZipFile(a['path']) as outer:
   payload=outer.read(chain[0])
  if len(payload)>64*1024**2:raise Stop('Nested archive exceeds 64 MiB bound')
  for member in chain[1:]:
   with zipfile.ZipFile(io.BytesIO(payload)) as z:payload=z.read(member)
   if len(payload)>64*1024**2:raise Stop('Nested archive exceeds 64 MiB bound')
  with zipfile.ZipFile(io.BytesIO(payload)) as z,z.open(a['member']) as f:yield f
 elif a.get('member'):
  with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
 else:
  with open(a['path'],'rb') as f:yield f

def asset_bytes(a,limit=64*1024**2):
 with asset_open(a) as f:b=f.read(limit+1)
 if len(b)>limit:raise Stop('Metadata/model exceeds 64 MiB bound: '+str(a))
 return b

def discover_inputs():
 assets=[];archives=[];seen=set();dirs=0
 roots=BACKUPS+[W]
 for root in roots:
  if not root.is_dir():continue
  for current,subdirs,files in os.walk(root,followlinks=False):
   dirs+=1
   subdirs[:]=[d for d in subdirs if d not in {'.git','__pycache__'} and not (Path(current)/d).resolve().is_relative_to(OUT.resolve())]
   for name in files:
    p=Path(current)/name
    if p.is_symlink() or str(p) in seen:continue
    seen.add(str(p))
    if name in _BANK_NAMES|_PANEL_NAMES:
     assets.append({'path':str(p),'member':'','logical':str(p),'bytes':p.stat().st_size})
    if name.lower().endswith('.zip'):archives.append(p)
 nested_read_bytes=0;nested_limit=512*1024**2;seen_nested=set()
 def scan_archive(z,physical,chain,depth):
  nonlocal nested_read_bytes
  for inf in z.infolist():
   if inf.is_dir():continue
   name=PurePosixPath(inf.filename).name
   if name in _BANK_NAMES|_PANEL_NAMES:
    assets.append({'path':str(physical),'member':inf.filename,'zip_chain':list(chain),
     'logical':'!/'.join([*chain,inf.filename]),'bytes':inf.file_size})
   elif name.lower().endswith('.zip') and depth<2:
    if inf.file_size>64*1024**2 or nested_read_bytes+inf.file_size>nested_limit:
     _RECOVERY_ERRORS.append({'archive':str(physical),'member':inf.filename,'status':'NESTED_SCAN_SIZE_LIMIT'});continue
    try:
     payload=z.read(inf);nested_read_bytes+=len(payload);digest=hashlib.sha256(payload).hexdigest()
     if digest in seen_nested:continue
     seen_nested.add(digest)
     with zipfile.ZipFile(io.BytesIO(payload)) as inner:scan_archive(inner,physical,[*chain,inf.filename],depth+1)
    except (OSError,ValueError,zipfile.BadZipFile) as ex:_RECOVERY_ERRORS.append({'archive':str(physical),'member':inf.filename,'error':str(ex)})
 for p in archives:
  try:
   with zipfile.ZipFile(p) as z:scan_archive(z,p,[],0)
  except (OSError,zipfile.BadZipFile) as ex:_RECOVERY_ERRORS.append({'path':str(p),'error':str(ex)})
 pd.DataFrame(assets,columns=['path','member','logical','bytes']).to_csv(OUT/'recovery_candidates.csv',index=False)
 js(OUT/'recovery_scan.json',{'roots':[{'path':str(p),'mounted':p.is_dir()} for p in roots],
  'directories_scanned':dirs,'archives_scanned':len(archives),'candidate_inputs':len(assets),
  'nested_ZIP_depth_limit':2,'nested_ZIP_read_bytes':nested_read_bytes,'errors':_RECOVERY_ERRORS})
 print('RECOVERY: scanned',len(archives),'ZIPs; found',len(assets),'bank/panel candidates.',flush=True)
 return assets

def normalized_panel(data):
 if data[:2]==b'\x1f\x8b':
  with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:data=f.read(64*1024**2+1)
  if len(data)>64*1024**2:raise Stop('Expanded source panel exceeds bound')
 df=pd.read_csv(io.BytesIO(data),dtype=str,keep_default_na=False)
 if not set(['source_scenario','ks','y']+F).issubset(df):raise Stop('Source-panel schema mismatch')
 for c in F[:-1]:
  df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
  if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid source predictor')
 df['proto']=df.proto.str.lower();df['y']=pd.to_numeric(df.y,errors='raise').astype(int)
 if not df.y.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Source-panel category mismatch')
 fingerprint=hashlib.sha256(pd.util.hash_pandas_object(df[['source_scenario','ks','y']+F],index=False).to_numpy().tobytes()).hexdigest()
 return df,fingerprint

def recover_frozen_bank():
 assets=discover_inputs();bankassets=[a for a in assets if PurePosixPath(a['logical']).name in _BANK_NAMES]
 panelassets=[a for a in assets if PurePosixPath(a['logical']).name in _PANEL_NAMES]
 if not bankassets:
  raise Stop('FROZEN_BANK_NOT_FOUND: no exact five_seed_models_and_calibrators.joblib or frozen_five_seed_bank.joblib in the listed files/ZIPs. A fresh runtime cannot recreate a model that was never backed up. See recovery_scan.json; no replacement model fitted.')
 banks={};panels={};audit=[]
 for a in bankassets:
  try:
   b=asset_bytes(a);h=hashlib.sha256(b).hexdigest()
   banks.setdefault(h,{'asset':a,'data':b})
  except Exception as e:audit.append({'kind':'bank','asset':a,'status':str(e)})
 # Only user-owned mounted models are loaded. Version warnings stop rather than
 # interpreting predictions from an incompatible sklearn serialization.
 from sklearn.exceptions import InconsistentVersionWarning
 valid=[]
 for h,candidate in banks.items():
  a=candidate['asset']
  try:
   with warnings.catch_warnings():
    warnings.simplefilter('error',InconsistentVersionWarning)
    bank=joblib.load(io.BytesIO(candidate['data']))
   expected={(p,f,s) for p in ['GROUP_DISJOINT','ROW_FIT_CAL_CONTROL'] for f in ['HGB','LR'] for s in [8101,8102,8103,8104,8105]}
   if not isinstance(bank,dict) or set(bank.get('models',{}))!=expected:raise Stop('Not the controlled five-seed bank')
   if set(bank.get('calibrators',{}))!=expected:raise Stop('Calibrator bank differs')
   signature=bank.get('protocol',{}).get('source_ordered_semantic_sha256')
   if not signature:raise Stop('Frozen source-panel semantic fingerprint missing')
   valid.append((h,candidate,bank,signature))
   audit.append({'kind':'bank','asset':a,'sha256':h,'status':'VALID_CONTROLLED_BANK'})
  except Exception as e:audit.append({'kind':'bank','asset':a,'sha256':h,'status':str(e)})
 for a in panelassets:
  try:
   df,sig=normalized_panel(asset_bytes(a));panels.setdefault(sig,{'asset':a,'frame':df})
   audit.append({'kind':'panel','asset':a,'source_ordered_semantic_sha256':sig,'status':'PARSED'})
  except Exception as e:audit.append({'kind':'panel','asset':a,'status':str(e)})
 js(OUT/'recovery_validation.json',audit)
 pairs=[v for v in valid if v[3] in panels]
 if not pairs:raise Stop('No verified bank/source-panel pair. Review recovery_validation.json for missing panel, incompatible sklearn version, or semantic fingerprint mismatch. No retraining performed.')
 if len(pairs)>1:raise Stop('More than one distinct valid frozen bank was found. No experiment started: specify its SHA256 rather than choose a model using target results.')
 h,candidate,bank,sig=pairs[0];panel=panels[sig]['frame'];a=panels[sig]['asset']
 local=OUT/'restored_inputs';local.mkdir()
 (local/'five_seed_models_and_calibrators.joblib').write_bytes(candidate['data'])
 panel.to_csv(local/'source_panel_with_network_groups.csv.gz',index=False,compression='gzip')
 models={family:bank['models'][('GROUP_DISJOINT',family,8101)] for family in ['HGB','LR']}
 calidx=np.asarray(bank['source_roles']['GROUP_DISJOINT']['calibration'],dtype=int)
 if len(calidx)==0 or calidx.min()<0 or calidx.max()>=len(panel):raise Stop('Frozen calibration indices do not fit verified panel')
 ref=panel.iloc[calidx];rates={}
 with threadpool_limits(limits=2):
  for family,model in models.items():
   if list(model.classes_)!=[0,1]:raise Stop('Model class order mismatch')
   rates[family]=float((model.predict_proba(encode(ref))[:,1]>=.5).mean())
 js(OUT/'model_binding.json',{'bank_original_location':candidate['asset'],'bank_sha256':h,
  'source_original_location':a,'source_ordered_semantic_sha256':sig,
  'source_fingerprint_matches_frozen_protocol':True,'families':list(models),'seed':8101,
  'policy':'GROUP_DISJOINT','source_calibration_positive_rates':rates,'models_retrained':False})
 print('RECOVERY VERIFIED: exact bank + matching ordered source panel. No fitting.',flush=True)
 return models,rates

def checkpoint():
 dest=OUT/'PRIVATE_restart_pilot_checkpoint.zip';tmp=OUT/'checkpoint.tmp'
 manifest=[]
 with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(OUT.rglob('*')):
   if not p.is_file() or p in [dest,tmp] or 'scratch' in p.relative_to(OUT).parts or p.suffix=='.zip':continue
   if p.stat().st_size>64*1024**2:continue
   rel=str(p.relative_to(OUT));z.write(p,rel);manifest.append({'member':rel,'bytes':p.stat().st_size,'sha256':sha(p)})
  z.writestr('CHECKPOINT_MANIFEST.json',json.dumps(manifest,indent=2))
 with zipfile.ZipFile(tmp) as z:
  if z.testzip():raise Stop('Checkpoint CRC validation failed')
 tmp.replace(dest)
 return {'path':str(dest),'bytes':dest.stat().st_size,'sha256':sha(dest),'members':len(manifest),'private':True}

def ensure_zeek():
    def find():
        for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
            if p and Path(p).is_file():
                r=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30)
                if r.returncode==0 and re.search(r'(?<![\d.])8\.0\.10(?![\d.])',r.stdout+r.stderr):return p,(r.stdout+r.stderr).strip()
        return None,None
    p,v=find()
    if p:return p,v
    if os.geteuid()!=0:raise Stop('Zeek 8.0.10 missing and installation requires root')
    release={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,value=line.split('=',1);release[k]=value.strip('"')
    if release.get('ID')!='ubuntu' or release.get('VERSION_ID') not in ['20.04','22.04','24.04','26.04']:raise Stop('Unsupported automatic Zeek installation platform')
    url='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_'+release['VERSION_ID']+'/'
    print('Installing Zeek 8.0.10 once; enable Kaggle Internet for this dependency step.',flush=True)
    try:
        with urllib.request.urlopen(url+'Release.key',timeout=60) as r:key=r.read(1024**2)
    except Exception as error:raise Stop('Could not download the official key; enable Kaggle Internet. '+str(error))
    if b'BEGIN PGP PUBLIC KEY BLOCK' not in key:raise Stop('Invalid repository signing-key response')
    kp=Path('/etc/apt/keyrings/p3_zeek.asc');kp.parent.mkdir(exist_ok=True);kp.write_bytes(key);kp.chmod(0o644)
    Path('/etc/apt/sources.list.d/p3-zeek.list').write_text(f'deb [signed-by={kp}] {url} /\n')
    def command(args,name,timeout):
        with open(OUT/name,'w') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
        if r.returncode:raise Stop('Dependency step failed; see '+name)
    command(['apt-get','-o','Acquire::Retries=2','-o','Acquire::http::Timeout=40','-o','Acquire::https::Timeout=40','update'],'zeek_apt_update.txt',600)
    r=subprocess.run(['apt-cache','madison','zeek-8.0'],capture_output=True,text=True,timeout=30)
    versions=[x.split('|')[1].strip() for x in r.stdout.splitlines() if len(x.split('|'))>=2 and re.match(r'(?:\d+:)?8\.0\.10(?:$|[-+~])',x.split('|')[1].strip())]
    if not versions:raise Stop('Exact Zeek 8.0.10 package unavailable; no substitute installed')
    command(['apt-get','-y','--no-install-recommends','install','zeek-8.0='+versions[0]],'zeek_install.txt',900)
    p,v=find()
    if not p:raise Stop('Installed executable did not verify as Zeek 8.0.10')
    return p,v

TAP=r"""@load base/protocols/conn
redef tcp_SYN_timeout = TIMEOUT secs;
event zeek_init() { print fmt("CFG|%s", tcp_SYN_timeout); }
event new_packet(c: connection, p: pkt_hdr)
 {
 if (!p?$ip) return;
 print fmt("IP|%.6f|%s|%s|%s|%d|%d|%s", network_time(), c$uid, p$ip$src, p$ip$dst, p$ip$id, p$ip$len, get_port_transport_proto(c$id$orig_p));
 }
event Conn::log_conn(rec: Conn::Info)
 { print fmt("AV|%.6f|%s", network_time(), rec$uid); }
"""

def raw_fp(ts,b,link):
 info=ip_packet(b,link)
 if info is None:return None
 a,z,ident,length,proto,ports=info
 return ((int(ts)+500)//1000,a,z,int(ident),int(length),proto)

def event_log(path):
 ev=defaultdict(Counter);av={};config=[]
 with open(path) as f:
  for line in f:
   if line.startswith('IP|'):
    x=line.strip().split('|')
    if len(x)!=8:raise Stop('IP event schema mismatch')
    ev[(us(x[1]),x[3],x[4],int(x[5]),int(x[6]),x[7])][x[2]]+=1
   elif line.startswith('AV|'):
    x=line.strip().split('|')
    if len(x)!=3 or x[2] in av:raise Stop('Invalid/duplicate availability event')
    av[x[2]]=float(x[1])
   elif line.startswith('CFG|'):config.append(line.strip())
 return ev,av,config

def replay(binary,pcap,d,timeout):
 d.mkdir(exist_ok=False);tap=d/'tap.zeek';tap.write_text(TAP.replace('TIMEOUT',str(float(timeout))))
 cd=d/'compile';cd.mkdir()
 ck=subprocess.run([binary,'-b',str(tap.resolve())],cwd=cd,capture_output=True,text=True,timeout=30)
 (d/'compile_stderr.txt').write_text(ck.stderr)
 if ck.returncode:raise Stop('Zeek instrumentation compile failed: '+ck.stderr[-1000:])
 start=time.perf_counter();rss=0
 with (d/'events.txt').open('w') as so,(d/'stderr.txt').open('w') as se:
  proc=subprocess.Popen([binary,'-C','-r',str(pcap.resolve()),str(tap.resolve())],cwd=d,stdout=so,stderr=se)
  try:
   while proc.poll() is None:
    if time.perf_counter()-start>1800:raise Stop('Replay exceeded fixed 1800-second limit')
    try:
     status=Path(f'/proc/{proc.pid}/status').read_text();m=re.search(r'^VmRSS:\s+(\d+)\s+kB',status,re.M)
     if m:rss=max(rss,int(m.group(1)))
    except OSError:pass
    time.sleep(.05)
  finally:
   if proc.poll() is None:proc.kill()
   proc.wait()
 if proc.returncode or not (d/'conn.log').is_file():raise Stop('Replay failed; stderr retained: '+str(d))
 rows={}
 for r in logs(d/'conn.log'):
  try:v=features(r);k=record_key(r)
  except (ValueError,KeyError):continue
  if r['uid'] in rows:raise Stop('Duplicate UID in extracted records')
  rows[r['uid']]={**v,'uid':r['uid'],'ks':k,'ts':float(r['ts'])}
 ev,av,config=event_log(d/'events.txt')
 if not ev or not set(rows).issubset(av):raise Stop('Packet or availability instrumentation missing')
 if len(config)!=1:raise Stop('Extractor setting not reported exactly once')
 match=re.search(r'[0-9]+(?:\.[0-9]+)?',config[0].split('|',1)[1])
 if match is None or float(match.group())!=float(timeout):raise Stop('Observed extractor timeout differs from declared setting')
 resource={'seconds':time.perf_counter()-start,'timeout_seconds':timeout,'records':len(rows),
  'sampled_Zeek_peak_RSS_KiB':rss,'memory_scope':'sampled Zeek process RSS, not total Python memory',
  'PCAP_sha256':sha(pcap),'status':'REPLAY_COMPLETE'}
 js(d.parent.parent/(d.name+'_resources.json'),resource)
 return rows,ev,av,resource

def write_trace(p,h,e,u,pack,delta=None):
 order=sorted(range(len(pack)),key=lambda i:(pack[i][0]+(int(delta[i]) if delta is not None else 0),i))
 with p.open('wb') as f:
  f.write(h)
  for i in order:
   ts,cap,wire,payload=pack[i];ts+=int(delta[i]) if delta is not None else 0
   f.write(struct.pack(e+'IIII',ts//10**9,(ts%10**9)//u,cap,wire));f.write(payload)
 return order

def reference_owners(groups,ev):
 result={};amb=0
 for fp,indices in groups.items():
  vv=ev.get(fp,{})
  if len(vv)==1 and sum(vv.values())==len(indices):
   uid=next(iter(vv));result.update({i:uid for i in indices})
  else:amb+=len(indices)
 return result,amb

def descendants(groups,ev,reference,rows):
 owners=defaultdict(set);mapped=Counter();tracked=Counter();sources=defaultdict(set);ecount=Counter()
 for fp,vv in ev.items():
  ecount.update(vv)
  if fp not in groups:
   for uid in vv:sources[uid].add('UNINDEXED')
 for fp,indices in groups.items():
  vv=ev.get(fp,{});parents={reference.get(i,'UNASSIGNED') for i in indices}
  if sum(vv.values())==len(indices) and len(parents)==1:
   parent=next(iter(parents))
   for uid,n in vv.items():
    sources[uid].add(parent)
    if parent!='UNASSIGNED':owners[parent].add(uid);mapped[parent]+=n;tracked[uid]+=n
  else:
   for uid in vv:sources[uid].add('AMBIGUOUS')
 expected=Counter(reference.values())
 pure={uid:len(sources[uid])==1 and not sources[uid]&{'UNINDEXED','UNASSIGNED','AMBIGUOUS'} and tracked[uid]==ecount[uid]==int(r['orig_pkts']+r['resp_pkts']) for uid,r in rows.items()}
 complete={p:mapped[p]==n and bool(owners[p]) and owners[p].issubset(rows) for p,n in expected.items()}
 return owners,pure,complete

def resolve_labels(path,panel):
 wanted={r['ks']:uid for uid,r in panel.items()};found={};duplicates=set();n=0
 for r in logs(path,True):
  n+=1
  if n>CFG['label_row_limit']:break
  try:k=record_key(r)
  except (ValueError,KeyError):continue
  if k not in wanted:continue
  uid=wanted[k];label=r['label'].lower()
  if label not in ['benign','malicious']:continue
  try:v=features(r)
  except (ValueError,KeyError):continue
  if v['proto']!=panel[uid]['proto'] or not np.allclose([v[c] for c in F[:-1]],[panel[uid][c] for c in F[:-1]],atol=1e-9,rtol=1e-9):continue
  if uid in found:duplicates.add(uid)
  found[uid]=int(label=='malicious')
 for uid in duplicates:found.pop(uid,None)
 return found,min(n,CFG['label_row_limit'])

def null_check(a,ava,b,avb):
 def index(rows,av):
  result={}
  for uid,r in rows.items():
   if r['ks'] in result:raise Stop('Duplicate key prevents strict null invariance test')
   result[r['ks']]=([r[c] for c in F[:-1]],r['proto'],av[uid])
  return result
 left=index(a,ava);right=index(b,avb)
 if set(left)!=set(right):raise Stop('Null replay changed record population')
 for k,x in left.items():
  y=right[k]
  if x[1]!=y[1] or not np.allclose(x[0],y[0],atol=1e-9,rtol=1e-9) or not np.isclose(x[2],y[2],atol=1e-6,rtol=0):raise Stop('Null replay changed features or record availability')
 return {'status':'NULL_INVARIANCE_PASSED','records':len(left)}

def decision_bounds(keys,st,alarm,deadline):
 owners,pure,complete=st['owners'],st['pure'],st['complete'];av=st['available'];result={}
 for k in keys:
  seen=[uid for uid in owners.get(k,()) if alarm.get(uid,False) and uid in av and av[uid]<=deadline[k]]
  witness=any(pure.get(uid,False) for uid in seen)
  result[k]=(1,1) if witness else ((0,0) if complete.get(k,False) and not seen else (0,1))
 return result

def scores(st,prob,begin,end,source_rate):
 use=[uid for uid,r in st['rows'].items() if begin<=r['ts']<end and uid in st['available'] and st['available'][uid]<=end]
 if not use:return {'low_confidence':0.,'boundary_pressure':0.,'traffic_load':0.,'positive_rate_shift':0.,'available_records':0}
 tcp=[st['rows'][uid] for uid in use if st['rows'][uid]['proto']=='tcp']
 return {'low_confidence':float(np.mean([1-max(prob[uid],1-prob[uid]) for uid in use])),
  'boundary_pressure':float(np.mean([r['orig_pkts']+r['resp_pkts']<=1 for r in tcp])) if tcp else 0.,
  'traffic_load':float(np.log1p(len(use))/(end-begin)),
  'positive_rate_shift':float(abs(np.mean([prob[uid]>=.5 for uid in use])-source_rate)),
  'available_records':len(use)}

def one_capture(capture,models,rates,binary):
 d=OUT/f'capture_{capture}';d.mkdir();scratch=d/'scratch';scratch.mkdir()
 cr={'capture':capture,'status':'STARTED'};unitrows=[];winrows=[]
 try:
  scenario=f'CTU-IoT-Malware-Capture-{capture}-1'
  pcaps=[p for p in RAW.rglob('*.pcap') if scenario in p.parts]
  labels=[p for p in RAW.rglob('conn.log.labeled') if scenario in p.parts]
  if not pcaps or len(labels)!=1:raise Stop('Original PCAP or unique primary-labelled log unavailable')
  raw=max(pcaps,key=lambda p:p.stat().st_size);h,e,u,link=header(raw)
  pack=[];groups0=defaultdict(list);size=24
  for i,ts,cap,wire,b,off in packets(raw):
   if size+16+cap>CFG['prefix_MiB']*1024**2 or len(pack)>=CFG['max_packets']:break
   idx=len(pack);pack.append((ts,cap,wire,b));size+=16+cap;fp=raw_fp(ts,b,link)
   if fp is not None:groups0[fp].append(idx)
  if not pack:raise Stop('Empty fixed prefix')
  origin=min(r[0] for r in pack)/1e9;end=max(r[0] for r in pack)/1e9
  if end-origin<=CFG['tail_seconds']+CFG['window_seconds']:raise Stop('Too short a time span in fixed prefix; no budget expanded')
  clean=scratch/'clean.pcap';write_trace(clean,h,e,u,pack)
  js(d/'raw_identity.json',{'source_path':str(raw),'prefix_sha256':sha(clean),'prefix_bytes':size,'prefix_packets':len(pack),'span_seconds':end-origin})
  rows0,ev0,av0,res0=replay(binary,clean,scratch/'delay0_timeout5',5)
  if capture==CFG['captures'][0]:
   rn,en,an,_=replay(binary,clean,scratch/'null_repeat_timeout5',5)
   js(d/'null_invariance.json',null_check(rows0,av0,rn,an))
   del rn,en,an;shutil.rmtree(scratch/'null_repeat_timeout5')
  reference,amb=reference_owners(groups0,ev0);counts=Counter(reference.values());first={}
  for idx,k in sorted(reference.items()):first.setdefault(k,idx)
  eligible={k for k,n in counts.items() if k in rows0 and rows0[k]['proto']=='tcp' and n>=2 and n==int(rows0[k]['orig_pkts']+rows0[k]['resp_pkts'])}
  candidates={k:r for k,r in rows0.items() if k in counts and 0<counts[k]<=64 and counts[k]==int(r['orig_pkts']+r['resp_pkts']) and r['proto'] in ['tcp','udp'] and r['ts']<end-CFG['tail_seconds']}
  ks=[k for k in sorted(candidates,key=lambda k:candidates[k]['ks'])[:CFG['reference_units']]]
  panel={k:candidates[k] for k in ks}
  if len(ks)<64:raise Stop('Fewer than 64 fully mapped supported reference units')
  pd.DataFrame(panel.values()).to_csv(d/'panel_before_labels.csv.gz',index=False,compression='gzip')
  pd.DataFrame({'packet_index':list(reference),'reference_uid':list(reference.values())}).to_csv(d/'reference_packet_UIDs.csv.gz',index=False,compression='gzip')
  truth,scanned=resolve_labels(labels[0],panel)
  js(d/'label_linkage.json',{'panel_units':len(ks),'matched_labels':len(truth),'benign':sum(y==0 for y in truth.values()),'malicious':sum(y==1 for y in truth.values()),'rows_scanned':scanned,'unmatched':len(ks)-len(truth)})
  for delay in CFG['conditions_seconds']:
   delta=np.zeros(len(pack),dtype=np.int64)
   if delay:
    for idx,k in reference.items():
     if k in eligible and idx!=first[k]:delta[idx]=delay*10**9
   times=np.array([r[0] for r in pack],dtype=np.int64)+delta;groups=defaultdict(list)
   for fp,indices in groups0.items():
    for idx in indices:groups[((int(times[idx])+500)//1000,*fp[1:])].append(idx)
   trace=clean if delay==0 else scratch/f'paced{delay}.pcap'
   if delay:write_trace(trace,h,e,u,pack,delta)
   states={}
   for timeout in CFG['timeouts_seconds']:
    print('REPLAY capture',capture,'condition',delay,'timeout',timeout,flush=True)
    if delay==0 and timeout==5:rr,ee,aa,resource=rows0,ev0,av0,res0
    else:rr,ee,aa,resource=replay(binary,trace,scratch/f'delay{delay}_timeout{timeout}',timeout)
    owners,pure,complete=descendants(groups,ee,reference,rr)
    states[timeout]={'rows':rr,'available':aa,'owners':owners,'pure':pure,'complete':complete}
    js(d/f'accounting_delay{delay}_timeout{timeout}.json',{'panel_units':len(ks),'complete_memberships':sum(complete.get(k,False) for k in ks),'pure_UIDs':sum(pure.values()),'PCAP_sha256':resource['PCAP_sha256']})
    if timeout!=5:del ee
   wi={k:int((times[first[k]]/1e9-origin)//CFG['window_seconds']) for k in ks}
   deadline={k:origin+(wi[k]+1)*CFG['window_seconds']+CFG['grace_seconds'] for k in ks}
   valid=[k for k in ks if deadline[k]<=end-CFG['tail_seconds']+CFG['grace_seconds']]
   for family,model in models.items():
    probs={};bounds={}
    with threadpool_limits(limits=2):
     for timeout,st in states.items():
      frame=pd.DataFrame(st['rows'].values())
      if frame.empty:raise Stop('No compatible records')
      p=model.predict_proba(encode(frame))[:,1]
      if not np.isfinite(p).all():raise Stop('Nonfinite model output')
      probs[timeout]=dict(zip(frame.uid,p));alarm={uid:v>=.5 for uid,v in probs[timeout].items()}
      bounds[timeout]=decision_bounds(valid,st,alarm,deadline)
    local=[]
    for k in valid:
     a,b=bounds[5][k],bounds[15][k];y=truth.get(k)
     wrong=bool(y is not None and a[0]==a[1] and a[0]!=y)
     helpful=bool(wrong and b[0]==b[1] and b[0]==y)
     harmful=bool(y is not None and a[0]==a[1] and a[0]==y and b[0]==b[1] and b[0]!=y)
     local.append({'capture':capture,'condition_seconds':delay,'family':family,'ks':panel[k]['ks'],'window':wi[k],
      'label':y,'default_lower':a[0],'default_upper':a[1],'alternate_lower':b[0],'alternate_upper':b[1],
      'definite_flip':a[0]==a[1] and b[0]==b[1] and a[0]!=b[0],
      'default_definite_error':wrong,'helpful_disagreement':helpful,'harmful_alternate_switch':harmful})
    unitrows.extend(local);df=pd.DataFrame(local)
    if df.empty:continue
    for window,g in df.groupby('window',sort=True):
     begin=origin+int(window)*CFG['window_seconds'];finish=begin+CFG['window_seconds']
     sc=scores(states[5],probs[5],begin,finish,rates[family])
     winrows.append({'capture':capture,'condition_seconds':delay,'family':family,'window':int(window),
      'units':len(g),'labelled_units':int(g.label.notna().sum()),'benign_units':int(g.label.eq(0).sum()),'malicious_units':int(g.label.eq(1).sum()),
      'disagreement':int(g.definite_flip.sum()),'default_definite_errors':int(g.default_definite_error.sum()),
      'helpful_units':int(g.helpful_disagreement.sum()),'harmful_alternate_units':int(g.harmful_alternate_switch.sum()),
      'unresolved_default_units':int(g.default_lower.ne(g.default_upper).sum()),'unresolved_alternate_units':int(g.alternate_lower.ne(g.alternate_upper).sum()),**sc})
    print('RESULT capture',capture,'condition',delay,'family',family,'units',len(df),'flips',int(df.definite_flip.sum()),'helpful',int(df.helpful_disagreement.sum()),flush=True)
   pd.DataFrame(unitrows).to_csv(d/'experiment1_units.csv.gz',index=False,compression='gzip')
   pd.DataFrame(winrows).to_csv(d/'experiment2_windows.csv',index=False)
   js(d/'condition_progress.json',{'completed_condition':delay,'unit_rows':len(unitrows),'window_rows':len(winrows),'capture_not_yet_complete':True})
   checkpoint();del states;gc.collect()
   if delay:trace.unlink()
   for rd in scratch.glob(f'delay{delay}_timeout*'):
    if rd.is_dir() and not (delay==0 and rd.name=='delay0_timeout5'):shutil.rmtree(rd)
  cr.update({'status':'CAPTURE_PILOT_COMPLETE','panel_units':len(ks),'matched_labels':len(truth),
   'eligible_TCP_reference_units':len(eligible),'ambiguous_clean_packet_occurrences':amb})
  shutil.rmtree(scratch);cr['only_this_run_scratch_removed']=True
 except Exception as e:
  cr.update({'status':'BLOCKED_OR_FAILED','reason':str(e)});(d/'error.txt').write_text(traceback.format_exc())
  print('CAPTURE',capture,'STOPPED:',e,flush=True)
 finally:js(d/'receipt.json',cr)
 return unitrows,winrows,cr


def policy_results(windows):
 wf=pd.DataFrame(windows);rows=[];rng=np.random.default_rng(CFG['seed'])
 def measure(g,idx,probe):
  selected=g.index.isin(set(idx));warning=selected & g.disagreement.gt(0).to_numpy() if probe else selected
  harmful=g.default_definite_errors.gt(0).to_numpy()
  return {'checks':int(selected.sum()) if probe else 0,'selected_windows':int(selected.sum()),'warnings':int(warning.sum()),
   'harmful_windows':int(harmful.sum()),'harmful_windows_warned':int((warning&harmful).sum()),
   'harmful_windows_unwarned':int((~warning&harmful).sum()),
   'warnings_without_definite_error':int((warning&~harmful).sum()),
   'helpful_units_exposed':int(g.loc[warning,'helpful_units'].sum())}
 for (capture,condition,family),g in wf.groupby(['capture','condition_seconds','family'],sort=True):
  for budget in CFG['policy_budgets']:
   n=max(1,int(math.floor(budget*len(g))));base={'capture':capture,'condition_seconds':condition,'family':family,'budget_fraction':budget,'total_windows':len(g),'requested_windows':n}
   for name in ['low_confidence','boundary_pressure','traffic_load','positive_rate_shift']:
    idx=g.sort_values([name,'window'],ascending=[False,True],kind='stable').index[:n]
    rows.append({**base,'policy':name.upper(),'repetition':0,**measure(g,idx,True)})
    rows.append({**base,'policy':name.upper()+'_PASSIVE_ESCALATION','repetition':0,**measure(g,idx,False)})
   for rep in range(CFG['random_schedules']):
    idx=rng.choice(g.index.to_numpy(),n,replace=False)
    rows.append({**base,'policy':'RANDOM','repetition':rep,**measure(g,idx,True)})
 pf=pd.DataFrame(rows);pf.to_csv(OUT/'experiment3_equal_check_policies.csv',index=False)
 summary=pf.groupby(['capture','condition_seconds','family','budget_fraction','policy'],as_index=False).agg(
  simulations=('repetition','size'),checks=('checks','mean'),warnings=('warnings','mean'),
  harmful_windows_warned=('harmful_windows_warned','mean'),harmful_windows_unwarned=('harmful_windows_unwarned','mean'),
  helpful_units_exposed=('helpful_units_exposed','mean'),warnings_without_definite_error=('warnings_without_definite_error','mean'))
 summary.to_csv(OUT/'experiment3_policy_summary.csv',index=False)
 totals=wf.groupby(['capture','condition_seconds','family'],as_index=False).agg(windows=('window','size'),
  labelled_units=('labelled_units','sum'),benign_units=('benign_units','sum'),malicious_units=('malicious_units','sum'),
  default_errors=('default_definite_errors','sum'),helpful_units=('helpful_units','sum'),
  definite_flips=('disagreement','sum'),harmful_alternate_units=('harmful_alternate_units','sum'))
 totals.to_csv(OUT/'DECISION_INFORMATION_TABLE.csv',index=False)
 return totals,summary

def main():
 if not RAW.is_dir():raise Stop('Original IoT-23 raw mount is absent: '+str(RAW))
 if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free required. No files deleted to make room.')
 js(OUT/'PRE_OUTCOME_PROTOCOL.json',{'config':CFG,'new_model_fits':0,
  'model_policy':'Recover exact controlled five-seed bank; use GROUP_DISJOINT HGB/LR seed 8101. Never silently replace or retrain.',
  'panels':'Fresh fixed-prefix exposed-data pilot; lowest key SHA256 among complete clean units before labels or predictions.',
  'labels':'Strict published primary labels and stable-feature linkage; unmatched labels not invented.',
  'stress':'10s after first packet of fully mapped TCP units, without label targeting. Offline diagnostic, not host/functionality validation.',
  'same_traffic_comparison':'Same packet population and frozen detector under 5s and 15s SYN timeout.',
  'runtime_information':'Only default records available by window end enter selection scores; target labels score results only.',
  'budget_scope':'Retrospective full-capture label-free ranking; not a causal scheduler, bounded-buffer implementation or online speedup.',
  'positive_rate_baseline':'absolute source-calibration predicted-positive rate change; not published MD3',
  'independent_confirmation':False,'novelty_established':False})
 models,rates=recover_frozen_bank();REPORT['input_recovery']='VERIFIED';js(OUT/'receipt.json',REPORT)
 print('Checkpointing the restored bank, matching source panel, protocol and source BEFORE replays.',flush=True)
 REPORT['input_checkpoint']=checkpoint();js(OUT/'receipt.json',REPORT)
 # Installation is local to the user-run Kaggle runtime, only if the exact version is absent.
 if CFG['auto_install_exact_zeek']:
  binary,version=ensure_zeek()
 else:
  binary=None;version=None
  for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
   if not p or not Path(p).is_file():continue
   ck=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30)
   text=(ck.stdout+ck.stderr).strip()
   if ck.returncode==0 and re.search(r'(?<![\d.])8\.0\.10(?![\d.])',text):binary,version=p,text;break
  if binary is None:raise Stop('Exact Zeek 8.0.10 missing; automatic installation disabled')
 js(OUT/'environment.json',{'zeek':version,'binary':binary,'free_GiB':shutil.disk_usage(W).free/1024**3})
 all_units=[];all_windows=[];statuses=[]
 for capture in CFG['captures']:
  units,windows,status=one_capture(capture,models,rates,binary);statuses.append(status)
  # Partial outputs are retained inside their capture directory but never enter pooled conclusions.
  if status['status']=='CAPTURE_PILOT_COMPLETE':all_units.extend(units);all_windows.extend(windows)
  pd.DataFrame(all_units).to_csv(OUT/'experiment1_unit_decisions.csv.gz',index=False,compression='gzip')
  pd.DataFrame(all_windows).to_csv(OUT/'experiment2_window_information.csv',index=False)
  js(OUT/'capture_progress.json',statuses);REPORT['capture_progress']=statuses;js(OUT/'receipt.json',REPORT);checkpoint();gc.collect()
 if not all_windows:raise Stop('No completed evaluable capture windows; read capture_progress.json and capture error files.')
 totals,summary=policy_results(all_windows);primary=totals[totals.family.eq('HGB')]
 informative=sorted(primary.loc[primary.helpful_units.ge(CFG['minimum_helpful_units']),'capture'].unique().tolist())
 if any(r['status']!='CAPTURE_PILOT_COMPLETE' for r in statuses):decision='INCOMPLETE_EXECUTION_NO_SCIENTIFIC_DECISION'
 elif primary.labelled_units.sum()==0:decision='INSUFFICIENT_LABEL_LINKAGE'
 elif primary.default_errors.sum()<CFG['minimum_helpful_units']:decision='INSUFFICIENT_DEFAULT_ERRORS_TO_TEST_ERROR_DISCOVERY'
 elif primary.helpful_units.sum()==0:decision='NO_HELPFUL_REMEASUREMENT_OBSERVED_IN_DECLARED_PILOT'
 elif len(informative)<CFG['minimum_informative_captures']:decision='LOCAL_SIGNAL_ONLY_NOT_ENOUGH_TO_BUILD_SCHEDULER'
 else:decision='INFORMATION_GATE_PASSED_TEST_CAUSAL_IMPLEMENTATION_NEXT'
 REPORT.update({'status':'PILOT_FINISHED','scientific_decision':decision,'informative_captures_primary_HGB':informative,
  'capture_progress':statuses,'online_scheduler_validated':False,'online_speedup_measured':False,
  'novelty_established':False,'independent_confirmation':False,
  'limits':['Alternative answers are not ground truth; harmful alternative switches are reported.',
   'No application-functionality or host-realizable evasion claim.',
   'Fresh bounded-prefix/key-ranked panels do not reproduce earlier whole-capture or 512-per-class results.',
   'Few default errors or missing labels is an inconclusive test, not proof the idea is impossible.',
   'Equal check counts are not equal measured CPU costs; per-window on-demand cost is not measured.',
   'Primary gate is an engineering feasibility screen, not a significance or publication test.']})
 js(OUT/'receipt.json',REPORT)
 print('\nEXPERIMENTS 1/2 — INFORMATION TABLE\n'+totals.to_string(index=False),flush=True)
 print('\nEXPERIMENT 3 — CHECK BUDGET 25%\n'+summary[summary.budget_fraction.eq(.25)].to_string(index=False),flush=True)

try:
 source=globals().get('__file__')
 if source and Path(source).is_file():shutil.copyfile(source,OUT/'executed_pilot.py')
 main()
except Exception as e:
 REPORT.update({'status':'STOPPED_WITH_EXACT_REASON','reason':str(e),'scientific_decision':'NOT_ESTABLISHED'})
 (OUT/'error.txt').write_text(traceback.format_exc());print('\nSTOPPED:',e,flush=True)
finally:
 js(OUT/'receipt.json',REPORT)
 try:
  cp=checkpoint();REPORT['final_checkpoint']=cp;js(OUT/'receipt.json',REPORT)
  print('\nPRIVATE CHECKPOINT:',cp['path'],flush=True)
 except Exception as e:REPORT['checkpoint_error']=str(e);js(OUT/'receipt.json',REPORT)
 print('\nPILOT RECEIPT\n'+json.dumps(REPORT,indent=2),flush=True)
