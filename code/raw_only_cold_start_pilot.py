# RAW-ONLY COLD-START PILOT. No previous models, source panels, ZIPs, or history.
from pathlib import Path
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from collections import defaultdict,Counter
import ast,gc,gzip,hashlib,heapq,io,json,math,os,platform,re,shutil,socket,struct,subprocess,sys,time,traceback,urllib.request,warnings,zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
OUT=W/('RAW_ONLY_REMEASUREMENT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
CFG={'source_captures':[1,3,8],'target_captures':[34,49,7],
 'source_per_class_per_capture':2000,'source_log_row_limit':4000000,
 'target_prefix_MiB':64,'target_max_packets':1500000,'target_panel_units':2048,
 'target_label_row_limit':4000000,'delays_seconds':[0,10],'timeouts_seconds':[5,15],
 'window_seconds':60,'grace_seconds':30,'tail_seconds':120,
 'model_seed':8101,'split_seed':94701,'ranking_seed':99101,
 'budgets':[.1,.25,.5,1.],'random_schedules':100,
 'minimum_helpful_units_per_capture':20,'minimum_informative_captures':2}
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
class Stop(Exception):pass
R={'status':'STARTED','new_model_fits':0,'new_PCAP_replays':0,'old_artifacts_read':False,
 'historical_models_reproduced':False,'scientific_decision':'NOT_ESTABLISHED','output_directory':str(OUT)}

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


def checkpoint():
 p=OUT/'PRIVATE_raw_only_checkpoint.zip';tmp=OUT/'checkpoint.tmp';manifest=[]
 with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
  for q in sorted(OUT.rglob('*')):
   if not q.is_file() or q in [p,tmp] or 'scratch' in q.relative_to(OUT).parts or q.suffix=='.zip':continue
   if q.stat().st_size>64*1024**2:continue
   name=str(q.relative_to(OUT));z.write(q,name);manifest.append({'member':name,'bytes':q.stat().st_size,'sha256':sha(q)})
  z.writestr('CHECKPOINT_MANIFEST.json',json.dumps(manifest,indent=2))
 with zipfile.ZipFile(tmp) as z:
  if z.testzip():raise Stop('Checkpoint CRC failed')
 tmp.replace(p);return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p),'members':len(manifest)}

def setup_zeek():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
  if p and Path(p).is_file():
   q=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30)
   text=(q.stdout+q.stderr).strip()
   if q.returncode==0 and re.search(r'\bversion\s+[89]\.',text):return p,text
 if os.geteuid()!=0:raise Stop('Zeek missing and package installation needs root. No experiment has run.')
 release={}
 for line in Path('/etc/os-release').read_text().splitlines():
  if '=' in line:
   k,v=line.split('=',1);release[k]=v.strip('"')
 if release.get('ID')!='ubuntu':raise Stop('Automatic Zeek setup supports Ubuntu only: '+str(release))
 version=release['VERSION_ID']
 url=f'https://download.opensuse.org/repositories/security:/zeek/xUbuntu_{version}/'
 print('DEPENDENCY: installing Zeek for Ubuntu',version,'— Kaggle Internet must be ON.',flush=True)
 try:
  with urllib.request.urlopen(url+'Release.key',timeout=60) as f:key=f.read(1024**2)
 except Exception as e:raise Stop('Zeek download failed. Enable Kaggle Internet and rerun this same cell. '+str(e))
 if b'BEGIN PGP PUBLIC KEY BLOCK' not in key:raise Stop('Repository returned an invalid signing key')
 kp=Path('/etc/apt/keyrings/raw-pilot-zeek.asc');kp.parent.mkdir(exist_ok=True);kp.write_bytes(key);kp.chmod(0o644)
 Path('/etc/apt/sources.list.d/raw-pilot-zeek.list').write_text(f'deb [signed-by={kp}] {url} /\n')
 def command(args,name,timeout):
  with (OUT/name).open('w') as f:q=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
  if q.returncode:raise Stop('Dependency command failed; see '+name)
 command(['apt-get','-o','Acquire::Retries=2','-o','Acquire::http::Timeout=40','-o','Acquire::https::Timeout=40','update'],'apt_update.txt',600)
 # New study, not historical reproduction: resolve and record one available 8.0 build.
 q=subprocess.run(['apt-cache','madison','zeek-8.0'],capture_output=True,text=True,timeout=30)
 available=[s.split('|')[1].strip() for s in q.stdout.splitlines() if len(s.split('|'))>=2]
 if not available:raise Stop('Official repository has no zeek-8.0 package for this Ubuntu release. No unverified executable downloaded.')
 package=available[0];js(OUT/'dependency_install.json',{'package':'zeek-8.0','package_version':package,'repository':url,'new_study_not_old_version_reproduction':True})
 command(['apt-get','-y','--no-install-recommends','-o','Acquire::Retries=2','install','zeek-8.0='+package],'apt_install.txt',900)
 for p in ['/opt/zeek/bin/zeek',shutil.which('zeek')]:
  if p and Path(p).is_file():
   q=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30)
   if q.returncode==0:return p,(q.stdout+q.stderr).strip()
 raise Stop('Installed Zeek executable not found')

def scenario_assets(cap,need_pcap=True):
 token=f'CTU-IoT-Malware-Capture-{cap}-1'
 labels=[p for p in RAW.rglob('conn.log.labeled') if token in p.parts]
 if len(labels)!=1:raise Stop('Expected exactly one published log for '+token+'; found '+str(len(labels)))
 pcaps=[p for p in RAW.rglob('*.pcap') if token in p.parts] if need_pcap else []
 if need_pcap and not pcaps:raise Stop('Original classic PCAP missing for '+token)
 return (max(pcaps,key=lambda p:p.stat().st_size) if pcaps else None),labels[0]

class RankedSample:
 def __init__(self,n):self.n=n;self.heap=[];self.keys=set()
 def add(self,key,row):
  if key in self.keys:return
  rank=int(key,16)
  if len(self.heap)<self.n:heapq.heappush(self.heap,(-rank,key,row));self.keys.add(key)
  elif rank<-self.heap[0][0]:
   _,old,_=heapq.heapreplace(self.heap,(-rank,key,row));self.keys.remove(old);self.keys.add(key)
 def values(self):return [x[2] for x in sorted(self.heap,key=lambda x:x[1])]

def train_from_raw_logs():
 rows=[];audit=[]
 for cap in CFG['source_captures']:
  _,path=scenario_assets(cap,False);samples={y:RankedSample(CFG['source_per_class_per_capture']) for y in [0,1]};seen=Counter();scanned=0
  for raw in logs(path,True):
   scanned+=1
   if scanned%250000==0:print('SOURCE',cap,'published rows scanned:',scanned,flush=True)
   if scanned>CFG['source_log_row_limit']:break
   label=raw['label'].lower()
   if label not in ['benign','malicious']:continue
   try:
    v=features(raw);key=record_key(raw)
    endpoints=sorted([(raw['id.orig_h'],int(raw['id.orig_p'])),(raw['id.resp_h'],int(raw['id.resp_p']))])
   except (ValueError,KeyError):continue
   y=int(label=='malicious');group=hashlib.sha256(json.dumps([cap,endpoints,raw['proto'].lower()],separators=(',',':')).encode()).hexdigest()
   row={**v,'ks':key,'y':y,'source_capture':cap,'group':group};samples[y].add(key,row);seen[y]+=1
  for y in [0,1]:
   part=samples[y].values()
   if len(part)<100:raise Stop(f'Source capture {cap}, class {y}: fewer than 100 valid records within fixed scan. No alternate source chosen.')
   rows.extend(part)
  audit.append({'capture':cap,'published_log':str(path),'rows_scanned':min(scanned,CFG['source_log_row_limit']),
   'valid_benign_seen':seen[0],'valid_malicious_seen':seen[1],
   'sample_benign':len(samples[0].heap),'sample_malicious':len(samples[1].heap)})
  print('SOURCE',cap,'sampled',len(samples[0].heap),'benign +',len(samples[1].heap),'malicious',flush=True)
 source=pd.DataFrame(rows).sort_values(['source_capture','ks'],kind='stable').reset_index(drop=True)
 if source.duplicated(['source_capture','ks']).any():raise Stop('Duplicate source sample keys')
 train,val=next(GroupShuffleSplit(n_splits=1,test_size=.2,random_state=CFG['split_seed']).split(source,source.y,source.group))
 if set(source.iloc[train].group)&set(source.iloc[val].group):raise Stop('Source group overlap')
 if set(source.iloc[train].y)!={0,1} or set(source.iloc[val].y)!={0,1}:raise Stop('Fixed grouped split has a single class. No hidden split search.')
 source['role']='train';source.loc[val,'role']='source_holdout';source.to_csv(OUT/'fresh_source_panel.csv.gz',index=False,compression='gzip')
 pd.DataFrame(audit).to_csv(OUT/'source_sampling.csv',index=False)
 js(OUT/'source_training_protocol.json',{'new_training':True,'historical_model_reproduction':False,
  'source_captures':CFG['source_captures'],'selection':'fixed key-hash ranked within source capture/class',
  'group':'source capture + unordered endpoint/port pair + protocol','group_holdout_fraction':.2,
  'split_seed':CFG['split_seed'],'feature_encoding':'log1p nonnegative numeric features + protocol indicators',
  'target_records_used_for_training_or_selection':False,
  'source_feature_provenance':'published labelled connection logs, stable-core schema; not publisher-extractor reproduction',
  'HGB':{'max_iter':150,'learning_rate':.08,'early_stopping':False},
  'LR':{'C':1.,'max_iter':3000,'solver':'lbfgs','source_fitted_scaler':True},
  'record_decision_threshold':.5,'this_split_is_not_capture_holdout_confirmation':True})
 models={};rates={};metrics=[]
 with threadpool_limits(limits=2):
  for family in ['HGB','LR']:
   model=HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=CFG['model_seed']) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,max_iter=3000,solver='lbfgs',random_state=CFG['model_seed']))])
   from sklearn.exceptions import ConvergenceWarning
   with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter('always',ConvergenceWarning);model.fit(encode(source.iloc[train]),source.iloc[train].y)
   if any(issubclass(x.category,ConvergenceWarning) for x in caught):raise Stop('Fixed '+family+' model failed to converge; no target-based tuning')
   R['new_model_fits']+=1;p=model.predict_proba(encode(source.iloc[val]))[:,1];y=source.iloc[val].y.to_numpy();pred=p>=.5
   rates[family]=float(pred.mean());models[family]=model
   metrics.append({'family':family,'train_rows':len(train),'source_holdout_rows':len(val),'accuracy':accuracy_score(y,pred),
    'balanced_accuracy':balanced_accuracy_score(y,pred),'AUROC':roc_auc_score(y,p),'malicious_recall':pred[y==1].mean(),'benign_FPR':pred[y==0].mean()})
   joblib.dump(model,OUT/('fresh_'+family+'.joblib'),compress=3)
   print('NEW SOURCE-ONLY MODEL READY:',family,flush=True)
 pd.DataFrame(metrics).to_csv(OUT/'source_holdout_metrics.csv',index=False)
 js(OUT/'model_binding.json',{'fresh_models':True,'training_target_overlap':False,'source_positive_rates':rates,
  'model_sha256':{f:sha(OUT/('fresh_'+f+'.joblib')) for f in models},'source_panel_sha256':sha(OUT/'fresh_source_panel.csv.gz')})
 print('\nSOURCE HOLDOUT\n'+pd.DataFrame(metrics).to_string(index=False),flush=True)
 return models,rates

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

def read_events(path):
 ev=defaultdict(Counter);av={};settings=[]
 with path.open() as f:
  for line in f:
   if line.startswith('IP|'):
    x=line.strip().split('|')
    if len(x)!=8:raise Stop('Packet instrumentation schema mismatch')
    ev[(us(x[1]),x[3],x[4],int(x[5]),int(x[6]),x[7])][x[2]]+=1
   elif line.startswith('AV|'):
    x=line.strip().split('|')
    if len(x)!=3 or x[2] in av:raise Stop('Invalid/duplicate availability event')
    av[x[2]]=float(x[1])
   elif line.startswith('CFG|'):settings.append(line.strip())
 return ev,av,settings

def replay(binary,pcap,d,timeout):
 d.mkdir();script=d/'tap.zeek';script.write_text(TAP.replace('TIMEOUT',str(float(timeout))))
 cd=d/'compile';cd.mkdir();q=subprocess.run([binary,'-b',str(script.resolve())],cwd=cd,capture_output=True,text=True,timeout=30)
 (d/'compile_stderr.txt').write_text(q.stderr)
 if q.returncode:raise Stop('Zeek script compile failed: '+q.stderr[-1500:])
 start=time.perf_counter();rss=0;R['new_PCAP_replays']+=1
 with (d/'events.txt').open('w') as so,(d/'stderr.txt').open('w') as se:
  p=subprocess.Popen([binary,'-C','-r',str(pcap.resolve()),str(script.resolve())],cwd=d,stdout=so,stderr=se)
  try:
   while p.poll() is None:
    if time.perf_counter()-start>1800:raise Stop('Replay exceeded fixed 1800-second limit')
    try:
     m=re.search(r'^VmRSS:\s+(\d+)\s+kB',Path(f'/proc/{p.pid}/status').read_text(),re.M)
     if m:rss=max(rss,int(m.group(1)))
    except OSError:pass
    time.sleep(.05)
  finally:
   if p.poll() is None:p.kill()
   p.wait()
 if p.returncode or not (d/'conn.log').is_file():raise Stop('Zeek replay failed; see '+str(d/'stderr.txt'))
 rows={}
 for r in logs(d/'conn.log'):
  try:v=features(r);k=record_key(r)
  except (ValueError,KeyError):continue
  if r['uid'] in rows:raise Stop('Repeated connection UID')
  rows[r['uid']]={**v,'uid':r['uid'],'ks':k,'ts':float(r['ts'])}
 ev,av,settings=read_events(d/'events.txt')
 if not ev or not set(rows).issubset(av):raise Stop('Packet or availability events missing')
 if len(settings)!=1:raise Stop('Configuration setting not reported exactly once')
 m=re.search(r'[0-9]+(?:\.[0-9]+)?',settings[0].split('|',1)[1])
 if not m or float(m.group())!=float(timeout):raise Stop('Extracted timeout differs from declared setting')
 resource={'status':'REPLAY_COMPLETE','seconds':time.perf_counter()-start,'timeout_seconds':timeout,
  'PCAP_sha256':sha(pcap),'sampled_Zeek_peak_RSS_KiB':rss,'RSS_scope':'sampled Zeek process, not full Python pilot','records':len(rows)}
 js(d.parent.parent/(d.name+'_resources.json'),resource)
 return rows,ev,av,resource

def fp(ts,payload,link):
 q=ip_packet(payload,link)
 if q is None:return None
 src,dst,ident,length,proto,ports=q
 return ((int(ts)+500)//1000,src,dst,int(ident),int(length),proto)
def write_trace(path,h,e,u,pack,delta=None):
 order=sorted(range(len(pack)),key=lambda i:(pack[i][0]+(int(delta[i]) if delta is not None else 0),i))
 with path.open('wb') as f:
  f.write(h)
  for i in order:
   ts,cap,wire,payload=pack[i];ts+=int(delta[i]) if delta is not None else 0
   f.write(struct.pack(e+'IIII',ts//10**9,(ts%10**9)//u,cap,wire));f.write(payload)
 return order

def reference_map(groups,events):
 result={};amb=0
 for key,indices in groups.items():
  vv=events.get(key,{})
  if len(vv)==1 and sum(vv.values())==len(indices):result.update({i:next(iter(vv)) for i in indices})
  else:amb+=len(indices)
 return result,amb

def map_condition(groups,events,reference,rows):
 owners=defaultdict(set);mapped=Counter();tracked=Counter();sources=defaultdict(set);ecount=Counter()
 for key,vv in events.items():
  ecount.update(vv)
  if key not in groups:
   for u in vv:sources[u].add('UNINDEXED')
 for key,indices in groups.items():
  vv=events.get(key,{});parent={reference.get(i,'UNASSIGNED') for i in indices}
  if sum(vv.values())==len(indices) and len(parent)==1:
   k=next(iter(parent))
   for u,n in vv.items():
    sources[u].add(k)
    if k!='UNASSIGNED':owners[k].add(u);mapped[k]+=n;tracked[u]+=n
  else:
   for u in vv:sources[u].add('AMBIGUOUS')
 pure={u:len(sources[u])==1 and not sources[u]&{'UNINDEXED','UNASSIGNED','AMBIGUOUS'} and tracked[u]==ecount[u]==int(r['orig_pkts']+r['resp_pkts']) for u,r in rows.items()}
 counts=Counter(reference.values());complete={k:mapped[k]==n and bool(owners[k]) and owners[k].issubset(rows) for k,n in counts.items()}
 return owners,pure,complete

def null_check(left,avleft,right,avright):
 def index(rows,av):
  result={}
  for uid,r in rows.items():
   if r['ks'] in result:raise Stop('Duplicate key prevents strict null-control comparison')
   result[r['ks']]=([r[c] for c in F[:-1]],r['proto'],av[uid])
  return result
 a=index(left,avleft);b=index(right,avright)
 if set(a)!=set(b):raise Stop('Null control changed record keys')
 for k,x in a.items():
  z=b[k]
  if x[1]!=z[1] or not np.allclose(x[0],z[0],atol=1e-9,rtol=1e-9) or not np.isclose(x[2],z[2],atol=1e-6,rtol=0):raise Stop('Null control changed features/availability')
 return {'status':'NULL_PASSED','records':len(a)}

def label_panel(path,panel):
 wanted={r['ks']:uid for uid,r in panel.items()};labels={};dup=set();n=0
 for r in logs(path,True):
  n+=1
  if n>CFG['target_label_row_limit']:break
  try:k=record_key(r)
  except (ValueError,KeyError):continue
  if k not in wanted or r['label'].lower() not in ['benign','malicious']:continue
  uid=wanted[k]
  try:v=features(r)
  except (ValueError,KeyError):continue
  if v['proto']!=panel[uid]['proto'] or not np.allclose([v[c] for c in F[:-1]],[panel[uid][c] for c in F[:-1]],atol=1e-9,rtol=1e-9):continue
  if uid in labels:dup.add(uid)
  labels[uid]=int(r['label'].lower()=='malicious')
 for uid in dup:labels.pop(uid,None)
 return labels,min(n,CFG['target_label_row_limit'])

def bounds(keys,st,alarm,deadline):
 result={}
 for k in keys:
  seen=[u for u in st['owners'].get(k,()) if alarm.get(u,False) and u in st['av'] and st['av'][u]<=deadline[k]]
  positive=any(st['pure'].get(u,False) for u in seen)
  result[k]=(1,1) if positive else ((0,0) if st['complete'].get(k,False) and not seen else (0,1))
 return result

def select_scores(st,prob,begin,end,source_rate):
 use=[u for u,r in st['rows'].items() if begin<=r['ts']<end and u in st['av'] and st['av'][u]<=end]
 if not use:return {'low_confidence':0.,'boundary_pressure':0.,'traffic_load':0.,'positive_rate_shift':0.,'available_records':0}
 tcp=[st['rows'][u] for u in use if st['rows'][u]['proto']=='tcp']
 return {'low_confidence':float(np.mean([1-max(prob[u],1-prob[u]) for u in use])),
  'boundary_pressure':float(np.mean([r['orig_pkts']+r['resp_pkts']<=1 for r in tcp])) if tcp else 0.,
  'traffic_load':float(np.log1p(len(use))/(end-begin)),
  'positive_rate_shift':float(abs(np.mean([prob[u]>=.5 for u in use])-source_rate)),'available_records':len(use)}


def target_capture(capture,models,rates,binary):
 d=OUT/f'capture_{capture}';d.mkdir();scratch=d/'scratch';scratch.mkdir()
 receipt={'capture':capture,'status':'STARTED'};unit_rows=[];window_rows=[]
 try:
  raw,published=scenario_assets(capture,True);h,e,u,link=header(raw)
  pack=[];groups0=defaultdict(list);size=24
  for idx,ts,cap,wire,payload,off in packets(raw):
   if size+16+cap>CFG['target_prefix_MiB']*1024**2 or len(pack)>=CFG['target_max_packets']:break
   j=len(pack);pack.append((ts,cap,wire,payload));size+=16+cap;key=fp(ts,payload,link)
   if key is not None:groups0[key].append(j)
  if not pack:raise Stop('Empty fixed prefix')
  begin=min(r[0] for r in pack)/1e9;end=max(r[0] for r in pack)/1e9
  if end-begin<=CFG['tail_seconds']+CFG['window_seconds']:raise Stop('Fixed prefix has insufficient time span; no automatic expansion')
  clean=scratch/'clean.pcap';write_trace(clean,h,e,u,pack)
  js(d/'raw_identity.json',{'original_path':str(raw),'fixed_prefix_bytes':size,'packets':len(pack),'prefix_sha256':sha(clean),'span_seconds':end-begin})
  r0,ev0,av0,_=replay(binary,clean,scratch/'delay0_timeout5',5)
  if capture==CFG['target_captures'][0]:
   rn,en,an,_=replay(binary,clean,scratch/'null_repeat_timeout5',5)
   js(d/'null_control.json',null_check(r0,av0,rn,an));del rn,en,an;shutil.rmtree(scratch/'null_repeat_timeout5')
  owner,amb=reference_map(groups0,ev0);counts=Counter(owner.values());first={}
  for idx,k in sorted(owner.items()):first.setdefault(k,idx)
  eligible={k for k,n in counts.items() if k in r0 and r0[k]['proto']=='tcp' and n>=2 and n==int(r0[k]['orig_pkts']+r0[k]['resp_pkts'])}
  candidate={k:r for k,r in r0.items() if k in counts and 0<counts[k]<=64 and counts[k]==int(r['orig_pkts']+r['resp_pkts']) and r['proto'] in ['tcp','udp'] and r['ts']<end-CFG['tail_seconds']}
  keys=sorted(candidate,key=lambda k:candidate[k]['ks'])[:CFG['target_panel_units']];panel={k:candidate[k] for k in keys}
  if len(keys)<64:raise Stop('Fewer than 64 fully mapped supported clean-reference units')
  pd.DataFrame(panel.values()).to_csv(d/'panel_BEFORE_LABELS.csv.gz',index=False,compression='gzip')
  pd.DataFrame({'packet_index':list(owner),'reference_uid':list(owner.values())}).to_csv(d/'reference_packet_UIDs.csv.gz',index=False,compression='gzip')
  labels,scanned=label_panel(published,panel)
  js(d/'label_linkage.json',{'panel_units':len(keys),'matched_labels':len(labels),'benign':sum(v==0 for v in labels.values()),'malicious':sum(v==1 for v in labels.values()),'unmatched_not_invented':len(keys)-len(labels),'rows_scanned':scanned})
  for delay in CFG['delays_seconds']:
   delta=np.zeros(len(pack),dtype=np.int64)
   if delay:
    for idx,k in owner.items():
     if k in eligible and idx!=first[k]:delta[idx]=delay*10**9
   timestamps=np.array([r[0] for r in pack],dtype=np.int64)+delta
   groups=defaultdict(list)
   for key,indices in groups0.items():
    for idx in indices:groups[((int(timestamps[idx])+500)//1000,*key[1:])].append(idx)
   trace=clean if delay==0 else scratch/f'paced{delay}.pcap'
   if delay:write_trace(trace,h,e,u,pack,delta)
   states={}
   for timeout in CFG['timeouts_seconds']:
    print('MEASUREMENT capture',capture,'delay',delay,'timeout',timeout,flush=True)
    if delay==0 and timeout==5:rows,events,av=r0,ev0,av0
    else:rows,events,av,_=replay(binary,trace,scratch/f'delay{delay}_timeout{timeout}',timeout)
    descendants,pure,complete=map_condition(groups,events,owner,rows)
    states[timeout]={'rows':rows,'av':av,'owners':descendants,'pure':pure,'complete':complete}
    js(d/f'accounting_delay{delay}_timeout{timeout}.json',{'panel_units':len(keys),'complete_memberships':sum(complete.get(k,False) for k in keys),'pure_record_UIDs':sum(pure.values()),'PCAP_sha256':sha(trace)})
    if timeout!=5:del events
   windows={k:int((timestamps[first[k]]/1e9-begin)//CFG['window_seconds']) for k in keys}
   deadline={k:begin+(windows[k]+1)*CFG['window_seconds']+CFG['grace_seconds'] for k in keys}
   valid=[k for k in keys if deadline[k]<=end-CFG['tail_seconds']+CFG['grace_seconds']]
   for family,model in models.items():
    probs={};decisions={}
    with threadpool_limits(limits=2):
     for timeout,st in states.items():
      frame=pd.DataFrame(st['rows'].values())
      if frame.empty:raise Stop('No compatible extracted rows')
      p=model.predict_proba(encode(frame))[:,1]
      if not np.isfinite(p).all():raise Stop('Nonfinite probabilities')
      probs[timeout]=dict(zip(frame.uid,p));decisions[timeout]=bounds(valid,st,{u:x>=.5 for u,x in probs[timeout].items()},deadline)
    local=[]
    for k in valid:
     a,b=decisions[5][k],decisions[15][k];y=labels.get(k)
     wrong=bool(y is not None and a[0]==a[1] and a[0]!=y)
     helpful=bool(wrong and b[0]==b[1] and b[0]==y)
     harmful=bool(y is not None and a[0]==a[1] and a[0]==y and b[0]==b[1] and b[0]!=y)
     local.append({'capture':capture,'condition_seconds':delay,'family':family,'ks':panel[k]['ks'],'window':windows[k],
      'label':y,'default_lower':a[0],'default_upper':a[1],'alternate_lower':b[0],'alternate_upper':b[1],
      'definite_flip':a[0]==a[1] and b[0]==b[1] and a[0]!=b[0],
      'default_definite_error':wrong,'helpful_disagreement':helpful,'harmful_alternate_switch':harmful})
    unit_rows.extend(local);df=pd.DataFrame(local)
    if df.empty:continue
    for wi,g in df.groupby('window',sort=True):
     left=begin+int(wi)*CFG['window_seconds'];right=left+CFG['window_seconds']
     sc=select_scores(states[5],probs[5],left,right,rates[family])
     window_rows.append({'capture':capture,'condition_seconds':delay,'family':family,'window':int(wi),
      'units':len(g),'labelled_units':int(g.label.notna().sum()),'benign_units':int(g.label.eq(0).sum()),'malicious_units':int(g.label.eq(1).sum()),
      'disagreement':int(g.definite_flip.sum()),'default_definite_errors':int(g.default_definite_error.sum()),
      'helpful_units':int(g.helpful_disagreement.sum()),'harmful_alternate_units':int(g.harmful_alternate_switch.sum()),
      'unresolved_default':int(g.default_lower.ne(g.default_upper).sum()),'unresolved_alternate':int(g.alternate_lower.ne(g.alternate_upper).sum()),**sc})
    print('CAPTURE',capture,'condition',delay,'model',family,'units',len(df),'labels',int(df.label.notna().sum()),'flips',int(df.definite_flip.sum()),'helpful',int(df.helpful_disagreement.sum()),flush=True)
   pd.DataFrame(unit_rows).to_csv(d/'experiment1_units.csv.gz',index=False,compression='gzip')
   pd.DataFrame(window_rows).to_csv(d/'experiment2_windows.csv',index=False)
   js(d/'progress.json',{'completed_condition':delay,'unit_rows':len(unit_rows),'window_rows':len(window_rows),'capture_not_yet_complete':True})
   checkpoint();del states;gc.collect()
   if delay:trace.unlink()
   for rd in scratch.glob(f'delay{delay}_timeout*'):
    if rd.is_dir() and not (delay==0 and rd.name=='delay0_timeout5'):shutil.rmtree(rd)
  receipt.update({'status':'CAPTURE_COMPLETE','panel_units':len(keys),'matched_labels':len(labels),'eligible_TCP_reference_units':len(eligible),'ambiguous_clean_packet_occurrences':amb})
  shutil.rmtree(scratch);receipt['only_this_run_scratch_removed']=True
 except Exception as ex:
  receipt.update({'status':'BLOCKED_OR_FAILED','reason':str(ex)});(d/'error.txt').write_text(traceback.format_exc())
  print('CAPTURE',capture,'STOPPED:',ex,flush=True)
 finally:js(d/'receipt.json',receipt)
 return unit_rows,window_rows,receipt

def policy_analysis(windows):
 wf=pd.DataFrame(windows);results=[];rng=np.random.default_rng(CFG['ranking_seed'])
 def evaluate(g,idx,probe):
  selected=g.index.isin(set(idx));warning=selected & g.disagreement.gt(0).to_numpy() if probe else selected
  harmful=g.default_definite_errors.gt(0).to_numpy()
  return {'checks':int(selected.sum()) if probe else 0,'selected_windows':int(selected.sum()),'warnings':int(warning.sum()),
   'harmful_windows_warned':int((warning&harmful).sum()),'harmful_windows_unwarned':int((~warning&harmful).sum()),
   'warnings_without_definite_error':int((warning&~harmful).sum()),'helpful_units_exposed':int(g.loc[warning,'helpful_units'].sum())}
 for (capture,condition,family),g in wf.groupby(['capture','condition_seconds','family'],sort=True):
  for budget in CFG['budgets']:
   n=max(1,int(math.floor(len(g)*budget)));base={'capture':capture,'condition_seconds':condition,'family':family,'budget_fraction':budget,'total_windows':len(g)}
   for name in ['low_confidence','boundary_pressure','traffic_load','positive_rate_shift']:
    idx=g.sort_values([name,'window'],ascending=[False,True],kind='stable').index[:n]
    results.append({**base,'policy':name.upper(),'repetition':0,**evaluate(g,idx,True)})
    results.append({**base,'policy':name.upper()+'_PASSIVE_ESCALATION','repetition':0,**evaluate(g,idx,False)})
   for rep in range(CFG['random_schedules']):
    idx=rng.choice(g.index.to_numpy(),n,replace=False)
    results.append({**base,'policy':'RANDOM','repetition':rep,**evaluate(g,idx,True)})
 pf=pd.DataFrame(results);pf.to_csv(OUT/'experiment3_policy_schedules.csv',index=False)
 summary=pf.groupby(['capture','condition_seconds','family','budget_fraction','policy'],as_index=False).agg(simulations=('repetition','size'),checks=('checks','mean'),warnings=('warnings','mean'),
  harmful_windows_warned=('harmful_windows_warned','mean'),harmful_windows_unwarned=('harmful_windows_unwarned','mean'),
  helpful_units_exposed=('helpful_units_exposed','mean'),warnings_without_definite_error=('warnings_without_definite_error','mean'))
 summary.to_csv(OUT/'experiment3_policy_summary.csv',index=False)
 totals=wf.groupby(['capture','condition_seconds','family'],as_index=False).agg(windows=('window','size'),units=('units','sum'),labelled_units=('labelled_units','sum'),
  benign_units=('benign_units','sum'),malicious_units=('malicious_units','sum'),default_errors=('default_definite_errors','sum'),
  helpful_units=('helpful_units','sum'),definite_flips=('disagreement','sum'),harmful_alternate_units=('harmful_alternate_units','sum'),
  unresolved_default=('unresolved_default','sum'),unresolved_alternate=('unresolved_alternate','sum'))
 totals.to_csv(OUT/'DECISION_INFORMATION_TABLE.csv',index=False);return totals,summary

def main():
 if not RAW.is_dir():raise Stop('Attach the ORIGINAL IoT-23 raw dataset at '+str(RAW)+'. No previous experiment artifacts are needed.')
 if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free required. Historical inputs/results will not be deleted.')
 js(OUT/'PRE_OUTCOME_PROTOCOL.json',{'config':CFG,'fresh_training':True,'historical_results_reproduced':False,
  'source_data':'original published labelled logs for 1,3,8 only','target_data':'fresh fixed prefixes from 34,49,7 only',
  'stress':'10s delay after first packet of fully mapped TCP units, selected without labels. Offline diagnostic stress, not host/functionality validation.',
  'comparison':'same packets, frozen freshly trained model, SYN timeout 5 vs 15 seconds',
  'panel':'lowest hash keys of fully mapped original units, before target labels and model outcomes',
  'runtime_labels_used':False,'labels':'strict exact-key/stable-core published-label matching for OFFLINE scoring only',
  'budget_experiment':'retrospective label-free ranking, NOT an online scheduler or measured on-demand speedup',
  'positive_rate_shift_baseline':'simple source-reference output-rate shift, not published MD3',
  'independent_confirmation':False,'novelty_established':False})
 binary,version=setup_zeek()
 js(OUT/'environment.json',{'python':sys.version,'platform':platform.platform(),'numpy':np.__version__,'pandas':pd.__version__,
  'sklearn':__import__('sklearn').__version__,'zeek':version,'zeek_path':binary,'experiment_uses_one_recorded_software_version':True})
 models,rates=train_from_raw_logs();R['status']='FRESH_SOURCE_MODELS_READY';js(OUT/'receipt.json',R)
 cp=checkpoint();print('SOURCE MODEL CHECKPOINT:',cp['path'],flush=True)
 all_units=[];all_windows=[];statuses=[]
 for cap in CFG['target_captures']:
  units,windows,status=target_capture(cap,models,rates,binary);statuses.append(status)
  # Never pool partial failed-capture computations into the scientific decision.
  if status['status']=='CAPTURE_COMPLETE':all_units.extend(units);all_windows.extend(windows)
  pd.DataFrame(all_units).to_csv(OUT/'experiment1_unit_decisions.csv.gz',index=False,compression='gzip')
  pd.DataFrame(all_windows).to_csv(OUT/'experiment2_window_information.csv',index=False)
  js(OUT/'capture_progress.json',statuses);R['capture_progress']=statuses;js(OUT/'receipt.json',R);checkpoint();gc.collect()
 if not all_windows:raise Stop('No completed evaluable target windows. See capture_progress.json; no scientific verdict produced.')
 totals,summary=policy_analysis(all_windows);primary=totals[totals.family.eq('HGB')]
 informative=sorted(primary.loc[primary.helpful_units.ge(CFG['minimum_helpful_units_per_capture']),'capture'].unique().tolist())
 if any(r['status']!='CAPTURE_COMPLETE' for r in statuses):decision='INCOMPLETE_EXECUTION_NO_SCIENTIFIC_DECISION'
 elif primary.labelled_units.sum()==0:decision='INSUFFICIENT_LABEL_LINKAGE'
 elif primary.default_errors.sum()<CFG['minimum_helpful_units_per_capture']:decision='INSUFFICIENT_DEFAULT_ERRORS_TO_TEST_ERROR_DISCOVERY'
 elif primary.helpful_units.sum()==0:decision='NO_HELPFUL_REMEASUREMENT_OBSERVED_IN_DECLARED_PILOT'
 elif len(informative)<CFG['minimum_informative_captures']:decision='LOCAL_SIGNAL_ONLY_NOT_ENOUGH_TO_BUILD_SCHEDULER'
 else:decision='INFORMATION_GATE_PASSED_TEST_CAUSAL_IMPLEMENTATION_NEXT'
 R.update({'status':'RAW_ONLY_PILOT_FINISHED','scientific_decision':decision,'informative_captures_primary_HGB':informative,
  'online_scheduler_validated':False,'online_speedup_measured':False,'novelty_established':False,'independent_confirmation':False,
  'limits':['Fresh model study, not reproduction of historical frozen-bank results.',
   'Alternative answers can be harmful; disagreement is not ground truth.',
   'No application-functionality or end-to-end host-evasion claim.',
   'Full-prefix replay cost is not the cost of an on-demand buffered-window probe.',
   'Retrospective rankings are not a causal online selection algorithm.',
   'Too few errors, weak label coverage, or unresolved attribution are inconclusive, not proof of impossibility.',
   'The 20-helpful-units/two-captures gate is an engineering screen, not a significance or acceptance test.']})
 js(OUT/'receipt.json',R)
 print('\nEXPERIMENTS 1/2 — INFORMATION TABLE\n'+totals.to_string(index=False),flush=True)
 print('\nEXPERIMENT 3 — CHECK BUDGET 25%\n'+summary[summary.budget_fraction.eq(.25)].to_string(index=False),flush=True)

try:
 source=globals().get('__file__')
 if source and Path(source).is_file():shutil.copyfile(source,OUT/'executed_pilot.py')
 main()
except Exception as ex:
 R.update({'status':'STOPPED_WITH_EXACT_REASON','reason':str(ex),'scientific_decision':'NOT_ESTABLISHED'})
 (OUT/'error.txt').write_text(traceback.format_exc());print('\nSTOPPED:',ex,flush=True)
finally:
 js(OUT/'receipt.json',R)
 try:
  cp=checkpoint();R['final_checkpoint']=cp;js(OUT/'receipt.json',R)
  print('\nPRIVATE CHECKPOINT:',cp['path'],flush=True)
 except Exception as ex:R['checkpoint_error']=str(ex);js(OUT/'receipt.json',R)
 print('\nPILOT RECEIPT\n'+json.dumps(R,indent=2),flush=True)
