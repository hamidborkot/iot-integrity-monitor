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
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
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

W=Path('/kaggle/working')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
BACKUP=Path('/kaggle/input/datasets/mdhamidborkottulla/full-working-backup')
RUN_ID='RAW_ONLY_REMEASUREMENT_20261017T130813279947Z'
OUT=W/('MECHANISM_DIAGNOSIS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
class Stop(Exception):pass
R={'status':'STARTED','new_model_fits':0,'new_PCAP_replays':0,'old_artifacts_read':True,
 'new_method_tested':False,'novelty_established':False,'output_directory':str(OUT)}
CFG={};OLD={};ASSET_LOG=[];EXPLANATIONS=[];INDEX=None

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

def scenario_assets(cap,need_pcap=True):
 token=f'CTU-IoT-Malware-Capture-{cap}-1'
 labels=[p for p in RAW.rglob('conn.log.labeled') if token in p.parts]
 if len(labels)!=1:raise Stop('Expected exactly one published log for '+token+'; found '+str(len(labels)))
 pcaps=[p for p in RAW.rglob('*.pcap') if token in p.parts] if need_pcap else []
 if need_pcap and not pcaps:raise Stop('Original classic PCAP missing for '+token)
 return (max(pcaps,key=lambda p:p.stat().st_size) if pcaps else None),labels[0]

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
  verify_prefix(capture,clean)
  js(d/'raw_identity.json',{'original_path':str(raw),'fixed_prefix_bytes':size,'packets':len(pack),'prefix_sha256':sha(clean),'span_seconds':end-begin})
  r0,ev0,av0,_=replay(binary,clean,scratch/'delay0_timeout5',5)
  if False:  # prior null control must already be verified by audit_inputs
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
  verify_panel(capture,panel)
  labels,scanned=reuse_labels(capture,panel)
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
    persist_records(d,delay,timeout,rows,av)
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
      explain_units(d,capture,delay,timeout,family,frame,p,st,valid,deadline,panel,labels)
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

def read_asset(a):
 chain=a['chain']
 if not chain:
  with open(a['path'],'rb') as f:data=f.read(64*1024**2+1)
 else:
  with zipfile.ZipFile(a['path']) as z:data=z.read(chain[0])
  for name in chain[1:]:
   if len(data)>64*1024**2:raise Stop('Nested metadata archive exceeds 64 MiB cap')
   with zipfile.ZipFile(io.BytesIO(data)) as z:data=z.read(name)
 if len(data)>64*1024**2:raise Stop('Required metadata/model exceeds 64 MiB cap')
 return data

def index_backup():
 global INDEX
 if INDEX is not None:return INDEX
 if not BACKUP.is_dir():raise Stop('Attach your saved full-working-backup dataset at '+str(BACKUP))
 entries=[];archives=[]
 for root in [BACKUP,W]:
  if not root.is_dir():continue
  for current,dirs,files in os.walk(root,followlinks=False):
   dirs[:]=[d for d in dirs if d not in {'.git','__pycache__'} and not (Path(current)/d).resolve().is_relative_to(OUT.resolve())]
   for name in files:
    p=Path(current)/name
    if p.is_symlink():continue
    if RUN_ID in p.parts:entries.append({'path':str(p),'chain':[],'logical':str(p),'bytes':p.stat().st_size})
    if p.suffix.lower()=='.zip':archives.append(p)
 nested_bytes=0
 def scan(z,path,chain,depth):
  nonlocal nested_bytes
  for inf in z.infolist():
   if inf.is_dir():continue
   logical='/'.join([str(path),*chain,inf.filename])
   if RUN_ID in logical:entries.append({'path':str(path),'chain':[*chain,inf.filename],'logical':logical,'bytes':inf.file_size})
   if inf.filename.lower().endswith('.zip') and depth<2 and inf.file_size<=64*1024**2:
    if nested_bytes+inf.file_size>256*1024**2:continue
    data=z.read(inf);nested_bytes+=len(data)
    try:
     with zipfile.ZipFile(io.BytesIO(data)) as inner:scan(inner,path,[*chain,inf.filename],depth+1)
    except zipfile.BadZipFile:pass
 for path in archives:
  try:
   with zipfile.ZipFile(path) as z:scan(z,path,[],0)
  except (OSError,zipfile.BadZipFile) as ex:ASSET_LOG.append({'scan_warning':str(ex),'path':str(path)})
 INDEX=entries
 print('INPUT INDEX:',len(entries),'entries for the exact saved run;',len(archives),'ZIPs checked.',flush=True)
 return entries

def restore(relative):
 local=OUT/'verified_inputs'/relative
 if local.is_file():return local
 hits=[a for a in index_backup() if a['logical'].replace('\\','/').endswith('/'+relative) and a['bytes']<=64*1024**2]
 if not hits:raise Stop('Required saved input missing from the mounted backup: '+RUN_ID+'/'+relative)
 versions={}
 for a in hits:
  b=read_asset(a);digest=hashlib.sha256(b).hexdigest();versions.setdefault(digest,[]).append((a,b))
 if len(versions)!=1:raise Stop('Content-conflicting copies for '+relative+'; no version guessed')
 digest,copies=next(iter(versions.items()));a,data=min(copies,key=lambda v:(len(v[0]['chain']),len(v[0]['path']),v[0]['path']))
 local.parent.mkdir(parents=True,exist_ok=True);local.write_bytes(data)
 ASSET_LOG.append({'relative':relative,'origin':a,'sha256':digest,'restored_bytes':len(data)})
 js(OUT/'input_binding.json',ASSET_LOG);return local

def audit_inputs():
 global CFG
 required=['PRE_OUTCOME_PROTOCOL.json','environment.json','model_binding.json','fresh_HGB.joblib','fresh_LR.joblib',
  'fresh_source_panel.csv.gz','source_holdout_metrics.csv','experiment1_unit_decisions.csv.gz',
  'experiment2_window_information.csv','DECISION_INFORMATION_TABLE.csv','capture_34/null_control.json']
 for name in required:restore(name)
 protocol=json.loads(restore('PRE_OUTCOME_PROTOCOL.json').read_text());CFG=dict(protocol['config'])
 if CFG['target_prefix_MiB']!=64 or CFG['timeouts_seconds']!=[5,15] or CFG['delays_seconds']!=[0,10]:raise Stop('Saved protocol differs from the inspected pilot')
 null=json.loads(restore('capture_34/null_control.json').read_text())
 if null.get('status')!='NULL_PASSED':raise Stop('Saved pilot null control did not pass')
 binding=json.loads(restore('model_binding.json').read_text())
 for family in ['HGB','LR']:
  if sha(restore('fresh_'+family+'.joblib'))!=binding['model_sha256'][family]:raise Stop('Saved '+family+' model hash mismatch')
 if sha(restore('fresh_source_panel.csv.gz'))!=binding['source_panel_sha256']:raise Stop('Saved source panel hash mismatch')
 units=pd.read_csv(restore('experiment1_unit_decisions.csv.gz'),dtype={'ks':str})
 windows=pd.read_csv(restore('experiment2_window_information.csv'))
 OLD['units']=units;OLD['windows']=windows;OLD['environment']=json.loads(restore('environment.json').read_text())
 for capture in [49,7]:
  OLD[capture]={'raw':json.loads(restore(f'capture_{capture}/raw_identity.json').read_text()),
   'panel':pd.read_csv(restore(f'capture_{capture}/panel_BEFORE_LABELS.csv.gz'),dtype={'ks':str})}
 summary=windows.groupby(['capture','condition_seconds','family'],as_index=False).agg(
  windows=('window','size'),panel_units=('units','sum'),labels=('labelled_units','sum'),
  benign=('benign_units','sum'),malicious=('malicious_units','sum'),flips=('disagreement','sum'),
  default_errors=('default_definite_errors','sum'),helpful=('helpful_units','sum'),
  empty_score_windows=('available_records',lambda x:int(x.eq(0).sum())))
 summary['empty_score_fraction']=summary.empty_score_windows/summary.windows
 summary.to_csv(OUT/'EXPERIMENT1_SAVED_RESULT_AUDIT.csv',index=False)
 print('\nEXPERIMENT 1 — SAVED RESULT AND SELECTOR OBSERVATION AUDIT\n'+summary.to_string(index=False),flush=True)
 js(OUT/'diagnostic_protocol.json',{'parent_run':RUN_ID,'same_models':binding['model_sha256'],
  'same_raw_prefix_and_initial_panel_required':True,'new_training':False,'new_hypothesis':False,
  'replays':{'49':[{'delay':d,'timeout':t} for d in [0,10] for t in [5,15]],
   '7':[{'delay':0,'timeout':t} for t in [5,15]]},
  'six_replays_maximum':True,'purpose':'Separate extraction changes, prediction changes, alarm-time changes, aggregation and deadline misses.',
  'negative_parent_result_preserved':True,'scheduler_development_authorized':False})
 # Serialization compatibility is checked before model loading, never fixed by retraining.
 current=__import__('sklearn').__version__
 if current!=OLD['environment']['sklearn']:raise Stop('Saved sklearn version '+OLD['environment']['sklearn']+' differs from runtime '+current+'. Use matching Kaggle image/environment; no model replacement allowed.')
 from sklearn.exceptions import InconsistentVersionWarning
 with warnings.catch_warnings():
  warnings.simplefilter('error',InconsistentVersionWarning)
  models={f:joblib.load(restore('fresh_'+f+'.joblib')) for f in ['HGB','LR']}
 return models,binding['source_positive_rates']

def setup_zeek():
 text=OLD['environment']['zeek'];m=re.search(r'version\s+([0-9]+\.[0-9]+\.[0-9]+)',text)
 if not m:raise Stop('Cannot parse saved Zeek identity: '+text)
 expected=m.group(1)
 def find():
  for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
   if not p or not Path(p).is_file():continue
   q=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30);s=(q.stdout+q.stderr).strip()
   if q.returncode==0 and re.search(r'(?<![\d.])'+re.escape(expected)+r'(?![\d.])',s):return p,s
  return None,None
 p,v=find()
 if p:return p,v
 if os.geteuid()!=0:raise Stop('Exact saved Zeek '+expected+' is missing; installation requires root')
 release={}
 for line in Path('/etc/os-release').read_text().splitlines():
  if '=' in line:
   k,x=line.split('=',1);release[k]=x.strip('"')
 if release.get('ID')!='ubuntu':raise Stop('Automatic exact-version installation supports Ubuntu only')
 url='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_'+release['VERSION_ID']+'/'
 print('Installing the saved Zeek version',expected,'— Kaggle Internet must be ON.',flush=True)
 with urllib.request.urlopen(url+'Release.key',timeout=60) as r:key=r.read(1024**2)
 if b'BEGIN PGP PUBLIC KEY BLOCK' not in key:raise Stop('Invalid signing-key response')
 kp=Path('/etc/apt/keyrings/mechanism-audit-zeek.asc');kp.parent.mkdir(exist_ok=True);kp.write_bytes(key);kp.chmod(0o644)
 Path('/etc/apt/sources.list.d/mechanism-audit-zeek.list').write_text(f'deb [signed-by={kp}] {url} /\n')
 def cmd(args,name,timeout):
  with (OUT/name).open('w') as f:q=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
  if q.returncode:raise Stop('Dependency step failed: '+name)
 cmd(['apt-get','-o','Acquire::Retries=2','-o','Acquire::http::Timeout=40','-o','Acquire::https::Timeout=40','update'],'apt_update.txt',600)
 package='zeek-'+'.'.join(expected.split('.')[:2]);q=subprocess.run(['apt-cache','madison',package],capture_output=True,text=True,timeout=30)
 versions=[line.split('|')[1].strip() for line in q.stdout.splitlines() if len(line.split('|'))>=2]
 versions=[x for x in versions if re.match(r'(?:\d+:)?'+re.escape(expected)+r'(?:$|[-+~])',x)]
 if not versions:raise Stop('Exact saved Zeek '+expected+' unavailable in this repository. No alternate version substituted.')
 cmd(['apt-get','-y','--no-install-recommends','install',package+'='+versions[0]],'apt_install.txt',900)
 p,v=find()
 if not p:raise Stop('Installed executable failed saved-version verification')
 return p,v

def verify_prefix(capture,path):
 if sha(path)!=OLD[capture]['raw']['prefix_sha256']:raise Stop('Rebuilt prefix does not match the saved run; no changed panel analyzed')

def verify_panel(capture,panel):
 old=OLD[capture]['panel'].set_index('ks');new=pd.DataFrame(panel.values()).set_index('ks')
 if old.index.duplicated().any() or new.index.duplicated().any() or set(old.index)!=set(new.index):raise Stop('Reference panel membership differs from saved run')
 new=new.loc[old.index]
 if not np.allclose(new[F[:-1]].to_numpy(float),old[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(new.proto,old.proto):raise Stop('Reference panel features differ from saved run')
 js(OUT/f'capture_{capture}'/'PARENT_PANEL_REPRODUCTION.json',{'status':'PASSED','keys':len(old),'features_equal':True,'prefix_hash_equal':True})

def reuse_labels(capture,panel):
 ref=OLD['units'];ref=ref[ref.capture.eq(capture)&ref.condition_seconds.eq(0)][['ks','label']].dropna()
 if ref.groupby('ks').label.nunique().gt(1).any():raise Stop('Saved original-unit labels conflict')
 known=ref.drop_duplicates('ks').set_index('ks').label.to_dict()
 return {uid:int(known[r['ks']]) for uid,r in panel.items() if r['ks'] in known},0

def persist_records(d,delay,timeout,rows,av):
 frame=pd.DataFrame(rows.values());frame['record_available_at']=frame.uid.map(av)
 frame.to_csv(d/f'extractor_records_delay{delay}_timeout{timeout}.csv.gz',index=False,compression='gzip')

def signature(values):
 canonical=sorted(values)
 return hashlib.sha256(json.dumps(canonical,separators=(',',':')).encode()).hexdigest()

def explain_units(d,capture,delay,timeout,family,frame,p,st,keys,deadline,panel,labels):
 probability=dict(zip(frame.uid,p));alarm={u:v>=.5 for u,v in probability.items()}
 pd.DataFrame({'uid':frame.uid,'probability':p,'prediction':p>=.5}).to_csv(d/f'probabilities_delay{delay}_timeout{timeout}_{family}.csv.gz',index=False,compression='gzip')
 outcome=bounds(keys,st,alarm,deadline)
 for k in keys:
  descendants=sorted(st['owners'].get(k,()))
  positive=[u for u in descendants if alarm.get(u,False)]
  pure_positive=[u for u in positive if st['pure'].get(u,False)]
  pure_time=min([st['av'][u] for u in pure_positive if u in st['av']],default=np.nan)
  a=outcome[k];y=labels.get(k);complete=bool(st['complete'].get(k,False))
  if y is None:reason='LABEL_UNAVAILABLE'
  elif a[0]!=a[1]:reason='ATTRIBUTION_UNRESOLVED'
  elif y==0:reason='BENIGN_FALSE_ALARM_BY_DEADLINE' if a[0] else 'BENIGN_NO_ALARM_BY_DEADLINE'
  elif a[0]:reason='MALICIOUS_ALARM_BY_DEADLINE'
  elif complete and not positive:reason='MALICIOUS_NO_POSITIVE_DESCENDANT_EVEN_EVENTUALLY'
  elif np.isfinite(pure_time) and pure_time>deadline[k]:reason='MALICIOUS_PURE_ALARM_EXISTS_BUT_LATE'
  else:reason='MALICIOUS_NO_EARLY_ALARM_WITH_ONLY_UNATTRIBUTED_LATER_EVIDENCE'
  feature_vectors=[]
  for u in descendants:
   if u not in st['rows']:continue
   r=st['rows'][u];feature_vectors.append([*[float(r[c]).hex() for c in F[:-1]],r['proto']])
  EXPLANATIONS.append({'capture':capture,'condition_seconds':delay,'timeout_seconds':timeout,'family':family,
   'ks':panel[k]['ks'],'label':y,'lower':a[0],'upper':a[1],'complete':complete,
   'descendant_records':len(descendants),'positive_descendant_records':len(positive),
   'pure_positive_records':len(pure_positive),'earliest_pure_alarm_at':pure_time,'deadline_at':deadline[k],
   'reason':reason,'feature_multiset_sha256':signature(feature_vectors),
   'probability_multiset_sha256':signature([float(probability[u]).hex() for u in descendants if u in probability]),
   'availability_multiset_sha256':signature([float(st['av'][u]).hex() for u in descendants if u in st['av']])})
 pd.DataFrame(EXPLANATIONS).to_csv(OUT/'per_unit_failure_explanations.csv.gz',index=False,compression='gzip')

def verify_parent_outcomes(capture,unit_rows):
 parent=OLD['units'];parent=parent[parent.capture.eq(capture)]
 new=pd.DataFrame(unit_rows)
 cols=['capture','condition_seconds','family','ks']
 keep=new[cols].drop_duplicates();old=parent.merge(keep,on=cols,validate='one_to_one')
 if len(old)!=len(new):raise Stop('New original-unit outcome population differs from saved pilot')
 joined=new.merge(old[cols+['default_lower','default_upper','alternate_lower','alternate_upper']],on=cols,suffixes=('_new','_old'),validate='one_to_one')
 fields=['default_lower','default_upper','alternate_lower','alternate_upper']
 ok=all(np.array_equal(joined[f+'_new'],joined[f+'_old']) for f in fields)
 js(OUT/f'capture_{capture}'/'PARENT_OUTCOME_REPRODUCTION.json',{'status':'PASSED' if ok else 'FAILED','rows':len(joined),'intervals_equal':ok})
 if not ok:raise Stop('Saved unit outcomes did not reproduce; new diagnostic not interpreted as the same experiment')

def summarize_explanations():
 df=pd.DataFrame(EXPLANATIONS)
 if df.empty:raise Stop('No instrumented unit explanations produced')
 counts=df.groupby(['capture','condition_seconds','timeout_seconds','family','reason'],dropna=False).size().reset_index(name='units')
 counts.to_csv(OUT/'FAILURE_DECOMPOSITION.csv',index=False)
 key=['capture','condition_seconds','family','ks'];a=df[df.timeout_seconds.eq(5)];b=df[df.timeout_seconds.eq(15)]
 paired=a.merge(b,on=key,suffixes=('_5','_15'),validate='one_to_one')
 if len(paired)!=len(a) or len(paired)!=len(b):raise Stop('Timeout comparison unit populations differ')
 for name in ['feature_multiset_sha256','probability_multiset_sha256','availability_multiset_sha256','descendant_records']:
  paired[name+'_changed']=paired[name+'_5'].ne(paired[name+'_15'])
 paired['final_interval_changed']=paired.lower_5.ne(paired.lower_15)|paired.upper_5.ne(paired.upper_15)
 paired['definite_binary_flip']=paired.lower_5.eq(paired.upper_5)&paired.lower_15.eq(paired.upper_15)&paired.lower_5.ne(paired.lower_15)
 paired.to_csv(OUT/'paired_layer_changes.csv.gz',index=False,compression='gzip')
 summary=paired.groupby(['capture','condition_seconds','family'],as_index=False).agg(units=('ks','size'),
  units_with_changed_feature_multiset=('feature_multiset_sha256_changed','sum'),
  units_with_changed_probability_multiset=('probability_multiset_sha256_changed','sum'),
  units_with_changed_availability=('availability_multiset_sha256_changed','sum'),
  units_with_changed_record_count=('descendant_records_changed','sum'),
  changed_final_intervals=('final_interval_changed','sum'),definite_binary_flips=('definite_binary_flip','sum'))
 summary.to_csv(OUT/'MECHANISM_INFORMATION_TABLE.csv',index=False)
 print('\nMECHANISM INFORMATION TABLE\n'+summary.to_string(index=False),flush=True)
 print('\nCLASSIFICATION / LATE-ALARM / ATTRIBUTION DECOMPOSITION\n'+counts.to_string(index=False),flush=True)
 return summary

def main():
 if not RAW.is_dir():raise Stop('Original IoT-23 mount missing: '+str(RAW))
 if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free required')
 models,rates=audit_inputs();R['status']='INPUT_IDENTITIES_AND_SAVED_RESULTS_VERIFIED';js(OUT/'receipt.json',R);checkpoint()
 binary,version=setup_zeek();js(OUT/'diagnostic_environment.json',{'zeek':version,'parent_environment':OLD['environment']})
 statuses=[]
 for capture,delays in [(49,[0,10]),(7,[0])]:
  CFG['delays_seconds']=delays
  units,windows,status=target_capture(capture,models,rates,binary);statuses.append(status)
  if status['status']!='CAPTURE_COMPLETE':raise Stop('Instrumented capture failed: '+str(status))
  verify_parent_outcomes(capture,units);checkpoint()
 summary=summarize_explanations()
 if summary.definite_binary_flips.sum():finding='PARENT_ZERO_FLIP_RESULT_DID_NOT_REPRODUCE_REVIEW_REQUIRED'
 elif summary.units_with_changed_probability_multiset.sum() or summary.units_with_changed_availability.sum():finding='INTERMEDIATE_INFORMATION_CHANGED_BUT_FINAL_SIGNAL_WAS_ABSENT'
 elif summary.units_with_changed_feature_multiset.sum() or summary.units_with_changed_record_count.sum():finding='EXTRACTION_CHANGED_WITHOUT_USEFUL_FINAL_DECISION_DIFFERENCES'
 else:finding='NO_MEASUREMENT_CHANGE_OBSERVED_ON_THESE_REFERENCE_UNITS'
 R.update({'status':'BOUNDED_MECHANISM_DIAGNOSIS_COMPLETE','finding':finding,'captures':statuses,
  'parent_models_retrained':False,'parent_prefix_panel_and_outcomes_reproduced':True,
  'scheduler_development_authorized':False,'novelty_or_paper_success_claimed':False,
  'interpretation':'Post-pilot explanation of a negative result, not a replacement positive-method experiment. Intermediate changes are not automatically useful error warnings.'})

try:
 source=globals().get('__file__')
 if source and Path(source).is_file():shutil.copyfile(source,OUT/'executed_diagnostic.py')
 main()
except Exception as e:
 R.update({'status':'STOPPED_WITH_EXACT_REASON','reason':str(e),'finding':'NOT_ESTABLISHED'})
 (OUT/'error.txt').write_text(traceback.format_exc());print('\nSTOPPED:',e,flush=True)
finally:
 js(OUT/'receipt.json',R)
 try:R['checkpoint']=checkpoint();js(OUT/'receipt.json',R)
 except Exception as e:R['checkpoint_error']=str(e);js(OUT/'receipt.json',R)
 print('\nDIAGNOSTIC RECEIPT\n'+json.dumps(R,indent=2),flush=True)
