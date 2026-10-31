
# Three-part feasibility pilot. This is NOT an online gateway or a completed defense.
from pathlib import Path
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from collections import defaultdict,Counter
import gc,gzip,hashlib,json,math,os,re,shutil,socket,struct,subprocess,time,traceback,zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
OUT=W/('REMEASUREMENT_PILOT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
REFERENCE_RATES={}
CFG={'captures':[34,49,7],'prefix_MiB':64,'max_packets':1500000,
 'conditions_seconds':[0,10],'timeouts_seconds':[5,15],
 'label_row_limit':4000000,'reference_units':2048,'window_seconds':60,
 'decision_grace_seconds':30,'tail_seconds':120,'seed':99101,
 'policy_budgets':[.10,.25,.50,1.0],'random_schedules':100,
 'minimum_helpful_units':20,'minimum_informative_captures':2}
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
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


def fingerprint(ts,info):
 if info is None:return None
 src,dst,ident,length,proto,ports=info
 return ((int(ts)+500)//1000,src,dst,int(ident),int(length),proto)
def read_events(path):
 packet=defaultdict(Counter);available={}
 with open(path) as f:
  for line in f:
   if line.startswith('IP|'):
    x=line.strip().split('|')
    if len(x)!=8:raise Stop('Instrumentation packet schema mismatch')
    packet[(us(x[1]),x[3],x[4],int(x[5]),int(x[6]),x[7])][x[2]]+=1
   elif line.startswith('AV|'):
    x=line.strip().split('|')
    if len(x)!=3:raise Stop('Availability schema mismatch')
    uid=x[2];tt=float(x[1])
    if uid in available:raise Stop('Repeated connection-log event; no guessed availability')
    available[uid]=tt
 return packet,available

def write_pcap(path,h,e,u,records,delay_ns=None):
 order=sorted(range(len(records)),key=lambda i:(records[i][0]+(0 if delay_ns is None else int(delay_ns[i])),i))
 with open(path,'wb') as f:
  f.write(h)
  for i in order:
   ts,cap,wire,payload=records[i];ts+=0 if delay_ns is None else int(delay_ns[i])
   f.write(struct.pack(e+'IIII',ts//10**9,(ts%10**9)//u,cap,wire));f.write(payload)
 return order

def model_bank():
 candidates=[]
 roots=[W,Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')]
 for root in roots:
  if not root.is_dir():continue
  for d in root.glob('CONTROLLED_FIVE_SEED_SOURCE_SPLIT_*'):
   rp=d/'receipt.json';p=d/'five_seed_models_and_calibrators.joblib'
   if not rp.is_file() or not p.is_file():continue
   try:r=json.loads(rp.read_text())
   except (OSError,ValueError):continue
   if r.get('status')=='CONTROLLED_FIVE_SEED_SOURCE_SPLIT_BANK_COMPLETE':candidates.append(p)
 if not candidates:raise Stop('Attach the completed CONTROLLED_FIVE_SEED_SOURCE_SPLIT directory with five_seed_models_and_calibrators.joblib. No training or backup guessing performed.')
 latest=max(p.parent.name for p in candidates);candidates=[p for p in candidates if p.parent.name==latest]
 hashes={sha(p) for p in candidates}
 if len(hashes)!=1:raise Stop('Conflicting copies of the latest completed frozen bank')
 p=min(candidates,key=lambda p:str(p));bundle=joblib.load(p)
 models={fam:bundle['models'][('GROUP_DISJOINT',fam,8101)] for fam in ['HGB','LR']}
 for m in models.values():
  if list(m.classes_)!=[0,1]:raise Stop('Model class order mismatch')
 sp=p.parent/'source_panel_with_network_groups.csv.gz'
 if not sp.is_file():sp=p.parent/'source_panel_with_network_groups.csv'
 if not sp.is_file():raise Stop('Completed bank source panel missing; needed for the source-reference shift baseline')
 with sp.open('rb') as f:is_gzip=f.read(2)==b'\x1f\x8b'
 sf=pd.read_csv(sp,compression='gzip' if is_gzip else None)
 for c in F[:-1]:sf[c]=pd.to_numeric(sf[c],errors='raise').astype(float)
 sf['proto']=sf.proto.astype(str).str.lower()
 ref=sf.iloc[bundle['source_roles']['GROUP_DISJOINT']['calibration']]
 with threadpool_limits(limits=2):
  for fam,model in models.items():REFERENCE_RATES[fam]=float((model.predict_proba(encode(ref))[:,1]>=.5).mean())
 js(OUT/'source_shift_baseline.json',{'source_panel_sha256':sha(sp),'positive_rate':REFERENCE_RATES,'fit_performed':False,'baseline':'absolute change from source-calibration predicted-positive rate; NOT published MD3'})
 js(OUT/'model_binding.json',{'path':str(p),'sha256':sha(p),'policy':'GROUP_DISJOINT','seed':8101,'families':list(models),'why_one_seed':'Previously identical random-state outputs are not independent evidence.'})
 return models

def zeek_binary():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
  if p and Path(p).is_file():
   r=subprocess.run([p,'--version'],capture_output=True,text=True,timeout=30)
   if r.returncode==0 and re.search(r'(?<![\d.])8\.0\.10(?![\d.])',r.stdout+r.stderr):return p
 raise Stop('Zeek 8.0.10 is required. This pilot does not install or change software automatically.')

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

def replay(binary,pcap,folder,timeout):
 folder.mkdir(parents=True,exist_ok=False)
 script=folder/'tap.zeek';script.write_text(TAP.replace('TIMEOUT',str(float(timeout))))
 compile_dir=folder/'compile';compile_dir.mkdir()
 ck=subprocess.run([binary,'-b',str(script.resolve())],cwd=compile_dir,capture_output=True,text=True,timeout=30)
 (folder/'compile_stderr.txt').write_text(ck.stderr)
 if ck.returncode:raise Stop('Zeek diagnostic script failed compilation: '+ck.stderr[-1000:])
 start=time.perf_counter()
 peak_kib=0
 with (folder/'events.txt').open('w') as so,(folder/'stderr.txt').open('w') as se:
  rr=subprocess.Popen([binary,'-C','-r',str(pcap.resolve()),str(script.resolve())],cwd=folder,stdout=so,stderr=se)
  try:
   while rr.poll() is None:
    if time.perf_counter()-start>1800:raise Stop('Replay exceeded the fixed 1800-second limit')
    try:
     status=Path(f'/proc/{rr.pid}/status').read_text()
     mm=re.search(r'^VmRSS:\s+(\d+)\s+kB',status,re.M)
     if mm:peak_kib=max(peak_kib,int(mm.group(1)))
    except (OSError,ValueError):pass
    time.sleep(.05)
  finally:
   if rr.poll() is None:rr.kill()
   rr.wait()
 seconds=time.perf_counter()-start
 if rr.returncode or not (folder/'conn.log').is_file():raise Stop('Replay failed; logs retained: '+str(folder))
 rows={}
 for r in logs(folder/'conn.log'):
  try:v=features(r)
  except (ValueError,KeyError):continue
  if r['uid'] in rows:raise Stop('Duplicate connection UID')
  rows[r['uid']]={**v,'uid':r['uid'],'ts':float(r['ts']),'ks':record_key(r),'orig_h':r['id.orig_h'],'orig_p':r['id.orig_p'],'resp_h':r['id.resp_h'],'resp_p':r['id.resp_p']}
 ev,av=read_events(folder/'events.txt')
 if not ev:raise Stop('No IP events: no inference from missing instrumentation')
 if not set(rows).issubset(av):raise Stop('Missing connection-record availability events; no timing inferred')
 with (folder/'events.txt').open() as eventfile:
  config_lines=[line.strip() for line in eventfile if line.startswith('CFG|')]
 if len(config_lines)!=1:raise Stop('Extractor configuration was not reported exactly once')
 observed=float(re.search(r'[0-9]+(?:\.[0-9]+)?',config_lines[0].split('|',1)[1]).group())
 if observed!=float(timeout):raise Stop('Reported SYN timeout differs from requested setting')
 resource_receipt={'status':'REPLAY_COMPLETE','timeout':timeout,'PCAP_sha256':sha(pcap),'seconds':seconds,'records':len(rows),'availability_events':len(av),'Zeek_peak_RSS_KiB_sampled':peak_kib,'RSS_sampling_seconds':.05,'memory_scope':'Zeek process only, sampled peak, not entire Python pilot'}
 js(folder/'replay_receipt.json',resource_receipt)
 js(folder.parent.parent/(folder.name+'_resources.json'),resource_receipt)
 return rows,ev,av,seconds

def group_map(groups,events):
 # A timestamp/IP fingerprint class is mapped only if multiplicity matches
 # and every packet in the class belongs to the same observed Zeek UID.
 owner={};ambiguous=0
 for fp,indices in groups.items():
  vv=events.get(fp,{})
  if len(vv)==1 and sum(vv.values())==len(indices):
   uid=next(iter(vv))
   for i in indices:owner[i]=uid
  else:ambiguous+=len(indices)
 return owner,ambiguous

def condition_map(groups,events,reference_owner,rows):
 owners=defaultdict(set);tracked=Counter();uid_sources=defaultdict(set);mapped=Counter()
 for fp,vv in events.items():
  if fp not in groups:
   for u in vv:uid_sources[u].add('UNINDEXED')
 for fp,indices in groups.items():
  vv=events.get(fp,{})
  sources={reference_owner.get(i,'UNASSIGNED') for i in indices}
  if sum(vv.values())==len(indices) and len(sources)==1:
   source=next(iter(sources))
   for uid,n in vv.items():
    uid_sources[uid].add(source)
    if source!='UNASSIGNED':owners[source].add(uid);mapped[source]+=n;tracked[uid]+=n
  else:
   for uid in vv:uid_sources[uid].add('AMBIGUOUS')
 expected=Counter(reference_owner.values());event_count=Counter()
 for vv in events.values():event_count.update(vv)
 pure={u:len(uid_sources[u])==1 and not uid_sources[u]&{'UNINDEXED','UNASSIGNED','AMBIGUOUS'} and u in rows and tracked[u]==int(rows[u]['orig_pkts']+rows[u]['resp_pkts'])==event_count[u] for u in rows}
 complete={k:mapped[k]==n and bool(owners[k]) and owners[k].issubset(rows) for k,n in expected.items()}
 return owners,pure,complete

def label_panel(path,panel):
 bykey={r['ks']:u for u,r in panel.items()};found={};duplicates=set();scanned=0
 for r in logs(path,True):
  scanned+=1
  if scanned>CFG['label_row_limit']:break
  try:k=record_key(r)
  except (ValueError,KeyError):continue
  if k not in bykey:continue
  u=bykey[k];lab=r['label'].lower()
  if lab not in ['benign','malicious']:continue
  try:v=features(r)
  except (ValueError,KeyError):continue
  if v['proto']!=panel[u]['proto'] or not np.allclose([v[c] for c in F[:-1]],[panel[u][c] for c in F[:-1]],atol=1e-9,rtol=1e-9):continue
  if u in found:duplicates.add(u)
  found[u]=int(lab=='malicious')
 for u in duplicates:found.pop(u,None)
 return found,min(scanned,CFG['label_row_limit'])

def bound_decisions(panel_keys,owners,pure,complete,alarm,available,deadline):
 result={}
 for k in panel_keys:
  uu=owners.get(k,set());seen=[u for u in uu if u in available and available[u]<=deadline[k] and alarm.get(u,False)]
  positive=any(pure.get(u,False) for u in seen)
  negative=complete.get(k,False) and not seen
  result[k]=(1,1) if positive else ((0,0) if negative else (0,1))
 return result

def selector_score(rows,av,prob,start,end,reference_rate):
 use=[u for u,r in rows.items() if start<=r['ts']<end and u in av and av[u]<=end]
 if not use:return {'low_confidence':0.,'boundary_pressure':0.,'traffic_change':0.,'positive_rate_shift':0.,'available_records':0}
 confidence=np.array([max(prob[u],1-prob[u]) for u in use]);tcp=[rows[u] for u in use if rows[u]['proto']=='tcp']
 pressure=np.mean([r['orig_pkts']+r['resp_pkts']<=1 for r in tcp]) if tcp else 0.
 return {'low_confidence':float(1-confidence.mean()),'boundary_pressure':float(pressure),'traffic_change':float(np.log1p(len(use))/(end-start)),'positive_rate_shift':float(abs(np.mean([prob[u]>=.5 for u in use])-reference_rate)),'available_records':len(use)}

def evaluate_policy(g,chosen,use_probe=True):
 # All labels enter only here, after selection indices are fixed.
 chosen=set(chosen);selected=g.index.isin(chosen)
 warnings=(selected & g['disagreement'].gt(0).to_numpy()) if use_probe else selected
 harmful=g['default_definite_errors'].gt(0).to_numpy()
 return {'checked_windows':int(selected.sum()) if use_probe else 0,'selected_windows':int(selected.sum()),'probe_used':use_probe,'warnings':int(warnings.sum()),
  'harmful_windows':int(harmful.sum()),'harmful_windows_warned':int((warnings&harmful).sum()),
  'harmful_windows_unwarned':int((~warnings&harmful).sum()),
  'warnings_without_definite_default_error':int((warnings&~harmful).sum()),
  'helpful_units_exposed':int(g.loc[warnings,'helpful_units'].sum()),
  'default_errors_in_checked_windows':int(g.loc[selected,'default_definite_errors'].sum()),
  'selected_disagreement_units':int(g.loc[selected,'disagreement'].sum())}


def null_invariance(left,avleft,right,avright):
 def indexed(rows,av):
  out={}
  for uid,r in rows.items():
   if r['ks'] in out:raise Stop('Null control has duplicate reference keys')
   out[r['ks']]=([r[c] for c in F[:-1]],r['proto'],av[uid])
  return out
 a=indexed(left,avleft);b=indexed(right,avright)
 if set(a)!=set(b):raise Stop('Null replay changed the extracted key population')
 bad=0
 for k in a:
  if a[k][1]!=b[k][1] or not np.allclose(a[k][0],b[k][0],atol=1e-9,rtol=1e-9) or not np.isclose(a[k][2],b[k][2],atol=1e-6,rtol=0):bad+=1
 if bad:raise Stop('Null replay changed features or availability for '+str(bad)+' records')
 return {'status':'NULL_INVARIANCE_PASSED','records':len(a),'changed_records':bad}

def run_pilot():
 if not W.is_dir() or not RAW.is_dir():raise Stop('Run in Kaggle with the original IoT-23 mount attached.')
 if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free space required.')
 js(OUT/'PRE_OUTCOME_PROTOCOL.json',{'config':CFG,'runtime_labels_used':False,'sample_policy':'lowest key SHA256 among complete supported clean-reference units before labels/model outputs',
  'stress':'delay all packets after the first in complete observed TCP reference units; no label-based targeting; controlled measurement stress, not functionality-preserving host evasion',
  'main_target':'security decision on the same original labelled traffic unit by window-end plus fixed grace',
  'runtime_observation':'shadow-extractor information pilot; selection scores use only default records available by window end',
  'budget_experiment':'retrospective label-free ranking simulation, NOT causal online scheduling or measured on-demand speedup',
  'alternate_answer_is_ground_truth':False,'offline_labels':'primary published labels with exact stable-core linkage; incomplete labels remain unscored',
  'scope':'fresh exposed-data development; no independent confirmation or deployment claim'})
 models=model_bank();binary=zeek_binary();resources=[];unit_results=[];window_results=[];capture_receipts=[]
 for capture in CFG['captures']:
  d=OUT/f'capture_{capture}';d.mkdir();scratch=d/'scratch';scratch.mkdir()
  cr={'capture':capture,'status':'STARTED'}
  try:
   scenario=f'CTU-IoT-Malware-Capture-{capture}-1'
   candidates=[p for p in RAW.rglob('*.pcap') if scenario in p.parts]
   published=[p for p in RAW.rglob('conn.log.labeled') if scenario in p.parts]
   if not candidates or len(published)!=1:raise Stop('Original capture or unique published log unavailable')
   raw=max(candidates,key=lambda p:p.stat().st_size);h,e,u,link=header(raw)
   records=[];groups0=defaultdict(list);size=24
   for i,ts,cap,wire,payload,off in packets(raw):
    if size+16+cap>CFG['prefix_MiB']*1024**2 or len(records)>=CFG['max_packets']:break
    j=len(records);records.append((ts,cap,wire,payload));size+=16+cap
    fp=fingerprint(ts,ip_packet(payload,link))
    if fp is not None:groups0[fp].append(j)
   if not records:raise Stop('Empty declared prefix')
   origin=min(x[0] for x in records)/1e9;end=max(x[0] for x in records)/1e9
   if end-origin<=CFG['tail_seconds']+CFG['window_seconds']:raise Stop('Insufficient time span in fixed prefix; no budget enlarged')
   cleanpcap=scratch/'clean.pcap';write_pcap(cleanpcap,h,e,u,records)
   js(d/'raw_identity.json',{'source_path':str(raw),'prefix_bytes':size,'prefix_packets':len(records),'prefix_sha256':sha(cleanpcap),'span_seconds':end-origin})
   r0,ev0,av0,sec0=replay(binary,cleanpcap,scratch/'delay0_timeout5',5)
   resources.append({'capture':capture,'delay':0,'timeout':5,'seconds':sec0,'prefix_bytes':size})
   if capture==CFG['captures'][0]:
    rn,en,an,sn=replay(binary,cleanpcap,scratch/'null_repeat_timeout5',5)
    js(d/'null_invariance.json',null_invariance(r0,av0,rn,an))
    resources.append({'capture':capture,'delay':0,'timeout':5,'seconds':sn,'prefix_bytes':size,'role':'NULL_REPEAT'})
    del rn,en,an;shutil.rmtree(scratch/'null_repeat_timeout5')
   refowner,amb=group_map(groups0,ev0);count=Counter(refowner.values())
   pd.DataFrame({'packet_index':list(refowner),'reference_uid':list(refowner.values())}).to_csv(d/'reference_packet_UIDs.csv.gz',index=False,compression='gzip')
   eligible={k for k,n in count.items() if k in r0 and r0[k]['proto']=='tcp' and n>=2 and n==int(r0[k]['orig_pkts']+r0[k]['resp_pkts'])}
   panel_candidates={k:r for k,r in r0.items() if k in count and count[k]==int(r['orig_pkts']+r['resp_pkts']) and r['proto'] in ['tcp','udp'] and 0<count[k]<=64 and r['ts']<end-CFG['tail_seconds']}
   selected=sorted(panel_candidates,key=lambda k:panel_candidates[k]['ks'])[:CFG['reference_units']]
   panel={k:panel_candidates[k] for k in selected}
   if len(panel)<64:raise Stop('Fewer than 64 fully mapped reference units in fixed prefix')
   pd.DataFrame(panel.values()).to_csv(d/'reference_panel_BEFORE_LABELS.csv.gz',index=False,compression='gzip')
   keys=list(panel);first_idx={}
   for i,k in sorted(refowner.items()):first_idx.setdefault(k,i)
   labels,scanned=label_panel(published[0],panel)
   js(d/'label_linkage.json',{'panel_units':len(panel),'matched_labels':len(labels),'benign':sum(v==0 for v in labels.values()),'malicious':sum(v==1 for v in labels.values()),'rows_scanned':scanned,'unmatched_units_not_guessed':len(panel)-len(labels)})
   for delay in CFG['conditions_seconds']:
    delta=np.zeros(len(records),dtype=np.int64)
    if delay:
     for i,k in refowner.items():
      if k in eligible and i!=first_idx[k]:delta[i]=delay*10**9
    timestamps=np.array([r[0] for r in records],dtype=np.int64)+delta
    groups=defaultdict(list)
    for fp,indices in groups0.items():
     for i in indices:groups[((int(timestamps[i])+500)//1000,*fp[1:])].append(i)
    pcap=cleanpcap if delay==0 else scratch/f'paced{delay}.pcap'
    if delay:write_pcap(pcap,h,e,u,records,delta)
    treatment_sha=sha(pcap)
    states={}
    for timeout in CFG['timeouts_seconds']:
     if delay==0 and timeout==5:rows,events,available,seconds=r0,ev0,av0,sec0
     else:
      rows,events,available,seconds=replay(binary,pcap,scratch/f'delay{delay}_timeout{timeout}',timeout)
      resources.append({'capture':capture,'delay':delay,'timeout':timeout,'seconds':seconds,'prefix_bytes':size})
     owners,pure,complete=condition_map(groups,events,refowner,rows)
     states[timeout]={'rows':rows,'available':available,'owners':owners,'pure':pure,'complete':complete}
     js(d/f'delay{delay}_timeout{timeout}_accounting.json',{'original_packet_count':len(records),'PCAP_sha256':treatment_sha,'reference_units':len(panel),'complete_panel_memberships':sum(complete.get(k,False) for k in keys),'pure_UIDs':sum(pure.values()),'replay_seconds':seconds})
     if timeout!=5:del events
    current_start={k:float(timestamps[first_idx[k]])/1e9 for k in keys}
    windows={k:int((current_start[k]-origin)//CFG['window_seconds']) for k in keys}
    deadline={k:origin+(windows[k]+1)*CFG['window_seconds']+CFG['decision_grace_seconds'] for k in keys}
    validkeys=[k for k in keys if deadline[k]<=end-CFG['tail_seconds']+CFG['decision_grace_seconds']]
    for family,model in models.items():
     outputs={};probs={}
     with threadpool_limits(limits=2):
      for timeout,st in states.items():
       frame=pd.DataFrame(st['rows'].values())
       if len(frame)==0:raise Stop('No compatible re-extracted records')
       pp=model.predict_proba(encode(frame))[:,1]
       if not np.isfinite(pp).all():raise Stop('Nonfinite frozen-model predictions')
       pr=dict(zip(frame.uid,pp));probs[timeout]=pr
       outputs[timeout]=bound_decisions(validkeys,st['owners'],st['pure'],st['complete'],{k:v>=.5 for k,v in pr.items()},st['available'],deadline)
     local=[]
     for k in validkeys:
      a,b=outputs[5][k],outputs[15][k];lab=labels.get(k)
      definite_flip=a[0]==a[1] and b[0]==b[1] and a[0]!=b[0]
      er0=lab is not None and a[0]==a[1] and a[0]!=lab
      er1=lab is not None and b[0]==b[1] and b[0]!=lab
      helpful=bool(lab is not None and er0 and b[0]==b[1] and b[0]==lab)
      harmful_switch=bool(lab is not None and a[0]==a[1] and a[0]==lab and er1)
      rr={'capture':capture,'condition_seconds':delay,'family':family,'ks':panel[k]['ks'],'window':windows[k],
       'label':lab,'default_lower':a[0],'default_upper':a[1],'alternate_lower':b[0],'alternate_upper':b[1],
       'definite_flip':bool(definite_flip),'default_definite_error':bool(er0),'alternate_definite_error':bool(er1),
       'helpful_disagreement':helpful,'harmful_alternate_switch':harmful_switch,'timing_stress_eligible':k in eligible}
      local.append(rr);unit_results.append(rr)
     lu=pd.DataFrame(local)
     if lu.empty:continue
     for wi,g in lu.groupby('window',sort=True):
      begin=origin+wi*CFG['window_seconds'];finish=begin+CFG['window_seconds']
      score=selector_score(states[5]['rows'],states[5]['available'],probs[5],begin,finish,REFERENCE_RATES[family])
      window_results.append({'capture':capture,'condition_seconds':delay,'family':family,'window':int(wi),
       'units':len(g),'labelled_units':int(g.label.notna().sum()),'malicious_units':int(g.label.eq(1).sum()),'benign_units':int(g.label.eq(0).sum()),
       'disagreement':int(g.definite_flip.sum()),'default_definite_errors':int(g.default_definite_error.sum()),
       'helpful_units':int(g.helpful_disagreement.sum()),'harmful_alternate_units':int(g.harmful_alternate_switch.sum()),
       'unresolved_default_units':int(g.default_lower.ne(g.default_upper).sum()),'unresolved_alternate_units':int(g.alternate_lower.ne(g.alternate_upper).sum()),**score})
     print('CAPTURE',capture,'condition',delay,'family',family,'units',len(lu),'labels',int(lu.label.notna().sum()),'flips',int(lu.definite_flip.sum()),'helpful',int(lu.helpful_disagreement.sum()),flush=True)
    pd.DataFrame(unit_results).to_csv(OUT/'experiment1_unit_decisions.csv.gz',index=False,compression='gzip')
    pd.DataFrame(window_results).to_csv(OUT/'experiment2_window_information.csv',index=False)
    del states
    if delay:pcap.unlink()
    # Keep compact receipts, not the verbose event and conn logs of successful replays.
    for rd in scratch.glob(f'delay{delay}_timeout*'):
     if rd.is_dir() and not (delay==0 and rd.name.endswith('timeout5')):shutil.rmtree(rd)
   cr.update({'status':'CAPTURE_PILOT_COMPLETE','panel_units':len(panel),'matched_labels':len(labels),'fully_mapped_TCP_units_eligible_for_stress':len(eligible),'ambiguous_clean_packet_occurrences':amb})
   shutil.rmtree(scratch);cr['only_this_run_scratch_removed']=True
  except Exception as ex:
   cr.update({'status':'BLOCKED_OR_FAILED','reason':str(ex)})
   (d/'error.txt').write_text(traceback.format_exc())
   print('CAPTURE',capture,'STOPPED:',ex,flush=True)
  finally:
   js(d/'receipt.json',cr);capture_receipts.append(cr)
   pd.DataFrame(resources).to_csv(OUT/'replay_resources.csv',index=False)
   js(OUT/'capture_progress.json',capture_receipts);gc.collect()
 if not window_results:raise Stop('No evaluable windows. Read capture_progress.json; no scientific conclusion produced.')
 wf=pd.DataFrame(window_results);policy=[];rng=np.random.default_rng(CFG['seed'])
 for (capture,condition,family),g in wf.groupby(['capture','condition_seconds','family'],sort=True):
  for budget in CFG['policy_budgets']:
   n=max(1,int(math.floor(len(g)*budget)))
   common={'capture':capture,'condition_seconds':condition,'family':family,'budget_fraction':budget,'total_windows':len(g),'requested_checks':n}
   for name,field in [('LOW_CONFIDENCE','low_confidence'),('BOUNDARY_PRESSURE','boundary_pressure'),('TRAFFIC_LOAD','traffic_change'),('POSITIVE_RATE_SHIFT','positive_rate_shift')]:
    chosen=g.sort_values([field,'window'],ascending=[False,True],kind='stable').index[:n]
    policy.append({**common,'policy':name,'repetition':0,**evaluate_policy(g,chosen)})
    policy.append({**common,'policy':name+'_PASSIVE_ESCALATION','repetition':0,**evaluate_policy(g,chosen,use_probe=False)})
   for rep in range(CFG['random_schedules']):
    chosen=rng.choice(g.index.to_numpy(),n,replace=False)
    policy.append({**common,'policy':'RANDOM','repetition':rep,**evaluate_policy(g,chosen)})
 pf=pd.DataFrame(policy);pf.to_csv(OUT/'experiment3_equal_check_count_policies.csv',index=False)
 summary=pf.groupby(['capture','condition_seconds','family','budget_fraction','policy'],as_index=False).agg(
  simulations=('repetition','size'),checks=('checked_windows','mean'),warnings=('warnings','mean'),
  helpful_units_exposed=('helpful_units_exposed','mean'),harmful_windows_warned=('harmful_windows_warned','mean'),
  harmful_windows_unwarned=('harmful_windows_unwarned','mean'),warnings_without_definite_error=('warnings_without_definite_default_error','mean'))
 summary.to_csv(OUT/'experiment3_policy_summary.csv',index=False)
 totals=wf.groupby(['capture','condition_seconds','family'],as_index=False).agg(windows=('window','size'),labelled_units=('labelled_units','sum'),
  default_errors=('default_definite_errors','sum'),helpful_units=('helpful_units','sum'),definite_flips=('disagreement','sum'),harmful_alternate_units=('harmful_alternate_units','sum'))
 totals.to_csv(OUT/'DECISION_INFORMATION_TABLE.csv',index=False)
 # Gate uses one predeclared primary family; never counts two models/conditions as independent captures.
 primary=totals[totals.family.eq('HGB')]
 informative=sorted(primary.loc[primary.helpful_units.ge(CFG['minimum_helpful_units']),'capture'].unique().tolist())
 complete=sum(r['status']=='CAPTURE_PILOT_COMPLETE' for r in capture_receipts)
 if complete<len(CFG['captures']):decision='INCOMPLETE_EXECUTION_NO_SCIENTIFIC_DECISION'
 elif primary.labelled_units.sum()==0:decision='INSUFFICIENT_LABEL_LINKAGE'
 elif primary.default_errors.sum()<CFG['minimum_helpful_units']:decision='INSUFFICIENT_DEFAULT_ERRORS_TO_TEST_ERROR_DISCOVERY'
 elif primary.helpful_units.sum()==0:decision='NO_HELPFUL_REMEASUREMENT_OBSERVED_IN_DECLARED_PILOT'
 elif len(informative)<CFG['minimum_informative_captures']:decision='LOCAL_SIGNAL_ONLY_NOT_ENOUGH_TO_BUILD_SCHEDULER'
 else:decision='INFORMATION_GATE_PASSED_TEST_CAUSAL_BUDGETED_IMPLEMENTATION_NEXT'
 receipt={'status':'PILOT_FINISHED','decision':decision,'informative_captures_primary_HGB':informative,'capture_outcomes':capture_receipts,
  'total_replay_count':len(resources),'new_model_fits':0,'runtime_labels_used':False,
  'online_policy_or_online_speedup_validated':False,'novelty_established':False,'independent_confirmation':False,
  'limits':['Bounded prefixes and key-ranked panels, not full-corpus prevalence.',
   'Fixed detector sensitivity: alternative outputs are not ground truth.',
   'A harmful event is a definite default-unit error, not proof of a successful malicious application.',
   'Label-free ranking uses recorded window scores retrospectively; no causal scheduler or measured budget savings claimed.',
   'Amortized full-replay time is NOT the runtime of an on-demand window probe.',
   'No helpful signal here does not prove all future measurement policies impossible.'],
  'output_directory':str(OUT)}
 print('\nEXPERIMENTS 1/2 — INFORMATION TABLE\n'+totals.to_string(index=False),flush=True)
 print('\nEXPERIMENT 3 — EQUAL-CHECK BUDGETS\n'+summary[summary.budget_fraction.eq(.25)].to_string(index=False),flush=True)
 js(OUT/'receipt.json',receipt);return receipt

REPORT={}
try:REPORT=run_pilot()
except Exception as ex:
 REPORT={'status':'STOPPED_WITH_EXACT_REASON','reason':str(ex),'output_directory':str(OUT),'scientific_decision':'NOT_ESTABLISHED'}
 (OUT/'error.txt').write_text(traceback.format_exc());js(OUT/'receipt.json',REPORT)
finally:
 package=OUT/'PRIVATE_pilot_code_and_small_results.zip'
 source=globals().get('__file__')
 if source and Path(source).is_file():shutil.copyfile(source,OUT/'executed_pilot.py')
 with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(OUT.rglob('*')):
   if p.is_file() and 'scratch' not in p.relative_to(OUT).parts and p!=package and p.stat().st_size<128*1024**2:z.write(p,str(p.relative_to(OUT)))
 with zipfile.ZipFile(package) as z:
  bad=z.testzip()
  if bad:raise RuntimeError('Checkpoint CRC failure: '+bad)
 print('\nPILOT RECEIPT\n'+json.dumps(REPORT,indent=2),flush=True)
 print('Verified private checkpoint:',package,'SHA256:',sha(package),flush=True)
