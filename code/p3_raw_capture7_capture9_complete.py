# P3 raw-data extension, batch 1: captures 7 and 9; no new model fitting.
# Fixed frozen five-seed source bank, clean / 1s / 10s, one declared intake policy.
# Ineligible timing actions remain identity cases. This is development evidence.
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from contextlib import contextmanager
from decimal import Decimal, ROUND_HALF_EVEN
import gzip, hashlib, heapq, io, ipaddress, json, math, os, re, shutil, socket, sqlite3, struct, subprocess, sys, time, traceback, urllib.request, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
PRIMARY=Path('/kaggle/input/datasets/mdhamidborkottulla/batch5');W=Path('/kaggle/working')
CAPTURES=[7,9]
PREFIX_MIB={7:128,9:128,33:128,36:512,39:512,43:128}
LABEL_ROW_LIMIT=4_000_000;N=512;TAIL=120
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SEEDS=[8101,8102,8103,8104,8105];POLICIES=['GROUP_DISJOINT','ROW_FIT_CAL_CONTROL'];THRESHOLD=.05
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
OUT=W/('P3_RAW_CAPTURE7_CAPTURE9_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(parents=True,exist_ok=False)
R={'status':'STARTED','captures_declared':CAPTURES,'model_fits':0,'calibrator_fits':0,'PCAP_replays':0,
   'independent_confirmation':False,'target_outcome_based_selection':False,'completed_captures':[],
   'historical_results_overwritten':False,'output_directory':str(OUT)}
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
def endpoint(r):return (tuple(sorted([(r['id.orig_h'],int(r['id.orig_p'])),(r['id.resp_h'],int(r['id.resp_p']))])),r['proto'].lower())
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

class Sample:
    def __init__(self,n,salt):self.n=n;self.salt=salt;self.heap=[];self.rows={}
    def add(self,k,r):
        if k in self.rows:
            if self.rows[k]['y']!=r['y'] or any(self.rows[k][c]!=r[c] for c in F):raise Stop('Conflicting selected original labels/features')
            return
        rank=int(hashlib.sha256((self.salt+'|'+k).encode()).hexdigest(),16)
        if len(self.heap)<self.n:heapq.heappush(self.heap,(-rank,k));self.rows[k]=r
        elif rank < -self.heap[0][0]:
            _,old=heapq.heapreplace(self.heap,(-rank,k));self.rows.pop(old);self.rows[k]=r
    def values(self):return [self.rows[k] for _,k in sorted(self.heap,key=lambda x:(-x[0],x[1]))]

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
def logit(p):
    p=np.clip(p,1e-6,1-1e-6);return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def norm_source(df):
    df=df.copy()
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid source feature')
    df['proto']=df.proto.str.lower();df['y']=pd.to_numeric(df.y,errors='raise').astype(int)
    if not set(df.y).issubset({0,1}):raise Stop('Invalid source labels')
    return df

def atc(conf,correct):
    n=int(np.asarray(correct,bool).sum())
    if n==0:return float(np.nextafter(conf.max(),np.inf)),0.
    t=float(np.sort(conf)[::-1][n-1]);alpha=(n-int((conf>t).sum()))/int((conf==t).sum())
    if not 0<=alpha<=1:raise Stop('Invalid ATC ties')
    return t,float(alpha)

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
    command(['apt-get','-o','Acquire::Retries=2','update'],'zeek_apt_update.txt',600)
    r=subprocess.run(['apt-cache','madison','zeek-8.0'],capture_output=True,text=True,timeout=30)
    versions=[x.split('|')[1].strip() for x in r.stdout.splitlines() if len(x.split('|'))>=2 and re.match(r'(?:\d+:)?8\.0\.10(?:$|[-+~])',x.split('|')[1].strip())]
    if not versions:raise Stop('Exact Zeek 8.0.10 package unavailable; no substitute installed')
    command(['apt-get','-y','--no-install-recommends','install','zeek-8.0='+versions[0]],'zeek_install.txt',900)
    p,v=find()
    if not p:raise Stop('Installed executable did not verify as Zeek 8.0.10')
    return p,v

def getfile(root,name):
    variants=[name]+([name[:-3]] if name.endswith('.gz') else [])
    for n in variants:
        p=root/n
        if p.is_file():return p
    raise Stop('Required frozen-bank input missing: '+str(root/name))

def model_bank():
    candidates=[]
    for root in [W,PRIMARY]:
        if not root.is_dir():continue
        for p in root.glob('CONTROLLED_FIVE_SEED_SOURCE_SPLIT_*'):
            rp=p/'receipt.json'
            if rp.is_file():
                r=json.loads(rp.read_text())
                if r.get('status')=='CONTROLLED_FIVE_SEED_SOURCE_SPLIT_BANK_COMPLETE':candidates.append(p)
    if not candidates:raise Stop('The completed five-model-seed source bank must be attached or present in working')
    base=max(candidates,key=lambda p:p.name);bankfile=getfile(base,'five_seed_models_and_calibrators.joblib');bank=joblib.load(bankfile)
    expected={(p,f,s) for p in POLICIES for f in ['HGB','LR'] for s in SEEDS}
    if set(bank['models'])!=expected or set(bank['calibrators'])!=expected:raise Stop('Five-seed bank schema differs')
    sp=getfile(base,'source_panel_with_network_groups.csv.gz')
    with open(sp,'rb') as f:compressed=f.read(2)==b'\x1f\x8b'
    source=norm_source(pd.read_csv(sp,compression='gzip' if compressed else None,dtype=str,keep_default_na=False))
    params={}
    with threadpool_limits(limits=2):
        for policy in POLICIES:
            cal=source.iloc[bank['source_roles'][policy]['calibration']]
            for family in ['HGB','LR']:
                for seed in SEEDS:
                    model=bank['models'][(policy,family,seed)]
                    if list(model.classes_)!=[0,1]:raise Stop('Unexpected primary class order')
                    p=model.predict_proba(encode(cal))[:,1];c=np.maximum(p,1-p);correct=(p>=.5)==cal.y.to_numpy()
                    t,alpha=atc(c,correct);params[(policy,family,seed)]={'accuracy':float(correct.mean()),'confidence':float(c.mean()),'threshold':t,'alpha':alpha}
    shutil.copyfile(bankfile,OUT/'frozen_five_seed_bank.joblib')
    js(OUT/'frozen_calibration_parameters.json',[{'policy':k[0],'family':k[1],'seed':k[2],**v} for k,v in params.items()])
    js(OUT/'bank_binding.json',{'source_run':str(base),'model_bank_sha256':sha(bankfile),'protocol':bank['protocol'],'source_panel_sha256':sha(sp)})
    return bank,params

def make_checkpoint(case_dirs,name):
    p=OUT/name;entries=[]
    with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for item in OUT.iterdir():
            if item.is_file() and item!=p and item.suffix.lower()!='.zip':
                z.write(item,arcname=item.name);entries.append({'member':item.name,'sha256':sha(item)})
        for folder in case_dirs:
            for item in folder.iterdir():
                if item.is_file() and item.suffix.lower()!='.zip':
                    rel=str(item.relative_to(OUT));z.write(item,arcname=rel);entries.append({'member':rel,'sha256':sha(item)})
        z.writestr('ARCHIVE_FILE_MANIFEST.json',json.dumps(entries,indent=2))
    with zipfile.ZipFile(p) as z:
        for e in entries:
            h=hashlib.sha256()
            with z.open(e['member']) as f:
                for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
            if h.hexdigest()!=e['sha256']:raise Stop('Checkpoint hash mismatch')
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p),'members_verified':len(entries),'private_only':True,'raw_PCАPs_included':False}

case_dirs=[];case_ledger=[];all_targets=[];all_monitors=[]
try:
    if not RAW.is_dir():raise Stop('Original IoT-23 mount missing')
    if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free is required')
    js(OUT/'pre_outcome_protocol.json',{'captures':CAPTURES,'all_planned_new_capture_budgets_MiB':PREFIX_MIB,
        'published_log_max_rows_per_capture':LABEL_ROW_LIMIT,'source_models_frozen':True,'conditions':[0,1,10],
        'cohort':'512 benign + 512 IPv4 TCP/UDP malicious units, 1..64 total packets, from unique stable-core links',
        'sampling':'lowest SHA256 ranks within fixed byte-prefix and published-row budget',
        'tail_margin_seconds':TAIL,'pacing_eligibility':'fully mapped TCP unit with >=2 total packets; all others retained unchanged',
        'pacing':'delay all eligible-unit packets after first, preserving bytes and within-unit order',
        'lineage_fingerprint':'timestamp_us + IPv4 src,dst,id,length + connection transport; collision classes unresolved',
        'row_budget_failure':'insufficient within declared intake budget, not proof capture has no eligible records',
        'target_labels_used_for_model_or_calibrator_fitting':False,'exposed_data_development':True,'independent_confirmation':False})
    bank,params=model_bank();zeek,version=ensure_zeek();R['zeek_version']=version
    for capture in CAPTURES:
        scenario=f'CTU-IoT-Malware-Capture-{capture}-1';folder=OUT/scenario;folder.mkdir();case_dirs.append(folder)
        C={'capture':capture,'status':'STARTED','new_PCAP_replays':0};scratch=None;db=None
        try:
            budget=PREFIX_MIB[capture]*1024**2
            if shutil.disk_usage(W).free<max(4*1024**3,budget*8+1024**3):raise Stop('Insufficient conservative per-capture reserve')
            files=[p for p in RAW.rglob('*') if p.is_file() and scenario in p.parts]
            pcaps=[p for p in files if p.suffix.lower()=='.pcap'];published=[p for p in files if p.name=='conn.log.labeled']
            if not pcaps or len(published)!=1:raise Stop('Original PCAP or unique published log missing')
            raw_pcap=max(pcaps,key=lambda p:p.stat().st_size);published=published[0]
            scratch=folder/'scratch';scratch.mkdir();prefix=scratch/'prefix.pcap';h,endian,unit,link=header(raw_pcap)
            size=24;packet_count=0;max_ts=0
            with open(prefix,'wb') as dst:
                dst.write(h)
                for idx,ts,cap,wire,b,off in packets(raw_pcap):
                    if size+16+cap>budget:break
                    dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(b)
                    size+=16+cap;packet_count+=1;max_ts=max(max_ts,ts)
            if not packet_count:raise Stop('Empty raw prefix')
            prefix_hash=sha(prefix)
            js(folder/'raw_inputs.json',{'pcap':str(raw_pcap),'published_log':str(published),'prefix_sha256':prefix_hash,'prefix_bytes':size,'prefix_packets':packet_count})
            print('\nCAPTURE',capture,'— fixed raw intake, no model-outcome selection.',flush=True)
            def replay(path,name,tap=None):
                d=scratch/name;d.mkdir();cmd=[zeek,'-C','-r',str(path)]
                if tap:cmd.append(str(tap))
                C['new_PCAP_replays']+=1;R['PCAP_replays']+=1;t=time.perf_counter()
                with open(folder/f'{name}_events.txt','w') as so,open(folder/f'{name}_stderr.txt','w') as se:
                    result=subprocess.run(cmd,cwd=d,stdout=so,stderr=se,timeout=1800)
                if result.returncode or not (d/'conn.log').is_file():raise Stop('Zeek failed: '+name)
                return d,time.perf_counter()-t
            intake,_=replay(prefix,'intake');cutoff=max_ts/1e9-TAIL
            db=sqlite3.connect(scratch/'clean.sqlite');db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA cache_size=-32768')
            db.execute('CREATE TABLE c(k TEXT PRIMARY KEY,payload TEXT,n INTEGER)');batch=[]
            for row in logs(intake/'conn.log'):
                try:f=features(row);kk=record_key(row)
                except (ValueError,KeyError):continue
                if float(row['ts'])+f['duration']>cutoff:continue
                rr={**f,'uid':row['uid'],'ts':row['ts'],'id.orig_h':row['id.orig_h'],'id.orig_p':row['id.orig_p'],'id.resp_h':row['id.resp_h'],'id.resp_p':row['id.resp_p']}
                batch.append((kk,json.dumps(rr,separators=(',',':')),1))
                if len(batch)>=10000:db.executemany('INSERT INTO c VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',batch);batch=[]
            if batch:db.executemany('INSERT INTO c VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',batch)
            db.commit();samplers={yy:Sample(N,f'P3_RAW_EXTENSION_V1|{capture}|{yy}') for yy in [0,1]};counts=Counter();scanned=0;exhausted=True
            for row in logs(published,True):
                scanned+=1
                if scanned>LABEL_ROW_LIMIT:exhausted=False;break
                label=row['label'].lower()
                if label not in ['benign','malicious']:continue
                try:
                    if float(row['ts'])>cutoff:continue
                    kk=record_key(row);pf=features(row)
                except (ValueError,KeyError):continue
                hit=db.execute('SELECT payload,n FROM c WHERE k=?',(kk,)).fetchone()
                if hit is None or hit[1]!=1:continue
                rr=json.loads(hit[0])
                if pf['proto']!=rr['proto'] or not np.allclose([pf[c] for c in F[:-1]],[rr[c] for c in F[:-1]],atol=1e-9,rtol=1e-9):continue
                yy=int(label=='malicious');counts[f'stable_class_{yy}']+=1
                if yy:
                    try:v4=ipaddress.ip_address(rr['id.orig_h']).version==4 and ipaddress.ip_address(rr['id.resp_h']).version==4
                    except ValueError:v4=False
                    if not(v4 and rr['proto'] in ['tcp','udp'] and 1<=rr['orig_pkts']+rr['resp_pkts']<=64):continue
                counts[f'supported_class_{yy}']+=1;samplers[yy].add(kk,{**rr,'ks':kk,'y':yy})
            db.close();db=None
            intake_result={'counts':dict(counts),'published_rows_scanned':min(scanned,LABEL_ROW_LIMIT),'full_published_log_exhausted':exhausted,'fixed_label_row_limit':LABEL_ROW_LIMIT}
            js(folder/'intake_counts.json',intake_result);print('INTAKE:',intake_result,flush=True)
            if any(len(samplers[yy].rows)!=N for yy in [0,1]):
                C['status']='INSUFFICIENT_UNDER_DECLARED_INTAKE_POLICY';C['reason']='Fewer than 512 supported stable-linked records per class; no eligibility or budget relaxed'
                case_ledger.append(C);js(folder/'receipt.json',C);continue
            clean=pd.DataFrame(samplers[0].values()+samplers[1].values())
            if clean.ks.duplicated().any():raise Stop('Conflicting cohort keys')
            clean.to_csv(folder/'clean_cohort.csv.gz',index=False,compression='gzip')
            keys=list(clean.ks);wanted=set(keys);ci=clean.set_index('ks');y=clean.y.to_numpy(int);mk=list(clean.loc[y==1,'ks'])
            watched=set();endpoint_sets={endpoint(ci.loc[k]) for k in mk};host_pairs={tuple(sorted([ci.loc[k,'id.orig_h'],ci.loc[k,'id.resp_h']])) for k in mk}
            for k in mk:
                r=ci.loc[k];proto=r.proto
                watched.add(f"{r['id.orig_h']}|{r['id.orig_p']}/{proto}|{r['id.resp_h']}|{r['id.resp_p']}/{proto}")
                watched.add(f"{r['id.resp_h']}|{r['id.resp_p']}/{proto}|{r['id.orig_h']}|{r['id.orig_p']}/{proto}")
            entries=',\n'.join(json.dumps(x) for x in sorted(watched))
            tap="""@load base/protocols/conn
const watched: set[string] = {ENTRIES};
global watched_uids: set[string] = set();
event new_packet(c: connection, p: pkt_hdr)
    {
    if ( ! p?$ip ) return;
    local k = fmt("%s|%s|%s|%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    if ( k !in watched ) return;
    add watched_uids[c$uid];
    print fmt("IPPACKET|%.6f|%s|%s|%s|%d|%d|%s", network_time(), c$uid, p$ip$src, p$ip$dst, p$ip$id, p$ip$len, get_port_transport_proto(c$id$orig_p));
    }
event Conn::log_conn(rec: Conn::Info)
    { if ( rec$uid in watched_uids ) print fmt("AVAILABLE|%.6f|%s", network_time(), rec$uid); }
""".replace('ENTRIES',entries)
            tap_path=folder/'packet_membership.zeek';tap_path.write_text(tap)
            check=subprocess.run([zeek,'-b',str(tap_path)],cwd=folder,capture_output=True,text=True,timeout=30)
            (folder/'compile_stderr.txt').write_text(check.stderr)
            if check.returncode:raise Stop('IPv4 packet instrumentation did not compile')
            raw_groups=defaultdict(list);packet_fingerprint={}
            for idx,ts,cap,wire,b,off in packets(prefix):
                info=ip_packet(b,link)
                if info is None:continue
                src,dst,ident,length,proto,ports=info
                relevant=((tuple(sorted([(src,ports[0]),(dst,ports[1])])),proto) in endpoint_sets) if ports else tuple(sorted([src,dst])) in host_pairs
                if relevant:
                    fp=((ts+500)//1000,src,dst,ident,length,proto);raw_groups[fp].append(idx);packet_fingerprint[idx]=fp
            d0,_=replay(prefix,'clean_instrumented',tap_path)
            def parse_events(name):
                event=defaultdict(list);available={}
                with open(folder/f'{name}_events.txt') as f:
                    for line in f:
                        if line.startswith('AVAILABLE|'):
                            x=line.rstrip('\r\n').split('|')
                            if len(x)!=3:raise Stop('Availability event schema differs')
                            tt=us(x[1]);available[x[2]]=min(tt,available.get(x[2],tt))
                        elif line.startswith('IPPACKET|'):
                            x=line.rstrip('\r\n').split('|')
                            if len(x)!=8:raise Stop('IP packet event schema differs')
                            fp=(us(x[1]),x[3],x[4],int(x[5]),int(x[6]),x[7]);event[fp].append(x[2])
                return event,available
            clean_events,clean_available=parse_events('clean_instrumented')
            if not clean_events:raise Stop('No cohort packet events; do not infer successful tracking')
            selected_tuples={(str(r['id.orig_h']),int(r['id.orig_p']),str(r['id.resp_h']),int(r['id.resp_p']),r['proto']) for r in clean.to_dict('records')}
            def selected_rows(path,needed_uids=None):
                selected={};records={};ambiguous_keys=set()
                for row in logs(path):
                    try:identity=(row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower())
                    except ValueError:continue
                    if identity in selected_tuples:
                        kk=record_key(row)
                        if kk in wanted:
                            if kk in selected:ambiguous_keys.add(kk)
                            selected[kk]={**features(row),'ks':kk,'y':int(ci.loc[kk,'y']),'uid':row['uid']}
                    if needed_uids is not None and row['uid'] in needed_uids:
                        if row['uid'] in records:raise Stop('Duplicate UID feature record')
                        records[row['uid']]={**features(row),'uid':row['uid']}
                for kk in ambiguous_keys:selected.pop(kk,None)
                return selected,records
            selected0,_=selected_rows(d0/'conn.log')
            if set(selected0)!=wanted:raise Stop('Clean original-start coverage is incomplete')
            fresh0=pd.DataFrame([selected0[k] for k in keys])
            if not np.allclose(fresh0[F[:-1]].to_numpy(float),clean[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(fresh0.proto,clean.proto):raise Stop('Instrumented clean features changed')
            uid_parent={selected0[k]['uid']:k for k in mk};packet_owner={};seen=Counter();source_class_owner={}
            for fp,indices in raw_groups.items():
                uids=clean_events.get(fp,[])
                if len(indices)==len(uids) and len(set(uids))==1:
                    parent=uid_parent.get(uids[0]);source_class_owner[fp]=parent
                    if parent:
                        for idx in indices:packet_owner[idx]=parent;seen[parent]+=1
                else:source_class_owner[fp]='AMBIGUOUS_SOURCE'
            expected={k:int(ci.loc[k,'orig_pkts']+ci.loc[k,'resp_pkts']) for k in mk};uid_counts=Counter(u for vv in clean_events.values() for u in vv)
            clean_complete={k:bool(seen[k]==expected[k] and uid_counts[selected0[k]['uid']]==expected[k]) for k in mk}
            first={}
            for idx,k in sorted(packet_owner.items()):first.setdefault(k,idx)
            eligible={k for k in mk if clean_complete[k] and ci.loc[k,'proto']=='tcp' and expected[k]>=2}
            pd.DataFrame([{'ks':k,'expected_packets':expected[k],'UID_mapped_packets':seen[k],'clean_complete':clean_complete[k],
                           'pacing_eligible':k in eligible,'identity_if_ineligible':k not in eligible} for k in mk]).to_csv(folder/'cohort_feasibility.csv',index=False)
            C['pacing_eligible_units']=len(eligible);C['unmodified_original_units']=N-len(eligible)
            states={};state_proofs=[]
            for delay in [0,1,10]:
                identity=(delay==0 or not eligible);path=prefix;name='clean_instrumented';condition_dir=d0
                raw_expected=defaultdict(list)
                for fp,indices in raw_groups.items():
                    for idx in indices:
                        parent=packet_owner.get(idx);known=source_class_owner[fp]
                        label=parent if parent is not None else ('AMBIGUOUS_SOURCE' if known=='AMBIGUOUS_SOURCE' else None)
                        delta=delay*1000000 if parent in eligible and idx!=first[parent] else 0
                        fp_new=(fp[0]+delta,)+fp[1:];raw_expected[fp_new].append((idx,label))
                if not identity:
                    db=sqlite3.connect(scratch/'schedule.sqlite');db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA temp_store=FILE');db.execute('PRAGMA cache_size=-32768')
                    db.execute('CREATE TABLE p(ts INTEGER,idx INTEGER,off INTEGER,cap INTEGER,wire INTEGER)');batch=[];changed=0
                    for idx,ts,cap,wire,b,off in packets(prefix):
                        parent=packet_owner.get(idx);delta=delay*10**9 if parent in eligible and idx!=first[parent] else 0
                        batch.append((ts+delta,idx,off,cap,wire));changed+=int(delta>0)
                        if len(batch)>=50000:db.executemany('INSERT INTO p VALUES(?,?,?,?,?)',batch);batch=[]
                    if batch:db.executemany('INSERT INTO p VALUES(?,?,?,?,?)',batch)
                    db.commit();db.execute('CREATE INDEX ordered ON p(ts,idx)');db.commit();path=scratch/f'paced_{delay}s.pcap';written=0;last=-1;last_idx={}
                    with open(prefix,'rb') as src,open(path,'wb') as dst:
                        dst.write(h)
                        for ts,idx,off,cap,wire in db.execute('SELECT ts,idx,off,cap,wire FROM p ORDER BY ts,idx'):
                            if ts<last:raise Stop('Output packet times unordered')
                            last=ts;parent=packet_owner.get(idx)
                            if parent is not None:
                                if idx<=last_idx.get(parent,-1):raise Stop('Original-unit packet order changed')
                                last_idx[parent]=idx
                            src.seek(off);b=src.read(cap)
                            if len(b)!=cap:raise Stop('Incomplete packet copy')
                            dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(b);written+=1
                    db.close();db=None;(scratch/'schedule.sqlite').unlink()
                    if written!=packet_count:raise Stop('Packet count changed')
                    name=f'pacing_{delay}s';condition_dir,_=replay(path,name,tap_path)
                else:changed=0
                events,available=(clean_events,clean_available) if identity else parse_events(name)
                owners=defaultdict(set);uid_owner=defaultdict(set);tracked=Counter();mapped=Counter();bad=Counter();map_rows=[]
                for fp,uids in events.items():
                    if fp not in raw_expected:
                        for u in uids:uid_owner[u].add('UNINDEXED')
                for fp,occurrences in raw_expected.items():
                    uids=events.get(fp,[]);labels={k if k is not None else 'OUTSIDE_SELECTED' for _,k in occurrences}
                    if len(occurrences)==len(uids) and len(labels)==1 and 'AMBIGUOUS_SOURCE' not in labels:
                        parent=next(iter(labels))
                        for u,n in Counter(uids).items():
                            uid_owner[u].add(parent)
                            if parent!='OUTSIDE_SELECTED':mapped[parent]+=n;owners[parent].add(u);tracked[u]+=n
                            map_rows.append({'fingerprint_sha256':hashlib.sha256(repr(fp).encode()).hexdigest(),'original_ks':parent,'uid':u,'packet_occurrences':n})
                    else:
                        for _,parent in occurrences:
                            if parent in expected:bad[parent]+=1
                        for u in uids:uid_owner[u].add('AMBIGUOUS')
                needed=set().union(*owners.values()) if owners else set();selected,records=selected_rows(condition_dir/'conn.log',needed)
                if set(selected)!=wanted:raise Stop('Transformed original-start records missing; no synthetic rows inserted')
                sf=pd.DataFrame([selected[k] for k in keys]);uids=sorted(records);cf=pd.DataFrame([records[u] for u in uids],columns=F+['uid'])
                event_count=Counter(u for vv in events.values() for u in vv)
                pure={u:bool(len(uid_owner[u])==1 and not uid_owner[u]&{'OUTSIDE_SELECTED','AMBIGUOUS','UNINDEXED'} and tracked[u]==int(records[u]['orig_pkts']+records[u]['resp_pkts'])==event_count[u]) for u in uids}
                complete={k:bool(mapped[k]==expected[k] and bad[k]==0 and owners[k] and owners[k].issubset(records)) for k in mk}
                membership=pd.DataFrame([{'ks':k,'expected_packets':expected[k],'mapped_packets':mapped[k],'unresolved_packets':bad[k],
                    'descendant_UIDs':len(owners[k]),'packet_membership_complete':complete[k],
                    'pure_descendant_UIDs':sum(pure.get(u,False) for u in owners[k])} for k in mk])
                membership.to_csv(folder/f'membership_{delay}s.csv',index=False)
                pd.DataFrame(map_rows).to_csv(folder/f'fingerprint_UIDs_{delay}s.csv.gz',index=False,compression='gzip')
                sf.to_csv(folder/f'selected_features_{delay}s.csv.gz',index=False,compression='gzip');cf.to_csv(folder/f'descendant_features_{delay}s.csv.gz',index=False,compression='gzip')
                js(folder/f'UID_relations_{delay}s.json',{'owners':dict(owners),'pure':pure,'complete':complete})
                states[delay]={'selected':sf,'records':cf,'owners':owners,'pure':pure,'complete':complete}
                state_proofs.append({'delay_seconds':delay,'identity_no_feasible_action':bool(delay>0 and not eligible),'modified_original_units':len(eligible) if delay else 0,
                    'delayed_packet_occurrences':changed,'PCAP_sha256':sha(path),'complete_memberships':sum(complete.values()),'cohort_units':N})
                print('Capture',capture,'condition',delay,'seconds: eligible',len(eligible),'complete membership',sum(complete.values()),'/',N,flush=True)
                if not identity:shutil.rmtree(condition_dir);path.unlink()
            js(folder/'condition_provenance.json',state_proofs)
            target_rows=[];monitor_rows=[];unit_rows=[]
            with threadpool_limits(limits=2):
                for policy in POLICIES:
                    for family in ['HGB','LR']:
                        for seed in SEEDS:
                            model=bank['models'][(policy,family,seed)];calibrator=bank['calibrators'][(policy,family,seed)];par=params[(policy,family,seed)];outcomes=[]
                            for delay in [0,1,10]:
                                st=states[delay];sf=st['selected'];cf=st['records'];p=model.predict_proba(encode(sf))[:,1];dec=p>=.5;confidence=np.maximum(p,1-p);q=calibrator.predict_proba(logit(p))[:,1]
                                alarms=dict(zip(cf.uid,model.predict_proba(encode(cf))[:,1]>=.5)) if len(cf) else {}
                                pos=neg=unknown=overlap=0
                                for k in mk:
                                    uu=st['owners'].get(k,());has=any(alarms.get(u,False) for u in uu);witness=any(alarms.get(u,False) and st['pure'].get(u,False) for u in uu);none=st['complete'][k] and not has
                                    label='PURE_ALARM_WITNESS' if witness else ('NO_RECORD_ALARM' if none else 'UNRESOLVED')
                                    pos+=int(witness);neg+=int(none);unknown+=int(label=='UNRESOLVED');overlap+=int(has)
                                    unit_rows.append({'capture':capture,'split_policy':policy,'family':family,'model_seed':seed,'delay_seconds':delay,'ks':k,'classification':label,'any_overlap_alarm':bool(has)})
                                accuracy=float((dec==y).mean());values={'AC':float(confidence.mean()),'DoC':float(np.clip(par['accuracy']+confidence.mean()-par['confidence'],0,1)),
                                    'ATC_SOURCE_GE':float((confidence>=par['threshold']).mean()),
                                    'ATC_FRACTIONAL_TIE_EXPECTATION':float(((confidence>par['threshold']).astype(float)+par['alpha']*(confidence==par['threshold'])).mean()),
                                    'CBPE_ACC_POINT':float(np.where(dec,q,1-q).mean())}
                                target_rows.append({'capture':capture,'split_policy':policy,'family':family,'model_seed':seed,'delay_seconds':delay,
                                    'record_accuracy':accuracy,'selected_record_recall':float(dec[y==1].mean()),'benign_FPR':float(dec[y==0].mean()),
                                    'original_units':N,'pacing_eligible_units':len(eligible),'modified_units':len(eligible) if delay else 0,
                                    'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                                    'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap})
                                outcomes.append((delay,accuracy,pos/N,(pos+unknown)/N,values))
                            baseline=outcomes[0]
                            for delay,truth,lower,upper,values in outcomes:
                                for method,value in values.items():
                                    estimated=baseline[4][method]-value;loss_lower=baseline[2]-upper;loss_upper=baseline[3]-lower
                                    monitor_rows.append({'capture':capture,'split_policy':policy,'family':family,'model_seed':seed,'delay_seconds':delay,'estimator':method,
                                        'record_accuracy':truth,'estimate':value,'absolute_error':abs(value-truth),'overestimation':value-truth,
                                        'record_accuracy_drop':baseline[1]-truth,'estimated_record_accuracy_drop':estimated,
                                        'differential_error':abs(estimated-(baseline[1]-truth)),
                                        'unit_detection_drop_lower':loss_lower,'unit_detection_drop_upper':loss_upper,
                                        'warning_at_5pp':estimated>=THRESHOLD,'definite_damage':loss_lower>=THRESHOLD,
                                        'missed_definite_damage':bool(loss_lower>=THRESHOLD and estimated<THRESHOLD)})
            targets=pd.DataFrame(target_rows);monitors=pd.DataFrame(monitor_rows)
            targets.to_csv(folder/'five_seed_target_results.csv',index=False);monitors.to_csv(folder/'five_seed_monitor_results.csv',index=False)
            pd.DataFrame(unit_rows).to_csv(folder/'original_unit_results.csv.gz',index=False,compression='gzip')
            all_targets.extend(target_rows);all_monitors.extend(monitor_rows)
            print('\nCAPTURE '+str(capture)+' — FIVE-SEED 10s RESULTS\n'+targets[targets.delay_seconds.eq(10)].to_string(index=False),flush=True)
            summary=monitors[monitors.delay_seconds.eq(10)].groupby(['split_policy','family','estimator'],as_index=False).agg(seed_rows=('model_seed','size'),mean_absolute_error=('absolute_error','mean'),mean_overestimation=('overestimation','mean'),mean_differential_error=('differential_error','mean'),warning_fraction_over_seed_rows=('warning_at_5pp','mean'),missed_definite_damage_fraction=('missed_definite_damage','mean'))
            summary.to_csv(folder/'monitor_summary_10s.csv',index=False)
            print('\nMONITOR SUMMARY AT 10s\n'+summary.to_string(index=False),flush=True)
            C.update({'status':'RAW_CAPTURE_PACKET_AWARE_POINT_MONITOR_EVALUATION_COMPLETE','original_units':N,
                'cohort_resampled_after_model_outcomes':False,'target_result_rows':len(targets),'monitor_result_rows':len(monitors),
                'published_rows_scanned':min(scanned,LABEL_ROW_LIMIT),'published_log_exhausted':exhausted,
                'partial_lineage_possible':not all(all(st['complete'].values()) for st in states.values()),
                'interpretation':'Bounded-prefix/label-budget IPv4 TCP/UDP development cohort. Ineligible timing actions are identity. No source/target class shift is relabeled as adversarial damage. Unknown attribution retained.'})
            R['completed_captures'].append(capture);case_ledger.append(C)
        except Exception as error:
            C['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';C['reason']=str(error)
            (folder/'error.txt').write_text(traceback.format_exc());case_ledger.append(C);print('\nCAPTURE',capture,C['status']+':',str(error),flush=True)
        finally:
            if db is not None:db.close();db=None
            if scratch is not None and scratch.is_dir() and C['status'] in ['RAW_CAPTURE_PACKET_AWARE_POINT_MONITOR_EVALUATION_COMPLETE','INSUFFICIENT_UNDER_DECLARED_INTAKE_POLICY']:
                shutil.rmtree(scratch);C['only_this_case_scratch_removed']=True
            elif scratch is not None and scratch.is_dir():C['scratch_retained_for_diagnosis']=True
            js(folder/'receipt.json',C);pd.DataFrame(case_ledger).to_csv(OUT/'capture_execution_ledger.csv',index=False)
            pd.DataFrame(all_targets).to_csv(OUT/'combined_new_capture_target_results.csv',index=False)
            pd.DataFrame(all_monitors).to_csv(OUT/'combined_new_capture_monitor_results.csv',index=False)
            js(OUT/'receipt.json',R)
            R['latest_checkpoint']=make_checkpoint(case_dirs,'PRIVATE_capture_progress_checkpoint.zip')
    R['status']='P3_TWO_CAPTURE_BATCH_COMPLETE' if len(R['completed_captures'])==len(CAPTURES) else 'P3_TWO_CAPTURE_BATCH_FINISHED_WITH_EXPLICIT_GAPS'
    R['next_planned_capture_batch']=[33,36]
    R['remaining_after_that_batch']=[39,43]
    R['source_five_seed_bank_unchanged']=True
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    js(OUT/'receipt.json',R)
    try:R['final_checkpoint']=make_checkpoint(case_dirs,'PRIVATE_two_capture_results_and_frozen_bank.zip')
    except Exception as error:R['checkpoint_error']=str(error)
    js(OUT/'receipt.json',R);print('\nBATCH RECEIPT\n'+json.dumps(R,indent=2),flush=True)

if __name__=='__main__':pass
