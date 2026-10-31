# P3 configuration sensitivity: tcp_SYN_timeout = 15 secs, fixed detectors.
# Two new replays (clean and exact historical 10s), then paired comparison with default.
# No tuning, detector retraining, or replacement of the default results.
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from contextlib import contextmanager
from collections import defaultdict, Counter
import hashlib, io, json, re, resource, shutil, socket, sqlite3, struct, subprocess, time, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');ALT=15.0
OUT=W/('CAPTURE49_SYN_TIMEOUT_SENSITIVITY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
R={'status':'STARTED','new_PCAP_replays':0,'models_trained':False,'source_calibration_refitted':False,
   'timeout_search_performed':False,'independent_confirmation':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def latest(pattern,status):
    found=[]
    for p in W.glob(pattern):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        try:r=json.loads(rp.read_text())
        except (OSError,ValueError):continue
        if r.get('status')==status:found.append((p,r))
    if not found:raise Stop('Missing completed stage '+status)
    return max(found,key=lambda x:x[0].name)
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def blob(a):
    with opened(a) as f:b=f.read(128*1024**2+1)
    if len(b)>128*1024**2:raise Stop('Bounded metadata read exceeded')
    return b

def sha_asset(a):
    h=hashlib.sha256()
    with opened(a) as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def sha_file(p):return sha_asset({'path':str(p),'member':''})
def csv(a):
    import gzip
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded metadata too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def norm(df):
    df=df.copy()
    if not set(F).issubset(df.columns):raise Stop('Feature schema differs')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor')
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid protocol')
    return df

def encode(df,protocol):
    pr=np.column_stack([df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']])
    return pr if protocol else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),pr])

def legacy_key(k):
    for sep in ['|','::',',']:
        p=str(k).split(sep)
        if len(p)==6:
            try:return (int(p[0]),p[1],int(p[2]),p[3],int(p[4]),p[5].lower())
            except ValueError:continue
    raise Stop('Unsupported historical sample-key serialization; no guessed labels or identities')
def conn_key(r):return (us(r['ts']),r['id.orig_h'],int(r['id.orig_p']),r['id.resp_h'],int(r['id.resp_p']),r['proto'].lower())
def feature_row(r):return {c:(r[c].lower() if c=='proto' else (0. if r[c] in ['-',''] else float(r[c]))) for c in F}
def log_rows(path):
    fields=None
    with open(path) as f:
        for line in f:
            if line.startswith('#fields'):fields=line.strip().split()[1:]
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('No Zeek field header')
                v=line.rstrip().split()
                if len(v)!=len(fields):raise Stop('Unexpected Zeek row width')
                yield dict(zip(fields,v))

def header(path):
    with open(path,'rb') as f:h=f.read(24)
    if len(h)!=24 or h[:4] not in MAGIC:raise Stop('Classic PCAP required')
    e,u=MAGIC[h[:4]];link=struct.unpack(e+'I',h[20:24])[0]&65535
    if link not in [1,113,276,101,228,12]:raise Stop('Unsupported link type')
    return h,e,u,link

def packets(path):
    h,e,u,link=header(path)
    with open(path,'rb') as f:
        f.seek(24);idx=0;offset=24
        while True:
            rh=f.read(16)
            if not rh:break
            if len(rh)!=16:raise Stop('Truncated packet header')
            sec,sub,cap,wire=struct.unpack(e+'IIII',rh)
            if cap>16*1024**2:raise Stop('Implausible packet size')
            b=f.read(cap)
            if len(b)!=cap:raise Stop('Truncated packet bytes')
            yield idx,sec*10**9+sub*u,cap,wire,b,offset+16
            idx+=1;offset+=16+cap

def tcp4(b,link):
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
    if ihl<20 or b[o+9]!=6 or int.from_bytes(b[o+6:o+8],'big')&0x3fff:return None
    t=o+ihl
    if len(b)<t+20:return None
    sp,dp,seq,ack=struct.unpack('!HHII',b[t:t+12])
    return (socket.inet_ntoa(b[o+12:o+16]),sp,socket.inet_ntoa(b[o+16:o+20]),dp,seq,ack,b[t+13],int.from_bytes(b[o+4:o+6],'big'),int.from_bytes(b[o+2:o+4],'big'))

def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean')
    return v.isin(['true','1']).to_numpy(bool)


# Input-location repair only. No calibration, model, cohort, or timeout changes.
import fnmatch
_REC_INDEX=None
_REC_LOG=[]
_REC_CACHE=OUT/'resolved_inputs'
_REC_CACHE.mkdir(exist_ok=True)
def _rec_index():
    global _REC_INDEX
    if _REC_INDEX is not None:return _REC_INDEX
    entries=[];archives=[]
    for root in [Path('/kaggle/input'),W]:
        if not root.is_dir():continue
        for current,dirs,files in __import__('os').walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if d not in {'.git','__pycache__'} and not (Path(current)/d).resolve().is_relative_to(OUT.resolve())]
            for name in files:
                p=Path(current)/name
                if p.is_symlink():continue
                try:
                    entries.append({'path':str(p),'member':'','logical':str(p),'bytes':p.stat().st_size})
                    if p.suffix.lower()=='.zip':archives.append(p)
                except OSError:pass
    for p in archives:
        try:
            with zipfile.ZipFile(p) as z:
                for info in z.infolist():
                    if not info.is_dir():entries.append({'path':str(p),'member':info.filename,'logical':info.filename,'bytes':info.file_size})
        except (OSError,zipfile.BadZipFile) as e:_REC_LOG.append({'archive':str(p),'error':str(e)})
    _REC_INDEX=entries
    print('Indexed input locations:',len(entries),'entries; archives:',len(archives),flush=True)
    return entries
@contextmanager
def _rec_open(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f
def _rec_hash(a):
    h=hashlib.sha256()
    with _rec_open(a) as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def _rec_unique(candidates,description):
    if not candidates:raise Stop('Required saved input not found in mounted files/ZIPs: '+description)
    variants={}
    for a in candidates:variants.setdefault(_rec_hash(a),[]).append(a)
    if len(variants)!=1:raise Stop('Content-conflicting saved copies: '+description+'; no version guessed')
    digest,copies=next(iter(variants.items()))
    a=min(copies,key=lambda x:(bool(x.get('member')),len(x['path']),x['path'],x.get('member','')))
    _REC_LOG.append({'requested':description,'resolved':a,'sha256':digest})
    return dict(a,sha256=digest)
def _rec_find(logical):
    parts=Path(str(logical)).parts
    candidates=_rec_index()
    # Require at least parent-directory plus filename; never basename-only recovery.
    for n in range(len(parts),1,-1):
        suffix='/'.join(parts[-n:])
        hits=[a for a in candidates if a['logical'].replace('\\','/').endswith('/'+suffix) or a['logical']==suffix]
        if hits:return _rec_unique(hits,str(logical))
    raise Stop('Exact path-suffix input unavailable: '+str(logical))
def _rec_save(a,where):
    if a['bytes']>256*1024**2:raise Stop('Metadata restoration exceeds 256 MiB per-file cap: '+a['logical'])
    where.parent.mkdir(parents=True,exist_ok=True)
    if where.is_file():
        if sha_file(where)!=_rec_hash(a):raise Stop('Restoration cache content conflict')
        return where
    if shutil.disk_usage(W).free<a['bytes']+1024**3:raise Stop('Insufficient space for selective input restoration')
    with _rec_open(a) as src,where.open('wb') as dst:shutil.copyfileobj(src,dst,4*1024**2)
    if sha_file(where)!=_rec_hash(a):raise Stop('Restored file hash mismatch')
    return where
def recover_asset(a):
    a=dict(a);p=Path(a['path']);member=a.get('member','')
    if p.is_file():
        if not member:return a
        with zipfile.ZipFile(p) as z:
            if member in z.namelist():return a
    if member:
        # Recover the actual member, not an arbitrary archive having a similar name.
        found=_rec_find(member)
    else:found=_rec_find(a['path'])
    return {**a,'path':found['path'],'member':found.get('member','')}
@contextmanager
def opened(a):
    with _rec_open(recover_asset(a)) as f:yield f
_STAGE_FILES={
 'P4_AC_AGREEMENT_BATCH_COMPLETE':['receipt.json','input_manifest.json'],
 'CLEAN_BASELINE_VALIDATED':['receipt.json','selected_slice.json','clean_packet_uid_mapping.csv.gz'],
 'MATCHED_MODEL_FAMILIES_AND_PROTOCOL_CONTROL_COMPLETE':['receipt.json','new_matched_comparison_models.joblib'],
 'TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED':['receipt.json','transformed_packet_uid_mapping.csv.gz','test2_transformed_membership.csv','transformed_selected_connection_records.csv.gz']}
def _rec_stage(dirname,status):
    dest=_REC_CACHE/dirname
    for name in _STAGE_FILES[status]:_rec_save(_rec_find(dirname+'/'+name),dest/name)
    r=json.loads((dest/'receipt.json').read_text())
    if r.get('status')!=status:raise Stop('Recovered stage receipt status differs: '+dirname)
    return dest,r
def latest(pattern,status):
    matches=[]
    for a in _rec_index():
        logical=Path(a['logical'])
        if logical.name!='receipt.json' or not fnmatch.fnmatch(logical.parent.name,pattern):continue
        if a['bytes']>4*1024**2:continue
        try:
            with _rec_open(a) as f:r=json.load(f)
        except (OSError,ValueError):continue
        if r.get('status')==status:matches.append(logical.parent.name)
    if not matches:raise Stop('No completed '+status+' receipt exists in attached files or ZIPs. See input_resolution.json.')
    dirname=sorted(set(matches))[-1]
    return _rec_stage(dirname,status)
def recover_transformed_stage(oldpath):
    return _rec_stage(Path(oldpath).name,'TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED')[0]

scratch=None;db=None
try:
    a,_=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    base,_=latest('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    matched,_=latest('LINEAGE_MATCHED_MODEL_FAMILIES_*','MATCHED_MODEL_FAMILIES_AND_PROTOCOL_CONTROL_COMPLETE')
    manifest=json.loads((a/'input_manifest.json').read_text());source_asset=recover_asset(json.loads((base/'selected_slice.json').read_text()))
    if sha_asset(source_asset)!=source_asset['sha256']:raise Stop('Source slice hash changed')
    clean=norm(csv(manifest['clean']));clean['y']=pd.to_numeric(clean.y,errors='raise').astype(int)
    if len(clean)!=1024 or clean.ks.duplicated().any() or not clean.y.isin([0,1]).all():raise Stop('Invalid frozen cohort')
    keys=clean.ks.astype(str).to_numpy();y=clean.y.to_numpy();mk=list(keys[y==1]);N=len(mk)
    if N!=512:raise Stop('Expected 512 original malicious units')
    label_by_key=dict(zip(keys,y))
    sample_lookup={legacy_key(k):k for k in keys}
    if len(sample_lookup)!=len(keys):raise Stop('Sample key identity collision')
    sample_endpoint_tuples={(v[1],v[2],v[3],v[4],v[5]) for v in sample_lookup}
    reference=pd.read_csv(base/'clean_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'zeek_uid':str})
    if reference.packet_index.duplicated().any() or set(reference.original_ks)!=set(mk):raise Stop('Invalid clean occurrence ledger')
    owner_by_idx=dict(zip(reference.packet_index.astype(int),reference.original_ks));first=reference.groupby('original_ks').packet_index.min().astype(int).to_dict()
    expected=reference.groupby('original_ks').size().to_dict()
    if min(expected.values())<2:raise Stop('Historical pacing eligibility differs')
    condition=next(x for x in manifest['conditions'] if int(x['delay_seconds'])==10)
    attack=norm(csv(condition['candidate_asset'])).set_index('ks').loc[keys].reset_index()
    original_results=recover_transformed_stage(condition['validated_result_directory']);rr=json.loads((original_results/'receipt.json').read_text())
    if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr['historical_transformed_pcap_sha256']!=condition['historical_transformed_pcap_sha256']:raise Stop('Historical 10s identity differs')
    if sha_asset(condition['candidate_asset'])!=condition['candidate_sha256']:raise Stop('Historical selected features changed')
    old_models=joblib.load(io.BytesIO(blob(manifest['models'])))['models']
    models={('HISTORICAL_HGB',int(k)):v['PRIMARY'] for k,v in old_models.items()}
    models.update({(str(f),int(s)):model for (f,s),model in joblib.load(matched/'new_matched_comparison_models.joblib').items()})
    if len(models)!=12:raise Stop('Expected 12 historical/matched/control models')
    zeek=shutil.which('zeek') or '/opt/zeek/bin/zeek'
    version=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30)
    version_text=(version.stdout+version.stderr).strip()
    if '8.0.10' not in version_text:raise Stop('Expected Zeek 8.0.10')
    probe=OUT/'default_timeout_probe.zeek';probe.write_text('event zeek_init() { print fmt("CONFIG|%s", tcp_SYN_timeout); }\n')
    check=subprocess.run([zeek,'-b',str(probe)],cwd=OUT,capture_output=True,text=True,timeout=30)
    setting_lines=[l for l in check.stdout.splitlines() if l.startswith('CONFIG|')]
    if check.returncode or len(setting_lines)!=1:raise Stop('Could not verify tcp_SYN_timeout')
    default_value=float(re.search(r'[0-9]+(?:\.[0-9]+)?',setting_lines[0].split('|',1)[1]).group())
    if default_value!=5.:raise Stop('The default configuration is no longer 5 seconds; no silent baseline change')
    js(OUT/'policy.json',{'default_tcp_SYN_timeout_seconds':default_value,'alternative_seconds':ALT,
        'parameters_changed':['tcp_SYN_timeout'],'timeout_search':False,'raw_traces_changed_between_extractors':False,
        'detectors_and_source_calibrators_refitted':False,'clean_reference':'separate clean extraction under each setting',
        'interpretation':'fixed-detector extractor-configuration sensitivity, not a claimed improved defense',
        'primary_unit':'same 512 default-reference original units','mixed_records':'pure-witness bounds plus separate overlap policy',
        'selected_record_comparison':'common retained original-start keys within each configuration',
        'nominal_time_policy':'network_time at Conn::log_conn, immediate classifier consumption, CPU excluded'})
    if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free required')
    scratch=OUT/'scratch';scratch.mkdir()
    if source_asset.get('member'):
        pcap=scratch/'source.pcap'
        with opened(source_asset) as src,open(pcap,'wb') as dst:shutil.copyfileobj(src,dst,4*1024**2)
    else:pcap=Path(source_asset['path'])
    h,endian,unit,link=header(pcap)
    endpoints=set()
    for idx,ts,cap,wire,b,off in packets(pcap):
        if idx in owner_by_idx:
            info=tcp4(b,link)
            if info is None:raise Stop('Validated original packet cannot be parsed')
            endpoints.add(tuple(sorted([(info[0],info[1]),(info[2],info[3])])))
    watched=set()
    for ee in endpoints:
        (s,sp),(d,dp)=ee;watched.update([f'{s}|{sp}|{d}|{dp}',f'{d}|{dp}|{s}|{sp}'])
    entries=',\n'.join(json.dumps(x) for x in sorted(watched))
    tap="""@load base/protocols/conn
redef tcp_SYN_timeout = 15.0 secs;
const watched: set[string] = {ENTRIES};
global watched_uids: set[string] = set();
event zeek_init() { print fmt("CONFIG|%s", tcp_SYN_timeout); }
event new_packet(c: connection, p: pkt_hdr)
    {
    if ( ! p?$ip || ! p?$tcp ) return;
    local k = fmt("%s|%d|%s|%d", p$ip$src, port_to_count(p$tcp$sport), p$ip$dst, port_to_count(p$tcp$dport));
    if ( k !in watched ) return;
    add watched_uids[c$uid];
    print fmt("PACKET|%.6f|%s|%s|%d|%s|%d|%d|%d|%d|%d|%d", network_time(), c$uid, p$ip$src, port_to_count(p$tcp$sport), p$ip$dst, port_to_count(p$tcp$dport), p$tcp$seq, p$tcp$ack, p$tcp$flags, p$ip$id, p$ip$len);
    }
event Conn::log_conn(rec: Conn::Info)
    {
    if ( rec$uid in watched_uids ) print fmt("AVAILABLE|%.6f|%s", network_time(), rec$uid);
    }
""".replace('ENTRIES',entries)
    tap_path=OUT/'alternative_timeout.zeek';tap_path.write_text(tap)
    compiled=subprocess.run([zeek,'-b',str(tap_path)],cwd=OUT,capture_output=True,text=True,timeout=30)
    (OUT/'compile_stderr.txt').write_text(compiled.stderr)
    if compiled.returncode or 'CONFIG|15' not in compiled.stdout:raise Stop('Alternative timeout did not compile/verify')
    raw={0:defaultdict(list),10:defaultdict(list)};rows=[];count=0
    db=sqlite3.connect(scratch/'schedule.sqlite');db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA temp_store=FILE');db.execute('PRAGMA cache_size=-32768')
    db.execute('CREATE TABLE p(ts INTEGER,idx INTEGER,off INTEGER,cap INTEGER,wire INTEGER)')
    print('[1/3] Reconstructing the SAME hash-bound 10s trace; timeout does not change packet bytes.',flush=True)
    for idx,ts,cap,wire,b,off in packets(pcap):
        k=owner_by_idx.get(idx);delta=10*10**9 if k is not None and idx!=first[k] else 0
        info=tcp4(b,link)
        if info is not None and tuple(sorted([(info[0],info[1]),(info[2],info[3])])) in endpoints:
            raw[0][((ts+500)//1000,)+info].append((idx,k));raw[10][((ts+delta+500)//1000,)+info].append((idx,k))
        rows.append((ts+delta,idx,off,cap,wire));count+=1
        if len(rows)>=50000:db.executemany('INSERT INTO p VALUES(?,?,?,?,?)',rows);rows=[]
    if rows:db.executemany('INSERT INTO p VALUES(?,?,?,?,?)',rows)
    db.commit();db.execute('CREATE INDEX ordered ON p(ts,idx)');db.commit()
    transformed=scratch/'same_paced10s.pcap'
    with open(pcap,'rb') as src,open(transformed,'wb') as dst:
        dst.write(h)
        for ts,idx,off,cap,wire in db.execute('SELECT ts,idx,off,cap,wire FROM p ORDER BY ts,idx'):
            src.seek(off);b=src.read(cap)
            if len(b)!=cap:raise Stop('Truncated packet copy')
            dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(b)
    db.close();db=None;(scratch/'schedule.sqlite').unlink()
    observed=sha_file(transformed)
    if observed!=condition['historical_transformed_pcap_sha256']:raise Stop('The 10s PCAP did not reproduce its historical hash')
    js(OUT/'trace_identity.json',{'source_sha256':source_asset['sha256'],'transformed_sha256':observed,'historical_hash_match':True,'packets':count})
    states={};resource_rows=[]
    for delay,path in [(0,pcap),(10,transformed)]:
        print(f'[2/3] Alternative 15s SYN timeout: {delay}s pacing.',flush=True)
        d=scratch/f'alt_{delay}';d.mkdir();stdout=OUT/f'alt_{delay}_events.txt';stderr=OUT/f'alt_{delay}_stderr.txt'
        def memory_limit():resource.setrlimit(resource.RLIMIT_AS,(6*1024**3,6*1024**3))
        t=time.perf_counter();peak=0;R['new_PCAP_replays']+=1
        with open(stdout,'w') as so,open(stderr,'w') as se:
            process=subprocess.Popen([zeek,'-C','-r',str(path),str(tap_path)],cwd=d,stdout=so,stderr=se,preexec_fn=memory_limit)
            try:
                while process.poll() is None:
                    if time.perf_counter()-t>1800:process.kill();process.wait();raise Stop('Zeek timeout')
                    try:
                        status=Path(f'/proc/{process.pid}/status').read_text()
                        m=re.search(r'^VmRSS:\s+(\d+)\s+kB',status,re.M)
                        if m:peak=max(peak,int(m.group(1)))
                    except (OSError,ValueError):pass
                    time.sleep(.2)
            except BaseException:
                if process.poll() is None:process.kill();process.wait()
                raise
        elapsed=time.perf_counter()-t
        if process.returncode or not (d/'conn.log').is_file():raise Stop('Alternative-config replay failed; stderr retained')
        events=defaultdict(list);available={};config_seen=False
        with open(stdout) as f:
            for line in f:
                if line.startswith('CONFIG|15'):config_seen=True
                elif line.startswith('AVAILABLE|'):
                    z=line.rstrip('\r\n').split('|')
                    if len(z)!=3:raise Stop('Bad availability event')
                    tt=us(z[1]);available[z[2]]=min(tt,available.get(z[2],tt))
                elif line.startswith('PACKET|'):
                    z=line.rstrip('\r\n').split('|')
                    if len(z)!=12:raise Stop('Bad packet event')
                    fp=(us(z[1]),z[3],int(z[4]),z[5],int(z[6]),*[int(x) for x in z[7:12]])
                    events[fp].append(z[2])
        if not config_seen or not events:raise Stop('Actual replay setting or packet events missing')
        owners=defaultdict(set);uid_owner=defaultdict(set);tracked=Counter();mapped=Counter();bad=Counter();map_rows=[]
        for fp,uu in events.items():
            if fp not in raw[delay]:
                for u in uu:uid_owner[u].add('UNINDEXED')
        for fp,occurrences in raw[delay].items():
            uu=events.get(fp,[]);source_owners={k if k is not None else 'OUTSIDE_SELECTED' for _,k in occurrences}
            if len(occurrences)==len(uu) and len(source_owners)==1:
                k=next(iter(source_owners))
                for u,n in Counter(uu).items():
                    uid_owner[u].add(k)
                    if k!='OUTSIDE_SELECTED':mapped[k]+=n;tracked[u]+=n;owners[k].add(u)
                    map_rows.append({'fingerprint_sha256':hashlib.sha256(repr(fp).encode()).hexdigest(),'original_ks':k,'uid':u,'occurrences':n})
            else:
                for _,k in occurrences:
                    if k is not None:bad[k]+=1
                for u in uu:uid_owner[u].add('AMBIGUOUS')
        needed=set().union(*owners.values()) if owners else set();conn={};selected={};ambiguous_start=set()
        for row in log_rows(d/'conn.log'):
            try:
                identity=(row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower())
            except ValueError:continue
            if identity in sample_endpoint_tuples:
                k=sample_lookup.get(conn_key(row))
                if k:
                    if k in selected:ambiguous_start.add(k)
                    selected[k]={**feature_row(row),'ks':k,'y':int(label_by_key[k])}
            if row['uid'] in needed:
                if row['uid'] in conn:raise Stop('Repeated UID feature record')
                conn[row['uid']]={**feature_row(row),'uid':row['uid']}
        for k in ambiguous_start:selected.pop(k,None)
        event_counts=Counter(u for uu in events.values() for u in uu)
        purity={u:bool(uid_owner[u] and len(uid_owner[u])==1 and not uid_owner[u]&{'OUTSIDE_SELECTED','UNINDEXED','AMBIGUOUS'}
                       and tracked[u]==int(conn[u]['orig_pkts']+conn[u]['resp_pkts'])==event_counts[u]) for u in conn}
        complete={k:bool(mapped[k]==expected[k] and bad[k]==0 and owners[k] and owners[k].issubset(conn)) for k in mk}
        pd.DataFrame(map_rows).to_csv(OUT/f'alt_{delay}_fingerprint_UIDs.csv.gz',index=False,compression='gzip')
        uid_order=sorted(conn);cf=norm(pd.DataFrame([conn[u] for u in uid_order],columns=F+['uid']))
        cf.to_csv(OUT/f'alt_{delay}_descendant_features.csv.gz',index=False,compression='gzip')
        sf=norm(pd.DataFrame(list(selected.values()),columns=F+['ks','y']))
        sf.to_csv(OUT/f'alt_{delay}_selected_features.csv.gz',index=False,compression='gzip')
        pd.DataFrame([{'uid':u,'available_network_time_us':tt} for u,tt in available.items()]).to_csv(OUT/f'alt_{delay}_record_availability.csv',index=False)
        pd.DataFrame([{'ks':k,'expected_packets':expected[k],'mapped_packets':mapped[k],'unresolved_packets':bad[k],
                       'descendant_UIDs':len(owners[k]),'packet_membership_complete':complete[k]} for k in mk]).to_csv(OUT/f'alt_{delay}_membership.csv',index=False)
        states[('ALTERNATIVE_15S',delay)]={'selected':sf,'conn':cf,'owners':owners,'complete':complete,'pure':purity,'available':available}
        resource_rows.append({'configuration':'ALTERNATIVE_15S','pacing_seconds':delay,'wall_seconds':elapsed,
                              'sampled_Zeek_process_peak_RSS_MiB':peak/1024 if peak else np.nan,
                              'memory_sampling_seconds':.2,'exact_peak_memory_claimed':False})
    # Default clean features were validated against this same raw trace earlier.
    clean_owners=reference.groupby('original_ks').zeek_uid.agg(lambda z:tuple(sorted(set(z)))).to_dict()
    if any(len(clean_owners[k])!=1 for k in mk):raise Stop('Default clean one-record relation changed')
    positive=clean.set_index('ks').loc[mk]
    cf0=positive[F].copy();cf0['uid']=[clean_owners[k][0] for k in mk];cf0=cf0.reset_index(drop=True)
    mp=pd.read_csv(original_results/'transformed_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'transformed_uid':str})
    membership=pd.read_csv(original_results/'test2_transformed_membership.csv',dtype={'ks':str})
    if not boolean(membership.transformed_membership_validated).all():raise Stop('Default transformed membership is no longer fully validated')
    owners10=mp.groupby('original_ks').transformed_uid.agg(lambda z:tuple(sorted(set(z)))).to_dict()
    cf10=norm(pd.read_csv(original_results/'transformed_selected_connection_records.csv.gz',dtype={'uid':str},keep_default_na=False))
    if set(owners10)!=set(mk) or set(cf10.uid)!=set(mp.transformed_uid):raise Stop('Default descendant coverage differs')
    states[('DEFAULT_5S',0)]={'selected':clean,'conn':cf0,'owners':clean_owners,'complete':dict.fromkeys(mk,True),'pure':dict.fromkeys(cf0.uid,True),'available':{}}
    states[('DEFAULT_5S',10)]={'selected':attack,'conn':cf10,'owners':owners10,'complete':dict.fromkeys(mk,True),'pure':dict.fromkeys(cf10.uid,True),'available':{}}
    print('[3/3] Fixed-detector comparisons with separate clean references and explicit retained-record coverage.',flush=True)
    summaries=[];unit_rows=[];timings=[]
    with threadpool_limits(limits=2):
        for config in ['DEFAULT_5S','ALTERNATIVE_15S']:
            common=set(states[(config,0)]['selected'].ks)&set(states[(config,10)]['selected'].ks)
            common_keys=[k for k in keys if k in common]
            for (family,seed),model in sorted(models.items()):
                protocol=family=='PROTOCOL_ONLY_LR';bounds={};temporary=[]
                for delay in [0,10]:
                    state=states[(config,delay)];cf=state['conn']
                    alarm=dict(zip(cf.uid,model.predict_proba(encode(cf,protocol))[:,1]>=.5)) if len(cf) else {}
                    pos=neg=unknown=overlap=0
                    for k in mk:
                        uu=state['owners'].get(k,());any_alarm=any(alarm.get(u,False) for u in uu)
                        witness=any(alarm.get(u,False) and state['pure'].get(u,False) for u in uu)
                        none=bool(state['complete'].get(k,False) and not any_alarm)
                        label='PURE_ALARM_WITNESS' if witness else ('NO_RECORD_ALARM' if none else 'UNRESOLVED')
                        pos+=int(witness);neg+=int(none);unknown+=int(label=='UNRESOLVED');overlap+=int(any_alarm)
                        unit_rows.append({'configuration':config,'delay_seconds':delay,'family':family,'seed':int(seed),'ks':k,
                                          'classification':label,'any_overlap_alarm':bool(any_alarm)})
                        if config=='ALTERNATIVE_15S':
                            t0=legacy_key(k)[0];uu_positive=[u for u in uu if alarm.get(u,False)]
                            for horizon in [1,5,10,30,60]:
                                bound=t0+horizon*1000000
                                lower=any(state['pure'].get(u,False) and u in state['available'] and t0<=state['available'][u]<=bound for u in uu_positive)
                                possible=any(u in state['available'] and t0<=state['available'][u]<=bound for u in uu_positive)
                                time_unknown=any(u not in state['available'] or state['available'][u]<t0 for u in uu_positive)
                                timings.append({'configuration':config,'delay_seconds':delay,'family':family,'seed':int(seed),'horizon_seconds':horizon,
                                                'ks':k,'lower':int(lower),'upper':int(lower or possible or time_unknown or not state['complete'].get(k,False))})
                    bounds[delay]=(pos/N,(pos+unknown)/N)
                    retained=state['selected'];common_frame=retained.set_index('ks').loc[common_keys] if common_keys else None
                    yy=common_frame.y.to_numpy(int) if len(common_keys) else np.array([],int)
                    dec=model.predict_proba(encode(common_frame,protocol))[:,1]>=.5 if len(common_keys) else np.array([],bool)
                    temporary.append({'configuration':config,'family':family,'seed':int(seed),'delay_seconds':delay,
                        'original_units':N,'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                        'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap,
                        'selected_start_records_retained':len(retained),'common_selected_records':len(common_keys),
                        'common_selected_malicious_records':int((yy==1).sum()),'common_selected_benign_records':int((yy==0).sum()),
                        'common_record_accuracy':float((dec==yy).mean()) if len(yy) else np.nan,
                        'common_record_malicious_recall':float(dec[yy==1].mean()) if (yy==1).any() else np.nan,
                        'common_record_benign_FPR':float(dec[yy==0].mean()) if (yy==0).any() else np.nan,
                        'descendant_UIDs':len(cf),'complete_packet_memberships':sum(state['complete'].values())})
                for row in temporary:
                    row['paired_unit_detection_drop_lower']=bounds[0][0]-bounds[row['delay_seconds']][1]
                    row['paired_unit_detection_drop_upper']=bounds[0][1]-bounds[row['delay_seconds']][0]
                    summaries.append(row)
    result=pd.DataFrame(summaries);result.to_csv(OUT/'configuration_model_comparison.csv',index=False)
    pd.DataFrame(unit_rows).to_csv(OUT/'configuration_original_unit_results.csv.gz',index=False,compression='gzip')
    timing=pd.DataFrame(timings).groupby(['configuration','delay_seconds','family','seed','horizon_seconds'],as_index=False).agg(lower_count=('lower','sum'),upper_count=('upper','sum'))
    timing['original_units']=N;timing['record_availability_detection_lower']=timing.lower_count/N;timing['record_availability_detection_upper']=timing.upper_count/N
    timing.to_csv(OUT/'alternative_record_availability_horizons.csv',index=False)
    pd.DataFrame(resource_rows).to_csv(OUT/'alternative_replay_software_resources.csv',index=False)
    for config,title in [('DEFAULT_5S','REFERENCE — DEFAULT EXTRACTION'),('ALTERNATIVE_15S','EXPERIMENTS 1 AND 2 — ALTERNATIVE CLEAN AND 10s')]:
        print('\n'+title+'\n'+result[result.configuration.eq(config)].to_string(index=False),flush=True)
    print('\nANALYSIS 3 — ALTERNATIVE-EXTRACTOR RECORD AVAILABILITY (historical HGB seed 8101)\n'+timing[timing.family.eq('HISTORICAL_HGB')&timing.seed.eq(8101)].to_string(index=False),flush=True)
    print('\nSOFTWARE REPLAY RESOURCES\n'+pd.DataFrame(resource_rows).to_string(index=False),flush=True)
    R.update({'status':'CAPTURE49_ALTERNATIVE_SYN_TIMEOUT_SENSITIVITY_COMPLETE','default_timeout_seconds':5.,'alternative_timeout_seconds':ALT,
              'same_raw_clean_and_transformed_traces':True,'historical_transformed_hash_reproduced':True,
              'clean_references_evaluated_for_both_settings':True,'fixed_detector_sensitivity_not_retrained_configuration_defense':True,
              'physical_latency_measured':False,'source_packet_cohort_changed':False,
              'interpretation':'Single exposed-capture fixed-detector extraction sensitivity. Retained original-start denominators are explicit. Pure witnesses and ambiguity remain separate. Do not select another timeout in response to these results.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    js(OUT/'input_resolution.json',_REC_LOG)
    if db is not None:db.close()
    if scratch is not None and scratch.is_dir() and R['status']=='CAPTURE49_ALTERNATIVE_SYN_TIMEOUT_SENSITIVITY_COMPLETE':shutil.rmtree(scratch);R['only_this_run_scratch_removed']=True
    elif scratch is not None and scratch.is_dir():R['scratch_retained_for_diagnosis']=True
    js(OUT/'receipt.json',R)
    package=OUT/'extractor_configuration_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)