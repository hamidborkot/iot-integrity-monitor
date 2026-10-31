# Fresh raw-data Capture-48 replication: clean, 1s, and 10s in one batch.
# Reads only the original IoT-23 mount. No old CSVs, models, backups, or notebook history.
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib, heapq, ipaddress, json, math, shutil, socket, sqlite3, struct, subprocess, time, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from sklearn.exceptions import ConvergenceWarning
from threadpoolctl import threadpool_limits

ROOT=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
WORK=Path('/kaggle/working');TARGET='CTU-IoT-Malware-Capture-48-1'
SOURCES=[f'CTU-IoT-Malware-Capture-{k}-1' for k in [1,3,8]]
OUT=WORK/('FRESH_RAW_CAPTURE48_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(parents=True,exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SEEDS=[8101,8102,8103];PREFIX_BYTES=256*1024**2;TARGET_PER_CLASS=512;SOURCE_CAP=2000;TAIL_MARGIN=120
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
R={'status':'STARTED','reads_historical_experiment_artifacts':False,'new_models_trained':0,'PCAP_replays':0,
   'historical_outputs_overwritten':False,'fresh_development_sample':True,'independent_confirmation':False,
   'malicious_functionality_tested':False,'injection_control_completed':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def sha_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def number(x):
    v=0. if x in ['-','',None] else float(x)
    if not math.isfinite(v) or v<0:raise ValueError('Invalid nonnegative feature')
    return v

def features(row):
    result={c:number(row[c]) for c in F[:-1]};result['proto']=row['proto'].lower()
    if result['proto'] not in ['tcp','udp','icmp']:raise ValueError('Unsupported protocol')
    return result

def key(row):
    identity=[us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()]
    return hashlib.sha256(json.dumps(identity,separators=(',',':')).encode()).hexdigest()

def endpoint(row):return tuple(sorted([(row['id.orig_h'],int(row['id.orig_p'])),(row['id.resp_h'],int(row['id.resp_p']))]))
def log_rows(path,labelled=False):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):
                # Published IoT-23 headers can combine the last three names with spaces.
                fields=line.strip().split()[1:]
                if labelled and 'label' not in fields:raise Stop('Published log has no explicit primary label: '+str(path))
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Missing Zeek field header: '+str(path))
                values=line.rstrip().split()
                if len(values)!=len(fields):raise Stop('Unexpected Zeek row width in '+str(path))
                yield dict(zip(fields,values))

class LowestHashSample:
    def __init__(self,limit,salt):self.limit=limit;self.salt=salt;self.heap=[];self.items={}
    def add(self,k,row):
        if k in self.items:
            old=self.items[k]
            if old['y']!=row['y'] or any(old[c]!=row[c] for c in F):raise Stop('Conflicting selected source labels/features')
            return
        score=int(hashlib.sha256((self.salt+'|'+k).encode()).hexdigest(),16)
        if len(self.heap)<self.limit:
            heapq.heappush(self.heap,(-score,k));self.items[k]=row
        elif score < -self.heap[0][0]:
            _,old=heapq.heapreplace(self.heap,(-score,k));self.items.pop(old);self.items[k]=row
    def values(self):return [self.items[k] for _,k in sorted(self.heap,key=lambda x:(-x[0],x[1]))]

def header(path):
    with open(path,'rb') as f:h=f.read(24)
    if len(h)!=24 or h[:4] not in MAGIC:raise Stop('This batch requires a classic PCAP, not PCAPNG')
    endian,unit=MAGIC[h[:4]];link=struct.unpack(endian+'I',h[20:24])[0]&65535
    if link not in [1,113,276,101,228,12]:raise Stop('Unsupported PCAP link type '+str(link))
    return h,endian,unit,link

def packets(path):
    h,endian,unit,link=header(path)
    with open(path,'rb') as f:
        f.seek(24);idx=0;off=24
        while True:
            rh=f.read(16)
            if not rh:break
            if len(rh)!=16:raise Stop('Truncated packet header')
            sec,fraction,cap,wire=struct.unpack(endian+'IIII',rh)
            if cap>16*1024**2:raise Stop('Implausible packet size')
            b=f.read(cap)
            if len(b)!=cap:raise Stop('Truncated packet bytes')
            yield idx,sec*10**9+fraction*unit,cap,wire,b,off+16
            off+=16+cap;idx+=1

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

def matrix(df,protocol_only=False):
    p=np.column_stack([df.proto.eq(x).to_numpy(float) for x in ['tcp','udp','icmp']])
    return p if protocol_only else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),p])

def model_metrics(y,p):
    d=p>=.5;y=np.asarray(y,int)
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
            'AUROC':float(roc_auc_score(y,p)), 'malicious_recall':float(d[y==1].mean()),'benign_FPR':float(d[y==0].mean())}

scratch=None;db=None
try:
    if not ROOT.is_dir():raise Stop('Original IoT-23 mount is missing: '+str(ROOT))
    if shutil.disk_usage(WORK).free<4*1024**3:raise Stop('At least 4 GiB free is required; no files were deleted')
    zeek=shutil.which('zeek') or '/opt/zeek/bin/zeek'
    v=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30)
    version=(v.stdout+v.stderr).strip()
    if '8.0.10' not in version:raise Stop('Expected the already installed Zeek 8.0.10')
    paths={s:{'logs':[],'pcaps':[]} for s in SOURCES+[TARGET]}
    for p in ROOT.rglob('*'):
        if not p.is_file():continue
        for scenario in paths:
            if scenario in p.parts:
                if p.name=='conn.log.labeled':paths[scenario]['logs'].append(p)
                elif p.suffix.lower()=='.pcap':paths[scenario]['pcaps'].append(p)
    for scenario in paths:
        if len(paths[scenario]['logs'])!=1:raise Stop(f'{scenario}: expected one original published conn.log.labeled, found {len(paths[scenario]["logs"])}')
    if not paths[TARGET]['pcaps']:raise Stop('No original Capture-48 PCAP found')
    raw_pcap=max(paths[TARGET]['pcaps'],key=lambda p:p.stat().st_size)
    policy={'status':'new raw-data development replication, not historical-sample reproduction','target':TARGET,
            'source_scenarios':SOURCES,'source_class_cap_per_scenario':SOURCE_CAP,'source_split_seed':8100,
            'prefix_budget_bytes':PREFIX_BYTES,'prefix_rule':'first complete packet records, starting at raw PCAP beginning',
            'target_class_size':TARGET_PER_CLASS,'target_selection':'lowest SHA256 ranks among uniquely linked stable-core matches',
            'tail_exclusion_seconds':TAIL_MARGIN,'malicious_eligibility':'IPv4 TCP; 2..64 total packets; positive originator count',
            'labels':'original published primary label; no relabeling', 'delays_seconds':[0,1,10],
            'operation':'delay all selected malicious-unit packets after their first; preserve packet bytes and within-unit order',
            'decision_threshold':.5,'seeds':SEEDS,'source_holdout_is_capture_disjoint':False,
            'parameter_search':False,'old_experiment_artifacts_read':False}
    js(OUT/'protocol.json',policy)
    js(OUT/'raw_input_manifest.json',{'dataset_root':str(ROOT),'target_raw_pcap':str(raw_pcap),
        'target_raw_pcap_bytes':raw_pcap.stat().st_size,
        'published_logs':{s:str(paths[s]['logs'][0]) for s in paths},'zeek_version':version})
    scratch=OUT/'scratch';scratch.mkdir();prefix=scratch/'fresh_prefix.pcap'
    h,endian,unit,link=header(raw_pcap);max_ts=0;prefix_count=0;size=24
    print('[1/3] Fresh intake: raw PCAP prefix, published-label linkage, and source-only model fitting.',flush=True)
    with open(prefix,'wb') as dst:
        dst.write(h)
        for idx,ts,cap,wire,b,off in packets(raw_pcap):
            if size+16+cap>PREFIX_BYTES:break
            dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(b)
            size+=16+cap;prefix_count+=1;max_ts=max(max_ts,ts)
    if not prefix_count:raise Stop('Empty raw prefix')
    prefix_hash=sha_file(prefix);R['prefix_sha256']=prefix_hash;R['prefix_packets']=prefix_count
    def run_zeek(pcap,name,tap=None):
        d=scratch/name;d.mkdir();args=[zeek,'-C','-r',str(pcap)]
        if tap:args.append(str(tap))
        t=time.perf_counter();R['PCAP_replays']+=1
        with open(OUT/f'{name}_events.txt','w') as so,open(OUT/f'{name}_stderr.txt','w') as se:
            result=subprocess.run(args,cwd=d,stdout=so,stderr=se,timeout=1800)
        if result.returncode or not (d/'conn.log').is_file():raise Stop('Zeek failed: '+name+'; stderr retained')
        return d, time.perf_counter()-t
    intake,seconds=run_zeek(prefix,'intake')
    db=sqlite3.connect(scratch/'clean_index.sqlite');db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA cache_size=-32768')
    db.execute('CREATE TABLE c(k TEXT PRIMARY KEY, payload TEXT, n INTEGER)')
    batch=[];retained=0;cutoff=max_ts/1e9-TAIL_MARGIN
    for row in log_rows(intake/'conn.log'):
        try:
            f=features(row)
            if float(row['ts'])+f['duration']>cutoff:continue
            kk=key(row)
        except (ValueError,KeyError):continue
        saved={**f,'uid':row['uid'],'ts':row['ts'],'id.orig_h':row['id.orig_h'],'id.orig_p':row['id.orig_p'],'id.resp_h':row['id.resp_h'],'id.resp_p':row['id.resp_p']}
        batch.append((kk,json.dumps(saved,separators=(',',':')),1));retained+=1
        if len(batch)>=10000:
            db.executemany('INSERT INTO c VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',batch);batch=[]
    if batch:db.executemany('INSERT INTO c VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',batch)
    db.commit()
    samplers={y:LowestHashSample(TARGET_PER_CLASS,'fresh_capture48_v1|'+str(y)) for y in [0,1]}
    counts=Counter()
    for row in log_rows(paths[TARGET]['logs'][0],labelled=True):
        label=row['label'].lower()
        if label not in ['benign','malicious']:continue
        try:kk=key(row);published=features(row)
        except (ValueError,KeyError):continue
        hit=db.execute('SELECT payload,n FROM c WHERE k=?',(kk,)).fetchone()
        if hit is None or hit[1]!=1:continue
        r=json.loads(hit[0]);counts['unique_key_matches']+=1
        if published['proto']!=r['proto'] or not np.allclose([published[c] for c in F[:-1]],[r[c] for c in F[:-1]],atol=1e-9,rtol=1e-9):continue
        yy=int(label=='malicious');counts[f'stable_core_class_{yy}']+=1
        if yy:
            try:ipv4=ipaddress.ip_address(r['id.orig_h']).version==4 and ipaddress.ip_address(r['id.resp_h']).version==4
            except ValueError:ipv4=False
            if not (ipv4 and r['proto']=='tcp' and 2<=r['orig_pkts']+r['resp_pkts']<=64 and r['orig_pkts']>=1):continue
        counts[f'eligible_class_{yy}']+=1;samplers[yy].add(kk,{**r,'ks':kk,'y':yy})
    db.close();db=None
    js(OUT/'target_intake_counts.json',dict(counts))
    print('Fresh target intake counts:',dict(counts),flush=True)
    if any(len(samplers[y].items)!=TARGET_PER_CLASS for y in [0,1]):raise Stop('Fixed raw-prefix policy yielded fewer than 512 eligible units per class. Counts saved; no sampling threshold was relaxed.')
    clean=pd.DataFrame(samplers[0].values()+samplers[1].values());clean.to_csv(OUT/'fresh_clean_target_sample.csv.gz',index=False,compression='gzip')
    ci=clean.set_index('ks');mk=list(clean.loc[clean.y.eq(1),'ks']);y=clean.y.to_numpy(int)
    source_frames=[];source_counts=[]
    for scenario in SOURCES:
        selections={yy:LowestHashSample(SOURCE_CAP,'source_fresh_v1|'+scenario+'|'+str(yy)) for yy in [0,1]};n=Counter()
        for row in log_rows(paths[scenario]['logs'][0],labelled=True):
            label=row['label'].lower()
            if label not in ['benign','malicious']:continue
            try:f=features(row);kk=key(row)
            except (ValueError,KeyError):continue
            yy=int(label=='malicious');n[yy]+=1;selections[yy].add(kk,{**f,'ks':kk,'y':yy,'source_scenario':scenario})
        if any(len(selections[yy].items)<500 for yy in [0,1]):raise Stop('Source class too small under the fixed protocol: '+scenario)
        source_frames.extend(selections[0].values()+selections[1].values())
        source_counts.append({'scenario':scenario,'available_benign':n[0],'available_malicious':n[1],'selected_benign':len(selections[0].items),'selected_malicious':len(selections[1].items)})
    source=pd.DataFrame(source_frames)
    if source.duplicated(['source_scenario','ks']).any():raise Stop('Duplicate selected source units')
    ids=np.arange(len(source));strata=source.source_scenario+'|'+source.y.astype(str)
    train_ids,hold_ids=train_test_split(ids,test_size=.2,random_state=8100,stratify=strata)
    train=source.iloc[train_ids];hold=source.iloc[hold_ids]
    if set(train.ks)&set(hold.ks) or set(source.ks)&set(clean.ks):raise Stop('Source split or source/target key overlap')
    source.to_csv(OUT/'fresh_source_panel.csv.gz',index=False,compression='gzip')
    pd.DataFrame(source_counts).to_csv(OUT/'source_selection_counts.csv',index=False)
    pd.DataFrame({'ks':source.ks,'source_scenario':source.source_scenario,'allocation':np.where(np.isin(ids,train_ids),'train','holdout')}).to_csv(OUT/'source_allocation.csv',index=False)
    models={};source_metrics=[]
    with threadpool_limits(limits=2):
        for family in ['HGB','LR','PROTOCOL_ONLY_LR']:
            protocol=family=='PROTOCOL_ONLY_LR'
            for seed in SEEDS:
                model=(HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=seed) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,solver='lbfgs',max_iter=5000,random_state=seed))]))
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always',ConvergenceWarning);model.fit(matrix(train,protocol),train.y)
                    if any(issubclass(x.category,ConvergenceWarning) for x in caught):raise Stop('Fixed model failed to converge: '+family)
                models[(family,seed)]=model;R['new_models_trained']+=1
                source_metrics.append({'family':family,'seed':seed,'holdout_rows':len(hold),**model_metrics(hold.y,model.predict_proba(matrix(hold,protocol))[:,1])})
    pd.DataFrame(source_metrics).to_csv(OUT/'source_holdout_metrics.csv',index=False);joblib.dump(models,OUT/'fresh_source_models.joblib',compress=3)
    print('\nSOURCE HOLDOUT\n'+pd.DataFrame(source_metrics).to_string(index=False),flush=True)
    # Build selected packet ownership from the raw prefix, independently of the models.
    descriptions=defaultdict(list);expected={};first={};packet_owner={};watched=set()
    for k in mk:
        r=ci.loc[k];begin=us(r['ts']);end=begin+us(str(r['duration']))+1000
        descriptions[endpoint(r)].append((begin,end,k));expected[k]=int(r.orig_pkts+r.resp_pkts)
    raw={d:defaultdict(list) for d in [0,1,10]};seen=Counter()
    for idx,ts,cap,wire,payload,off in packets(prefix):
        info=tcp4(payload,link)
        if info is None:continue
        ee=tuple(sorted([(info[0],info[1]),(info[2],info[3])]))
        if ee not in descriptions:continue
        tt=(ts+500)//1000;possible=[k for begin,end,k in descriptions[ee] if begin<=tt<=end]
        if len(possible)>1:raise Stop('Ambiguous selected original packet ownership')
        owner=possible[0] if possible else None
        if owner is not None:packet_owner[idx]=owner;seen[owner]+=1;first.setdefault(owner,idx)
        for delay in [0,1,10]:
            delta=delay*10**9 if owner is not None and idx!=first[owner] else 0
            raw[delay][((ts+delta+500)//1000,)+info].append((idx,owner))
    if dict(seen)!=expected:raise Stop('Selected packet counts do not match the fresh extractor records')
    for endpoints in descriptions:
        (h1,p1),(h2,p2)=endpoints;watched.update([f'{h1}|{p1}|{h2}|{p2}',f'{h2}|{p2}|{h1}|{p1}'])
    entries=',\n'.join(json.dumps(x) for x in sorted(watched))
    tap="""const watched: set[string] = {ENTRIES};
event new_packet(c: connection, p: pkt_hdr)
    {
    if ( ! p?$ip || ! p?$tcp ) return;
    local k = fmt("%s|%d|%s|%d", p$ip$src, port_to_count(p$tcp$sport), p$ip$dst, port_to_count(p$tcp$dport));
    if ( k !in watched ) return;
    print fmt("PACKET|%.6f|%s|%s|%d|%s|%d|%d|%d|%d|%d|%d", network_time(), c$uid, p$ip$src, port_to_count(p$tcp$sport), p$ip$dst, port_to_count(p$tcp$dport), p$tcp$seq, p$tcp$ack, p$tcp$flags, p$ip$id, p$ip$len);
    }
""".replace('ENTRIES',entries)
    tap_path=OUT/'packet_membership.zeek';tap_path.write_text(tap)
    check=subprocess.run([zeek,'-b',str(tap_path)],cwd=OUT,capture_output=True,text=True,timeout=30)
    (OUT/'instrumentation_compile_stderr.txt').write_text(check.stderr)
    if check.returncode:raise Stop('Packet instrumentation did not compile')
    results=[];unit_results=[];condition_proofs=[]
    for delay in [0,1,10]:
        print(f'\nEXPERIMENT — FRESH CAPTURE 48, {delay}s PACING',flush=True)
        transformed=prefix;modified_packets=0
        if delay:
            db=sqlite3.connect(scratch/'schedule.sqlite');db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA temp_store=FILE');db.execute('PRAGMA cache_size=-32768')
            db.execute('CREATE TABLE p(ts INTEGER,idx INTEGER,off INTEGER,cap INTEGER,wire INTEGER)');batch=[]
            for idx,ts,cap,wire,payload,off in packets(prefix):
                owner=packet_owner.get(idx);delta=delay*10**9 if owner is not None and idx!=first[owner] else 0
                batch.append((ts+delta,idx,off,cap,wire));modified_packets+=int(delta>0)
                if len(batch)>=50000:db.executemany('INSERT INTO p VALUES(?,?,?,?,?)',batch);batch=[]
            if batch:db.executemany('INSERT INTO p VALUES(?,?,?,?,?)',batch)
            db.commit();db.execute('CREATE INDEX ordered ON p(ts,idx)');db.commit()
            transformed=scratch/f'paced_{delay}s.pcap';last_ts=-1;last_selected={};written=0
            with open(prefix,'rb') as src,open(transformed,'wb') as dst:
                dst.write(h)
                for ts,idx,off,cap,wire in db.execute('SELECT ts,idx,off,cap,wire FROM p ORDER BY ts,idx'):
                    if ts<last_ts:raise Stop('Transformed timestamps unordered')
                    last_ts=ts;owner=packet_owner.get(idx)
                    if owner is not None:
                        if idx<=last_selected.get(owner,-1):raise Stop('Original-unit packet order changed')
                        last_selected[owner]=idx
                    src.seek(off);payload=src.read(cap)
                    if len(payload)!=cap:raise Stop('Packet-copy truncation')
                    dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(payload);written+=1
            db.close();db=None;(scratch/'schedule.sqlite').unlink()
            if written!=prefix_count:raise Stop('Packet count changed')
        d,replay_seconds=run_zeek(transformed,f'condition_{delay}s',tap_path)
        events=defaultdict(list)
        with open(OUT/f'condition_{delay}s_events.txt') as f:
            for line in f:
                if not line.startswith('PACKET|'):continue
                x=line.rstrip('\r\n').split('|')
                if len(x)!=12:raise Stop('Unexpected instrumented event format')
                fp=(us(x[1]),x[3],int(x[4]),x[5],int(x[6]),*[int(z) for z in x[7:12]])
                events[fp].append(x[2])
        if not events:raise Stop('No selected-endpoint packet events')
        mapped=Counter();bad=Counter();owners=defaultdict(set);uid_owner=defaultdict(set);packet_rows=[]
        for fp,uids in events.items():
            if fp not in raw[delay]:
                for uid in uids:uid_owner[uid].add('UNINDEXED')
        for fp,occurrences in raw[delay].items():
            uids=events.get(fp,[])
            if len(occurrences)==1 and len(uids)==1:
                idx,k=occurrences[0];uid=uids[0];uid_owner[uid].add(k if k is not None else 'OUTSIDE_SELECTED')
                if k is not None:mapped[k]+=1;owners[k].add(uid);packet_rows.append({'packet_index':idx,'original_ks':k,'uid':uid,'timestamp_us':fp[0]})
            else:
                for _,k in occurrences:
                    if k is not None:bad[k]+=1
                for uid in uids:uid_owner[uid].add('AMBIGUOUS_OCCURRENCE')
        needed=set().union(*owners.values()) if owners else set();conn={};selected={}
        for row in log_rows(d/'conn.log'):
            try:kk=key(row)
            except (ValueError,KeyError):continue
            if kk in set(clean.ks):
                if kk in selected:raise Stop('Duplicate selected-start key after extraction')
                selected[kk]={**features(row),'ks':kk,'y':int(ci.loc[kk,'y'])}
            if row['uid'] in needed:
                if row['uid'] in conn:raise Stop('Duplicate connection UID')
                conn[row['uid']]={**features(row),'uid':row['uid']}
        if set(selected)!=set(clean.ks):raise Stop('Selected-start records missing; no imputed records accepted')
        frame=pd.DataFrame([selected[k] for k in clean.ks]);uids=sorted(conn)
        conn_frame=pd.DataFrame([conn[u] for u in uids]);audit=[]
        for k in mk:
            uu=owners[k];total_packets=sum(int(conn[u]['orig_pkts']+conn[u]['resp_pkts']) for u in uu if u in conn)
            good=bool(uu) and mapped[k]==expected[k] and bad[k]==0 and uu.issubset(conn) and all(uid_owner[u]=={k} for u in uu) and total_packets==expected[k]
            if delay==0:good=good and len(uu)==1
            audit.append({'ks':k,'expected_packets':expected[k],'mapped_packets':mapped[k],'unresolved_packets':bad[k],
                          'descendant_records':len(uu),'descendant_packet_sum':total_packets,'membership_validated':bool(good)})
        audit=pd.DataFrame(audit);audit.to_csv(OUT/f'membership_{delay}s.csv',index=False)
        pd.DataFrame(packet_rows).to_csv(OUT/f'packet_uid_mapping_{delay}s.csv.gz',index=False,compression='gzip')
        frame.to_csv(OUT/f'selected_features_{delay}s.csv.gz',index=False,compression='gzip')
        conn_frame.to_csv(OUT/f'descendant_features_{delay}s.csv.gz',index=False,compression='gzip')
        if delay==0:
            if not audit.membership_validated.all():raise Stop('Clean packet membership failed; no transformed experiment interpreted')
            if not np.allclose(frame[F[:-1]].to_numpy(float),clean[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(frame.proto,clean.proto):raise Stop('Instrumented clean replay changed selected features')
        good=audit.set_index('ks').membership_validated.to_dict();q=int((~audit.membership_validated).sum())
        with threadpool_limits(limits=2):
            for (family,seed),model in sorted(models.items()):
                protocol=family=='PROTOCOL_ONLY_LR';p0=model.predict_proba(matrix(clean,protocol))[:,1];p=model.predict_proba(matrix(frame,protocol))[:,1]
                d0=p0>=.5;dec=p>=.5;uid_alarm=dict(zip(uids,model.predict_proba(matrix(conn_frame,protocol))[:,1]>=.5))
                initial=d0[y==1];selected_d=dec[y==1]
                alarms=[bool(any(uid_alarm[u] for u in owners[k])) if good[k] else None for k in mk]
                n_alarm=sum(x is True for x in alarms);recovered=sum(bool(cd and not sd and ad is True) for cd,sd,ad in zip(initial,selected_d,alarms))
                row={'family':family,'seed':seed,'delay_seconds':delay,**model_metrics(y,p),
                     'record_accuracy_drop':float((d0==y).mean()-(dec==y).mean()),'original_units':len(mk),
                     'clean_detected_units':int(initial.sum()),'selected_record_detected_units':int(selected_d.sum()),
                     'validated_units':len(mk)-q,'unresolved_units':q,'units_with_descendant_alarm':n_alarm,
                     'selected_losses_recovered':recovered,'unit_detection_lower':n_alarm/len(mk),'unit_detection_upper':(n_alarm+q)/len(mk),
                     'unit_detection_drop_lower':float(initial.mean()-(n_alarm+q)/len(mk)),
                     'unit_detection_drop_upper':float(initial.mean()-n_alarm/len(mk)),
                     'zero_clean_detection_floor':bool(initial.sum()==0)}
                results.append(row)
                unit_results.extend({'family':family,'seed':seed,'delay_seconds':delay,'ks':k,'clean_detected':bool(cd),
                                     'selected_record_detected':bool(sd),'membership_validated':bool(good[k]),'any_descendant_alarm':ad}
                                    for k,cd,sd,ad in zip(mk,initial,selected_d,alarms))
        condition_proofs.append({'delay_seconds':delay,'fresh_prefix_sha256':prefix_hash,'condition_pcap_sha256':sha_file(transformed),
                                 'packets':prefix_count,'delayed_packets':modified_packets,'validated_units':len(mk)-q,
                                 'unresolved_units':q,'replay_wall_seconds':replay_seconds})
        pd.DataFrame(results).to_csv(OUT/'fresh_condition_model_results.csv',index=False)
        pd.DataFrame(unit_results).to_csv(OUT/'fresh_original_unit_results.csv.gz',index=False,compression='gzip')
        js(OUT/'condition_provenance.json',condition_proofs)
        print('\nPACKET MEMBERSHIP\n'+audit.drop(columns='ks').sum(numeric_only=True).to_string(),flush=True)
        print('\nMODEL RESULTS\n'+pd.DataFrame([r for r in results if r['delay_seconds']==delay]).to_string(index=False),flush=True)
        shutil.rmtree(d)
        if delay:transformed.unlink()
    R.update({'status':'FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE','target_original_units':512,'target_benign_units':512,
              'source_training_rows':len(train),'source_holdout_rows':len(hold),'new_models_trained':len(models),
              'conditions_seconds':[0,1,10],'historical_sample_reproduced':False,
              'interpretation':'New bounded-prefix, source-trained development replication using original PCAPs and published labels. Not blind confirmation or application-functionality validation. Preserve unresolved membership and clean detection floors.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    if db is not None:db.close()
    if scratch is not None and scratch.is_dir() and R['status']=='FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE':
        shutil.rmtree(scratch);R['only_this_run_scratch_removed']=True
    elif scratch is not None and scratch.is_dir():R['scratch_retained_for_diagnosis']=True
    js(OUT/'receipt.json',R)
    package=OUT/'fresh_capture48_small_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
