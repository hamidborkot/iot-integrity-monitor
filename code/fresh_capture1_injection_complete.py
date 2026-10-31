# Fresh Capture-1 injection control: clean, one clone, three clones in one batch.
# Reads original IoT-23 data only. No historical CSV/model/helper dependencies.
# Within-capture source fitting is five-tuple-group-disjoint from target units.
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
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from threadpoolctl import threadpool_limits

ROOT=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full');W=Path('/kaggle/working')
CAPTURE='CTU-IoT-Malware-Capture-1-1';LIMIT=256*1024**2;N=512;SOURCE_CAP=2000;TAIL=120;SEEDS=[8101,8102,8103]
OUT=W/('FRESH_RAW_CAPTURE1_INJECTION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(parents=True,exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
R={'status':'STARTED','old_artifacts_read':False,'models_trained':0,'PCAP_replays':0,'historical_outputs_overwritten':False,
   'historical_injection_result_reproduced':False,'independent_confirmation':False,'application_functionality_tested':False,
   'output_directory':str(OUT)}
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
    if not math.isfinite(v) or v<0:raise ValueError('Invalid feature')
    return v

def feature(row):
    r={c:number(row[c]) for c in F[:-1]};r['proto']=row['proto'].lower()
    if r['proto'] not in ['tcp','udp','icmp']:raise ValueError('Unknown protocol')
    return r

def endpoint(row):return tuple(sorted([(row['id.orig_h'],int(row['id.orig_p'])),(row['id.resp_h'],int(row['id.resp_p']))]))
def group_key(row):return hashlib.sha256(json.dumps([endpoint(row),row['proto'].lower()],separators=(',',':')).encode()).hexdigest()
def record_key(row):
    x=[us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()]
    return hashlib.sha256(json.dumps(x,separators=(',',':')).encode()).hexdigest()
def log_rows(path,labelled=False):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):
                fields=line.strip().split()[1:]
                if labelled and 'label' not in fields:raise Stop('Explicit primary label missing')
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Zeek fields missing')
                v=line.rstrip().split()
                if len(v)!=len(fields):raise Stop('Zeek row width differs from header')
                yield dict(zip(fields,v))

class Sample:
    def __init__(self,n,salt):self.n=n;self.salt=salt;self.heap=[];self.rows={}
    def add(self,k,row):
        if k in self.rows:
            if self.rows[k]['y']!=row['y'] or any(self.rows[k][c]!=row[c] for c in F):raise Stop('Conflicting selected labels/features')
            return
        rank=int(hashlib.sha256((self.salt+'|'+k).encode()).hexdigest(),16)
        if len(self.heap)<self.n:heapq.heappush(self.heap,(-rank,k));self.rows[k]=row
        elif rank < -self.heap[0][0]:
            _,old=heapq.heapreplace(self.heap,(-rank,k));self.rows.pop(old);self.rows[k]=row
    def values(self):return [self.rows[k] for _,k in sorted(self.heap,key=lambda x:(-x[0],x[1]))]

def pcap_header(p):
    with open(p,'rb') as f:h=f.read(24)
    if len(h)!=24 or h[:4] not in MAGIC:raise Stop('Classic PCAP required')
    endian,unit=MAGIC[h[:4]];link=struct.unpack(endian+'I',h[20:24])[0]&65535
    if link not in [1,113,276,101,228,12]:raise Stop('Unsupported link type '+str(link))
    return h,endian,unit,link

def packets(p):
    h,endian,unit,link=pcap_header(p)
    with open(p,'rb') as f:
        f.seek(24);i=0
        while True:
            rh=f.read(16)
            if not rh:break
            if len(rh)!=16:raise Stop('Truncated PCAP record')
            sec,sub,cap,wire=struct.unpack(endian+'IIII',rh)
            if cap>16*1024**2:raise Stop('Invalid captured length')
            b=f.read(cap)
            if len(b)!=cap:raise Stop('Truncated packet')
            yield i,sec*10**9+sub*unit,rh,b
            i+=1

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
    thl=(b[t+12]>>4)*4
    if thl<20 or len(b)<t+thl:return None
    sp,dp,seq,ack=struct.unpack('!HHII',b[t:t+12]);length=int.from_bytes(b[o+2:o+4],'big')
    info=(socket.inet_ntoa(b[o+12:o+16]),sp,socket.inet_ntoa(b[o+16:o+20]),dp,seq,ack,b[t+13],int.from_bytes(b[o+4:o+6],'big'),length)
    return info, length==ihl+thl

def encode(df,protocol=False):
    pr=np.column_stack([df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']])
    return pr if protocol else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),pr])

def metrics(y,p):
    d=p>=.5;y=np.asarray(y,int)
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
            'AUROC':float(roc_auc_score(y,p)), 'malicious_recall':float(d[y==1].mean()),'benign_FPR':float(d[y==0].mean())}

scratch=None;db=None
try:
    if not ROOT.is_dir():raise Stop('Original IoT-23 mount missing')
    if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free space is required')
    raw_files=[p for p in ROOT.rglob('*') if p.is_file() and CAPTURE in p.parts]
    pcaps=[p for p in raw_files if p.suffix.lower()=='.pcap'];logs=[p for p in raw_files if p.name=='conn.log.labeled']
    if not pcaps or len(logs)!=1:raise Stop('Expected original Capture-1 PCAP and one published labelled log')
    original=max(pcaps,key=lambda p:p.stat().st_size);published=logs[0]
    zeek=shutil.which('zeek') or '/opt/zeek/bin/zeek'
    v=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30);version=(v.stdout+v.stderr).strip()
    if '8.0.10' not in version:raise Stop('Expected Zeek 8.0.10')
    policy={'scope':'new within-capture development injection control, not historical result replication',
            'capture':CAPTURE,'prefix_budget_bytes':LIMIT,'tail_margin_seconds':TAIL,'target_per_class':N,
            'target_selection':'lowest SHA256 ranks; positive candidates IPv4 TCP, 2..64 total packets',
            'source_selection':'stable-core-linked same-capture rows excluding ALL target five-tuple groups; lowest hashes, cap 2000/class',
            'source_split':'first fold of StratifiedGroupKFold(5, shuffle=True, random_state=8100)',
            'source_groups':'unordered endpoint/port pair plus protocol; no timestamp',
            'target_mutation':'duplicate first existing header-only originator packet, keeping identical timestamp/header/bytes',
            'injection_counts':[0,1,3],'packet_feasibility':'ineligible selected units are retained unchanged; no resampling',
            'matching':'multiplicity-aware packet fingerprint classes; ambiguous ownership retained unresolved',
            'detection_policies':['pure positive record witness','any-overlap alarm sensitivity'],
            'threshold':.5,'seeds':SEEDS,'target_labels_used_for_training':False,
            'functionality_preservation_tested':False,'new_runtime_defense_introduced':False}
    js(OUT/'protocol.json',policy)
    js(OUT/'raw_inputs.json',{'raw_pcap':str(original),'raw_pcap_bytes':original.stat().st_size,'published_log':str(published),'zeek_version':version})
    scratch=OUT/'scratch';scratch.mkdir();prefix=scratch/'source_prefix.pcap'
    h,endian,unit,link=pcap_header(original);size=24;total=0;max_ts=0
    with open(prefix,'wb') as dst:
        dst.write(h)
        for idx,ts,rh,payload in packets(original):
            if size+len(rh)+len(payload)>LIMIT:break
            dst.write(rh);dst.write(payload);size+=len(rh)+len(payload);total+=1;max_ts=max(max_ts,ts)
    if not total:raise Stop('Empty raw prefix')
    prefix_hash=sha_file(prefix);R['prefix_packets']=total;R['prefix_sha256']=prefix_hash
    def replay(pcap,name,tap=None):
        d=scratch/name;d.mkdir();cmd=[zeek,'-C','-r',str(pcap)]
        if tap:cmd.append(str(tap))
        R['PCAP_replays']+=1;t=time.perf_counter()
        with open(OUT/f'{name}_events.txt','w') as so,open(OUT/f'{name}_stderr.txt','w') as se:
            process=subprocess.run(cmd,cwd=d,stdout=so,stderr=se,timeout=1800)
        if process.returncode or not (d/'conn.log').is_file():raise Stop('Zeek replay failed: '+name)
        return d,time.perf_counter()-t
    print('[1/3] Raw-data linkage, disjoint within-capture source fitting, and clean control.',flush=True)
    intake,_=replay(prefix,'intake');cutoff=max_ts/1e9-TAIL
    db=sqlite3.connect(scratch/'clean_index.sqlite');db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF');db.execute('PRAGMA cache_size=-32768')
    db.execute('CREATE TABLE c(k TEXT PRIMARY KEY,payload TEXT,n INTEGER)');batch=[]
    for row in log_rows(intake/'conn.log'):
        try:f=feature(row);kk=record_key(row)
        except (ValueError,KeyError):continue
        if float(row['ts'])+f['duration']>cutoff:continue
        r={**f,'uid':row['uid'],'ts':row['ts'],'id.orig_h':row['id.orig_h'],'id.orig_p':row['id.orig_p'],'id.resp_h':row['id.resp_h'],'id.resp_p':row['id.resp_p'],'group':group_key(row)}
        batch.append((kk,json.dumps(r,separators=(',',':')),1))
        if len(batch)>=10000:db.executemany('INSERT INTO c VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',batch);batch=[]
    if batch:db.executemany('INSERT INTO c VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=n+1',batch)
    db.commit()
    def linked_rows():
        for row in log_rows(published,True):
            label=row['label'].lower()
            if label not in ['benign','malicious']:continue
            try:kk=record_key(row);pf=feature(row)
            except (ValueError,KeyError):continue
            hit=db.execute('SELECT payload,n FROM c WHERE k=?',(kk,)).fetchone()
            if hit is None or hit[1]!=1:continue
            r=json.loads(hit[0])
            if pf['proto']!=r['proto'] or not np.allclose([pf[c] for c in F[:-1]],[r[c] for c in F[:-1]],atol=1e-9,rtol=1e-9):continue
            yield kk,{**r,'ks':kk,'y':int(label=='malicious')}
    targets={yy:Sample(N,'capture1_injection_target_v1|'+str(yy)) for yy in [0,1]};counts=Counter()
    for kk,row in linked_rows():
        yy=row['y'];counts[f'stable_class_{yy}']+=1
        if yy:
            ipv4=ipaddress.ip_address(row['id.orig_h']).version==4 and ipaddress.ip_address(row['id.resp_h']).version==4
            if not (ipv4 and row['proto']=='tcp' and 2<=row['orig_pkts']+row['resp_pkts']<=64 and row['orig_pkts']>=1):continue
        counts[f'target_eligible_class_{yy}']+=1;targets[yy].add(kk,row)
    js(OUT/'intake_counts.json',dict(counts));print('Intake:',dict(counts),flush=True)
    if any(len(targets[yy].rows)!=N for yy in [0,1]):raise Stop('Fixed prefix yields fewer than 512 target units/class; no eligibility threshold relaxed')
    clean=pd.DataFrame(targets[0].values()+targets[1].values())
    if clean.ks.duplicated().any():raise Stop('Conflicting target keys')
    wanted=set(clean.ks);excluded_groups=set(clean.group);ci=clean.set_index('ks');y=clean.y.to_numpy(int);mk=list(clean.loc[y==1,'ks'])
    source_samples={yy:Sample(SOURCE_CAP,'capture1_source_v1|'+str(yy)) for yy in [0,1]}
    for kk,row in linked_rows():
        if row['group'] not in excluded_groups:source_samples[row['y']].add(kk,row)
    db.close();db=None
    if any(len(source_samples[yy].rows)<500 for yy in [0,1]):raise Stop('Insufficient group-disjoint source rows under fixed protocol')
    source=pd.DataFrame(source_samples[0].values()+source_samples[1].values())
    if source.ks.duplicated().any() or set(source.group)&excluded_groups:raise Stop('Source/target group leakage')
    if source.group.nunique()<5:raise Stop('Too few source groups')
    split=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=8100)
    tr,ho=next(split.split(np.zeros(len(source)),source.y,groups=source.group))
    train=source.iloc[tr];hold=source.iloc[ho]
    if set(train.group)&set(hold.group) or set(train.y)!={0,1} or set(hold.y)!={0,1}:raise Stop('Source group split lacks both classes or overlaps')
    clean.to_csv(OUT/'target_clean.csv.gz',index=False,compression='gzip');source.to_csv(OUT/'source_panel.csv.gz',index=False,compression='gzip')
    pd.DataFrame({'ks':source.ks,'group':source.group,'allocation':np.where(np.isin(np.arange(len(source)),tr),'train','holdout')}).to_csv(OUT/'source_allocation.csv',index=False)
    models={};sm=[]
    with threadpool_limits(limits=2):
        for family in ['HGB','LR','PROTOCOL_ONLY_LR']:
            protocol=family=='PROTOCOL_ONLY_LR'
            for seed in SEEDS:
                model=(HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=seed) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,solver='lbfgs',max_iter=5000,random_state=seed))]))
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always',ConvergenceWarning);model.fit(encode(train,protocol),train.y)
                    if any(issubclass(x.category,ConvergenceWarning) for x in caught):raise Stop('Fixed model did not converge')
                models[(family,seed)]=model;R['models_trained']+=1;sm.append({'family':family,'seed':seed,'holdout_rows':len(hold),**metrics(hold.y,model.predict_proba(encode(hold,protocol))[:,1])})
    pd.DataFrame(sm).to_csv(OUT/'source_holdout_metrics.csv',index=False);joblib.dump(models,OUT/'source_models.joblib',compress=3)
    print('\nSOURCE HOLDOUT\n'+pd.DataFrame(sm).to_string(index=False),flush=True)
    descriptions=defaultdict(list);expected={};clone_index={};clone_fingerprint={};packet_owner={};raw=defaultdict(list);seen=Counter()
    for k in mk:
        r=ci.loc[k];begin=us(r['ts']);descriptions[endpoint(r)].append((begin,begin+us(str(r.duration))+1000,k));expected[k]=int(r.orig_pkts+r.resp_pkts)
    for idx,ts,rh,payload in packets(prefix):
        parsed=tcp4(payload,link)
        if parsed is None:continue
        info,header_only=parsed;ee=tuple(sorted([(info[0],info[1]),(info[2],info[3])]))
        if ee not in descriptions:continue
        tt=(ts+500)//1000;possible=[k for begin,end,k in descriptions[ee] if begin<=tt<=end]
        if len(possible)>1:raise Stop('Ambiguous original packet ownership')
        owner=possible[0] if possible else None;fp=(tt,)+info;raw[fp].append((idx,owner))
        if owner:
            packet_owner[idx]=owner;seen[owner]+=1;r=ci.loc[owner]
            if header_only and info[0]==r['id.orig_h'] and info[1]==int(r['id.orig_p']) and owner not in clone_index:
                clone_index[owner]=idx;clone_fingerprint[owner]=fp
    if dict(seen)!=expected:raise Stop('Original packet counts do not match selected records')
    eligible=set(clone_index);R['injection_eligible_units']=len(eligible)
    pd.DataFrame([{'ks':k,'injection_eligible':k in eligible,'clone_source_packet_index':clone_index.get(k)} for k in mk]).to_csv(OUT/'packet_feasibility.csv',index=False)
    watched=set()
    for ee in descriptions:
        (a,ap),(b,bp)=ee;watched.update([f'{a}|{ap}|{b}|{bp}',f'{b}|{bp}|{a}|{ap}'])
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
    compile_result=subprocess.run([zeek,'-b',str(tap_path)],cwd=OUT,capture_output=True,text=True,timeout=30)
    (OUT/'zeek_compile_stderr.txt').write_text(compile_result.stderr)
    if compile_result.returncode:raise Stop('Instrumentation did not compile')
    clone_by_idx={idx:k for k,idx in clone_index.items()}
    selected_tuples=set(zip(clean['id.orig_h'].astype(str),clean['id.orig_p'].astype(str),clean['id.resp_h'].astype(str),clean['id.resp_p'].astype(str),clean.proto))
    all_results=[];all_units=[];proofs=[]
    for clones in [0,1,3]:
        print(f'\nEXPERIMENT — {clones} DUPLICATE PACKET(S) PER ELIGIBLE ORIGINAL UNIT',flush=True)
        transformed=prefix;added=0;expected_added=clones*len(eligible)
        if clones:
            transformed=scratch/f'injection_{clones}.pcap'
            with open(transformed,'wb') as dst:
                dst.write(h)
                for idx,ts,rh,payload in packets(prefix):
                    dst.write(rh);dst.write(payload)
                    if idx in clone_by_idx:
                        for _ in range(clones):dst.write(rh);dst.write(payload);added+=1
            # Independently verify every original record and every exact cloned record.
            with open(transformed,'rb') as check:
                if check.read(24)!=h:raise Stop('PCAP header changed')
                for idx,ts,rh,payload in packets(prefix):
                    record=rh+payload
                    if check.read(len(record))!=record:raise Stop('Original packet record was altered')
                    if idx in clone_by_idx:
                        for _ in range(clones):
                            if check.read(len(record))!=record:raise Stop('Injected record is not the declared exact duplicate')
                if check.read(1):raise Stop('Unexpected extra transformed records')
            if added!=expected_added:raise Stop('Injected packet count differs')
        d,elapsed=replay(transformed,f'injection_{clones}',tap_path)
        events=defaultdict(list)
        with open(OUT/f'injection_{clones}_events.txt') as f:
            for line in f:
                if not line.startswith('PACKET|'):continue
                x=line.rstrip('\r\n').split('|')
                if len(x)!=12:raise Stop('Unexpected packet-event format')
                fp=(us(x[1]),x[3],int(x[4]),x[5],int(x[6]),*[int(z) for z in x[7:12]])
                events[fp].append(x[2])
        if not events:raise Stop('No watched packet events')
        expected_groups={fp:list(v) for fp,v in raw.items()}
        for k in eligible:
            for j in range(clones):expected_groups[clone_fingerprint[k]].append((f'clone_{j}',k))
        mapped=Counter();ambiguous=Counter();owner_uids=defaultdict(set);uid_owner=defaultdict(set);uid_selected_count=Counter();fingerprint_rows=[]
        for fp,uids in events.items():
            if fp not in expected_groups:
                for uid in uids:uid_owner[uid].add('UNINDEXED_EVENT')
        for fp,occurrences in expected_groups.items():
            uids=events.get(fp,[]);owners={owner if owner is not None else 'OUTSIDE_SELECTED' for _,owner in occurrences}
            target_owners={x for x in owners if x!='OUTSIDE_SELECTED'}
            ownership_resolved=len(occurrences)==len(uids) and len(owners)==1
            if ownership_resolved:
                owner=next(iter(owners))
                for uid,n in Counter(uids).items():
                    uid_owner[uid].add(owner)
                    if owner!='OUTSIDE_SELECTED':mapped[owner]+=n;owner_uids[owner].add(uid);uid_selected_count[uid]+=n
                    fingerprint_rows.append({'fingerprint_sha256':hashlib.sha256(repr(fp).encode()).hexdigest(),'original_ks':owner,'uid':uid,'occurrences':n,'matching':'ownership of identical-packet equivalence class; not clone-identity proof'})
            else:
                for owner in target_owners:ambiguous[owner]+=sum(x==owner for _,x in occurrences)
                for uid in uids:uid_owner[uid].add('AMBIGUOUS_CLASS')
        needed=set().union(*owner_uids.values()) if owner_uids else set();records={};selected={}
        for row in log_rows(d/'conn.log'):
            ident=(row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower())
            if ident not in selected_tuples and row['uid'] not in needed:continue
            kk=record_key(row)
            if kk in wanted:
                if kk in selected:raise Stop('Duplicate original-start record')
                selected[kk]={**feature(row),'ks':kk,'y':int(ci.loc[kk,'y'])}
            if row['uid'] in needed:
                if row['uid'] in records:raise Stop('Duplicate extracted UID')
                records[row['uid']]={**feature(row),'uid':row['uid']}
        # Missing original-start records remain explicit; do not synthesize them.
        present=[k for k in clean.ks if k in selected]
        selected_frame=pd.DataFrame([selected[k] for k in present])
        if not len(present):raise Stop('No original-start records remain for the selected-record diagnostic')
        selected_frame.to_csv(OUT/f'selected_features_k{clones}.csv.gz',index=False,compression='gzip')
        uid_order=sorted(records);record_frame=pd.DataFrame([records[u] for u in uid_order],columns=F+['uid'])
        record_frame.to_csv(OUT/f'descendant_features_k{clones}.csv.gz',index=False,compression='gzip')
        purity={}
        for uid in uid_order:
            counted=int(records[uid]['orig_pkts']+records[uid]['resp_pkts'])
            purity[uid]=bool(len(uid_owner[uid])==1 and not uid_owner[uid]&{'OUTSIDE_SELECTED','UNINDEXED_EVENT','AMBIGUOUS_CLASS'} and counted==uid_selected_count[uid])
        # Explicit event counts protect against untracked packets in a witness record.
        event_counts=Counter(uid for values in events.values() for uid in values)
        for uid in purity:purity[uid]=bool(purity[uid] and event_counts[uid]==int(records[uid]['orig_pkts']+records[uid]['resp_pkts']))
        lineage=[]
        for k in mk:
            expected_k=expected[k]+(clones if k in eligible else 0)
            complete=mapped[k]==expected_k and ambiguous[k]==0 and bool(owner_uids[k]) and owner_uids[k].issubset(records)
            lineage.append({'ks':k,'expected_packets_including_clones':expected_k,'mapped_packets':mapped[k],'ambiguous_equivalence_class_packets':ambiguous[k],
                'descendant_UIDs':len(owner_uids[k]),'packet_membership_complete':bool(complete),
                'all_descendants_pure':bool(owner_uids[k]) and all(purity.get(u,False) for u in owner_uids[k])})
        lt=pd.DataFrame(lineage);lt.to_csv(OUT/f'packet_accounting_k{clones}.csv',index=False)
        pd.DataFrame(fingerprint_rows).to_csv(OUT/f'equivalence_class_UID_map_k{clones}.csv.gz',index=False,compression='gzip')
        if clones==0:
            if not lt.packet_membership_complete.all() or not lt.all_descendants_pure.all() or set(present)!=wanted:raise Stop('Clean instrumentation/membership did not validate')
            ordered=selected_frame.set_index('ks').loc[clean.ks]
            if not np.allclose(ordered[F[:-1]].to_numpy(float),clean[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(ordered.proto,clean.proto):raise Stop('Clean replay features changed')
        complete_map=lt.set_index('ks').packet_membership_complete.to_dict()
        with threadpool_limits(limits=2):
            for (family,seed),model in sorted(models.items()):
                protocol=family=='PROTOCOL_ONLY_LR';clean_p=model.predict_proba(encode(clean,protocol))[:,1];initial=clean_p[y==1]>=.5
                sp=model.predict_proba(encode(selected_frame,protocol))[:,1];selected_dec=dict(zip(selected_frame.ks,sp>=.5))
                alarms=dict(zip(uid_order,model.predict_proba(encode(record_frame,protocol))[:,1]>=.5)) if len(record_frame) else {}
                definite=absent=unresolved=overlap=0
                for k,initial_d in zip(mk,initial):
                    uu=owner_uids[k];any_alarm=any(alarms.get(u,False) for u in uu)
                    witness=any(alarms.get(u,False) and purity.get(u,False) for u in uu)
                    no_alarm=bool(complete_map[k] and not any_alarm)
                    state='DETECTED_PURE_WITNESS' if witness else ('NO_DESCENDANT_ALARM' if no_alarm else 'UNRESOLVED')
                    definite+=int(witness);absent+=int(no_alarm);unresolved+=int(state=='UNRESOLVED');overlap+=int(any_alarm)
                    all_units.append({'clones':clones,'family':family,'seed':seed,'ks':k,'injection_eligible':k in eligible,'clean_detected':bool(initial_d),
                        'selected_record_detected':selected_dec.get(k),'packet_membership_complete':bool(complete_map[k]),'pure_alarm_witness':bool(witness),'any_overlap_alarm':bool(any_alarm),'classification':state})
                yy=selected_frame.y.to_numpy(int);sd=sp>=.5
                all_results.append({'clones_per_eligible_unit':clones,'family':family,'seed':seed,'selected_records_retained':len(present),
                    'selected_malicious_records_retained':int((yy==1).sum()),'selected_record_accuracy':float((sd==yy).mean()),
                    'selected_record_recall':float(sd[yy==1].mean()) if (yy==1).any() else np.nan,
                    'selected_record_benign_FPR':float(sd[yy==0].mean()) if (yy==0).any() else np.nan,
                    'original_units':N,'injection_eligible_units':len(eligible),'modified_units':len(eligible) if clones else 0,
                    'added_packets':added,'clean_detected_units':int(initial.sum()),'pure_alarm_witness_units':definite,
                    'no_descendant_alarm_units':absent,'unresolved_units':unresolved,
                    'unit_detection_lower':definite/N,'unit_detection_upper':(definite+unresolved)/N,
                    'unit_detection_drop_lower':float(initial.mean()-(definite+unresolved)/N),
                    'unit_detection_drop_upper':float(initial.mean()-definite/N),
                    'any_overlap_alarm_units':overlap})
        proofs.append({'clones':clones,'prefix_packets':total,'expected_output_packets':total+expected_added,'verified_added_packets':added,
            'source_prefix_sha256':prefix_hash,'condition_sha256':sha_file(transformed),'original_and_injected_records_verified':True,
            'complete_original_memberships':int(lt.packet_membership_complete.sum()),'replay_wall_seconds':elapsed})
        js(OUT/'condition_provenance.json',proofs);pd.DataFrame(all_results).to_csv(OUT/'injection_control_model_results.csv',index=False)
        pd.DataFrame(all_units).to_csv(OUT/'injection_original_unit_results.csv.gz',index=False,compression='gzip')
        print('\nPACKET ACCOUNTING\n'+lt.drop(columns='ks').sum(numeric_only=True).to_string(),flush=True)
        print('\nINJECTION RESULTS\n'+pd.DataFrame([r for r in all_results if r['clones_per_eligible_unit']==clones]).to_string(index=False),flush=True)
        shutil.rmtree(d)
        if clones:transformed.unlink()
    R.update({'status':'FRESH_CAPTURE1_NULL_K1_K3_INJECTION_CONTROL_COMPLETE','conditions_clones':[0,1,3],
        'source_training_rows':len(train),'source_holdout_rows':len(hold),'target_original_units':N,
        'source_target_five_tuple_group_disjoint':True,'source_train_holdout_group_disjoint':True,
        'packet_multiset_construction_verified':True,'duplicate_occurrence_identity_claimed':False,
        'interpretation':'New within-capture, group-disjoint development control. Exact duplicate packets are matched by multiplicity and original-unit ownership, not by fabricated one-to-one clone identities. No historical numerical-result, protocol-functionality, or independent-confirmation claim.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    if db is not None:db.close()
    if scratch is not None and scratch.is_dir() and R['status']=='FRESH_CAPTURE1_NULL_K1_K3_INJECTION_CONTROL_COMPLETE':
        shutil.rmtree(scratch);R['only_this_run_scratch_removed']=True
    elif scratch is not None and scratch.is_dir():R['scratch_retained_for_diagnosis']=True
    js(OUT/'receipt.json',R)
    package=OUT/'capture1_injection_small_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
