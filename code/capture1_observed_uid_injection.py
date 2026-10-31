# Capture-1 injection continuation using observed clean Zeek UIDs, not durations.
# Reuses the just-fitted source models; runs clean, k=1, k=3 and saves a checkpoint.
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib, json, math, shutil, socket, struct, subprocess, time, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('CAPTURE1_UID_INJECTION_CONTINUATION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
HORIZONS=[1,5,10,30,60]
R={'status':'STARTED','models_retrained':False,'PCAP_replays':0,'duration_used_for_packet_ownership':False,
   'original_results_overwritten':False,'application_functionality_tested':False,'independent_confirmation':False,
   'P5_final_release_complete':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def key(row):return hashlib.sha256(json.dumps([us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()],separators=(',',':')).encode()).hexdigest()
def ep(row):return tuple(sorted([(row['id.orig_h'],int(row['id.orig_p'])),(row['id.resp_h'],int(row['id.resp_p']))]))
def number(x):
    v=0. if x in ['-','',None] else float(x)
    if not math.isfinite(v) or v<0:raise Stop('Invalid feature value')
    return v

def feature(row):
    r={c:number(row[c]) for c in F[:-1]};r['proto']=row['proto'].lower()
    if r['proto'] not in ['tcp','udp','icmp']:raise Stop('Unexpected protocol')
    return r

def log_rows(path):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):fields=line.strip().split()[1:]
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Missing Zeek header')
                values=line.rstrip().split()
                if len(values)!=len(fields):raise Stop('Zeek record width differs')
                yield dict(zip(fields,values))

def header(path):
    with open(path,'rb') as f:h=f.read(24)
    if len(h)!=24 or h[:4] not in MAGIC:raise Stop('Classic PCAP required')
    endian,unit=MAGIC[h[:4]];link=struct.unpack(endian+'I',h[20:24])[0]&65535
    if link not in [1,113,276,101,228,12]:raise Stop('Unsupported link type')
    return h,endian,unit,link

def packets(path):
    h,endian,unit,link=header(path)
    with open(path,'rb') as f:
        f.seek(24);idx=0
        while True:
            rh=f.read(16)
            if not rh:break
            if len(rh)!=16:raise Stop('Truncated packet header')
            sec,sub,cap,wire=struct.unpack(endian+'IIII',rh)
            if cap>16*1024**2:raise Stop('Invalid packet length')
            payload=f.read(cap)
            if len(payload)!=cap:raise Stop('Truncated packet')
            yield idx,sec*10**9+sub*unit,rh,payload
            idx+=1

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
    return info,length==ihl+thl

def encode(df,protocol):
    p=np.column_stack([df.proto.eq(s).to_numpy(float) for s in ['tcp','udp','icmp']])
    return p if protocol else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),p])

def checkpoint():
    # Snapshot only compact evidence, never PCAPs, scratch, nested ZIPs, or models.
    roots=[OUT]
    prefixes=('LINEAGE_MONITOR_','LINEAGE_WINDOW_ORDER_','LINEAGE_TRANSFORM_','LINEAGE_BATCH4_',
              'LINEAGE_PACKET_BASELINE_','LINEAGE_TIMING_','LINEAGE_MATCHED_MODEL_',
              'FRESH_RAW_CAPTURE48_','CAPTURE48_MERGE_WITNESS_','FRESH_RAW_CAPTURE1_INJECTION_')
    roots.extend(p for p in W.iterdir() if p.is_dir() and p.name.startswith(prefixes))
    included=[];total_bytes=0;limit=128*1024**2;package=OUT/'validated_work_checkpoint.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for root in roots:
            for p in root.rglob('*'):
                if not p.is_file() or p.is_symlink():continue
                rel=p.relative_to(root)
                if any(x in {'scratch','temporary_replay','clean_replay'} for x in rel.parts):continue
                if p.suffix.lower() not in {'.csv','.gz','.json','.jsonl','.py'}:continue
                size=p.stat().st_size
                if size>8*1024**2 or total_bytes+size>limit:continue
                arc=str(Path(root.name)/rel);z.write(p,arcname=arc);total_bytes+=size
                included.append({'member':arc,'bytes':size,'sha256':sha(p)})
        z.writestr('CHECKPOINT_MANIFEST.json',json.dumps(included,indent=2))
    with zipfile.ZipFile(package) as z:
        bad=z.testzip()
    return {'archive':str(package),'files':len(included),'input_bytes':total_bytes,'archive_bytes':package.stat().st_size,
            'archive_sha256':sha(package),'CRC_verified':bad is None,'final_release':False,'models_and_large_inputs_included':False}

scratch=None
try:
    sources=[]
    for p in W.glob('FRESH_RAW_CAPTURE1_INJECTION_*'):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        r=json.loads(rp.read_text())
        if r.get('reason')=='Original packet counts do not match selected records' and (p/'source_models.joblib').is_file() and (p/'target_clean.csv.gz').is_file():sources.append((p,r))
    if not sources:raise Stop('The just-computed Capture-1 source models and retained raw prefix were not found')
    previous,old=max(sources,key=lambda x:x[0].name)
    prefix=previous/'scratch/source_prefix.pcap'
    if not prefix.is_file() or sha(prefix)!=old['prefix_sha256']:raise Stop('Retained raw prefix missing or changed; no substitute was chosen')
    clean=pd.read_csv(previous/'target_clean.csv.gz',dtype=str,keep_default_na=False)
    for c in F[:-1]:clean[c]=pd.to_numeric(clean[c],errors='raise').astype(float)
    clean['proto']=clean.proto.str.lower();yy=pd.to_numeric(clean.y,errors='raise')
    if not yy.isin([0,1]).all():raise Stop('Invalid cohort labels')
    clean['y']=yy.astype(int);y=clean.y.to_numpy(int)
    if len(clean)!=1024 or clean.ks.duplicated().any() or int((y==1).sum())!=512:raise Stop('Original selected cohort differs')
    ci=clean.set_index('ks');mk=list(clean.loc[y==1,'ks']);wanted=set(clean.ks)
    models=joblib.load(previous/'source_models.joblib')
    if len(models)!=9:raise Stop('Expected nine already fitted models')
    if shutil.disk_usage(W).free<2*1024**3:raise Stop('At least 2 GiB free required; no files deleted')
    zeek=shutil.which('zeek') or '/opt/zeek/bin/zeek'
    v=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30);version=(v.stdout+v.stderr).strip()
    if '8.0.10' not in version:raise Stop('Expected Zeek 8.0.10')
    h,endian,unit,link=header(prefix);expected={k:int(ci.loc[k,'orig_pkts']+ci.loc[k,'resp_pkts']) for k in mk}
    endpoints={ep(ci.loc[k]) for k in mk};watched=set()
    for ee in endpoints:
        (a,ap),(b,bp)=ee;watched.update([f'{a}|{ap}|{b}|{bp}',f'{b}|{bp}|{a}|{ap}'])
    entries=',\n'.join(json.dumps(x) for x in sorted(watched))
    tap="""@load base/protocols/conn
const watched: set[string] = {ENTRIES};
global watched_uids: set[string] = set();
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
    tap_path=OUT/'packet_membership.zeek';tap_path.write_text(tap)
    zc=subprocess.run([zeek,'-b',str(tap_path)],cwd=OUT,capture_output=True,text=True,timeout=30)
    (OUT/'compile_stderr.txt').write_text(zc.stderr)
    if zc.returncode:raise Stop('Instrumentation compile failed')
    selected_tuples=set(zip(clean['id.orig_h'],clean['id.orig_p'],clean['id.resp_h'],clean['id.resp_p'],clean.proto))
    scratch=OUT/'scratch';scratch.mkdir();raw=defaultdict(list);raw_meta={};input_count=0
    print('[1/3] Assigning original packet ownership from observed clean connection UIDs, not durations.',flush=True)
    for idx,ts,rh,payload in packets(prefix):
        input_count+=1;parsed=tcp4(payload,link)
        if parsed is None:continue
        info,header_only=parsed;ee=tuple(sorted([(info[0],info[1]),(info[2],info[3])]))
        if ee in endpoints:
            fp=((ts+500)//1000,)+info;raw[fp].append(idx);raw_meta[idx]=(fp,header_only)
    def run(pcap,name):
        d=scratch/name;d.mkdir();t=time.perf_counter();R['PCAP_replays']+=1
        with open(OUT/f'{name}_events.txt','w') as so,open(OUT/f'{name}_stderr.txt','w') as se:
            result=subprocess.run([zeek,'-C','-r',str(pcap),str(tap_path)],cwd=d,stdout=so,stderr=se,timeout=1800)
        if result.returncode or not (d/'conn.log').is_file():raise Stop('Zeek replay failed: '+name)
        events=defaultdict(list);available={}
        with open(OUT/f'{name}_events.txt') as f:
            for line in f:
                if line.startswith('AVAILABLE|'):
                    x=line.rstrip('\r\n').split('|')
                    if len(x)!=3:raise Stop('Bad availability event')
                    tt=us(x[1]);available[x[2]]=min(tt,available.get(x[2],tt))
                elif line.startswith('PACKET|'):
                    x=line.rstrip('\r\n').split('|')
                    if len(x)!=12:raise Stop('Bad packet event')
                    fp=(us(x[1]),x[3],int(x[4]),x[5],int(x[6]),*[int(v) for v in x[7:12]])
                    events[fp].append(x[2])
        if not events:raise Stop('No watched packet events')
        return d,events,available,time.perf_counter()-t
    baseline_dir,clean_events,clean_available,clean_seconds=run(prefix,'clean')
    baseline_rows={};baseline_uid_owner={}
    for row in log_rows(baseline_dir/'conn.log'):
        ident=(row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower())
        if ident not in selected_tuples:continue
        k=key(row)
        if k in wanted:
            if k in baseline_rows:raise Stop('Ambiguous original-start connection key')
            baseline_rows[k]={**feature(row),'ks':k,'y':int(ci.loc[k,'y']),'uid':row['uid']}
            if k in expected:baseline_uid_owner[row['uid']]=k
    if set(baseline_rows)!=wanted:raise Stop('Clean replay original-start rows missing')
    fresh=pd.DataFrame([baseline_rows[k] for k in clean.ks])
    if not np.allclose(fresh[F[:-1]].to_numpy(float),clean[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(fresh.proto,clean.proto):raise Stop('Clean feature invariance failed')
    original_owner={};seen=Counter();ambiguous=Counter();source_groups={};uid_events=Counter(u for values in clean_events.values() for u in values)
    for fp,indices in raw.items():
        uids=clean_events.get(fp,[])
        if len(indices)==len(uids) and len(set(uids))==1:
            uid=uids[0];owner=baseline_uid_owner.get(uid)
            source_groups[fp]=owner
            if owner:
                for idx in indices:original_owner[idx]=owner;seen[owner]+=1
        else:
            for uid in set(uids):
                owner=baseline_uid_owner.get(uid)
                if owner:ambiguous[owner]+=1
            source_groups[fp]='AMBIGUOUS_SOURCE_CLASS'
    base_audit=[]
    for k in mk:
        uid=baseline_rows[k]['uid'];good=(seen[k]==expected[k] and uid_events[uid]==expected[k] and ambiguous[k]==0)
        base_audit.append({'ks':k,'expected_packets':expected[k],'UID_assigned_packets':seen[k],
            'instrumented_UID_packet_count':uid_events[uid],'ambiguous_fingerprint_classes':ambiguous[k],
            'clean_UID_membership_validated':bool(good)})
    ba=pd.DataFrame(base_audit);ba.to_csv(OUT/'clean_UID_membership.csv',index=False)
    print('\nCLEAN UID MEMBERSHIP\n'+ba.drop(columns='ks').sum(numeric_only=True).to_string(),flush=True)
    if not ba.clean_UID_membership_validated.all():raise Stop('Some original packets still cannot be assigned uniquely by observed UIDs. No count was forced and no selected unit was dropped.')
    clone_index={};clone_fp={}
    for idx in sorted(original_owner):
        owner=original_owner[idx];fp,header_only=raw_meta[idx];row=ci.loc[owner]
        if header_only and fp[1]==row['id.orig_h'] and fp[2]==int(row['id.orig_p']) and owner not in clone_index:
            clone_index[owner]=idx;clone_fp[owner]=fp
    eligible=set(clone_index);by_index={idx:k for k,idx in clone_index.items()}
    pd.DataFrame([{'ks':k,'clone_eligible':k in eligible,'source_packet_index':clone_index.get(k)} for k in mk]).to_csv(OUT/'clone_feasibility.csv',index=False)
    if not eligible:raise Stop('No header-only originator packet is available; no injection control claimed')
    js(OUT/'policy.json',{'source_run':str(previous),'ownership':'clean instrumented UID matched to exact original-start key and verified features',
        'clones':[0,1,3],'clone_timestamp':'unchanged','cohort_resampled':False,'source_models_refitted':False,
        'matching':'multiplicity-aware fingerprint ownership; no individual clone-identity assertion',
        'availability':'network_time at Conn::log_conn, immediate final-record consumption; excludes model CPU time',
        'horizons_seconds':HORIZONS,'ineligible_original_units':'retained unchanged','functionality_tested':False})
    js(OUT/'input_manifest.json',{'source_run':str(previous),'prefix_sha256':sha(prefix),
        'source_models_sha256':sha(previous/'source_models.joblib'),'target_clean_sha256':sha(previous/'target_clean.csv.gz')})
    results=[];units=[];timings=[];proofs=[]
    for clones in [0,1,3]:
        name='clean' if clones==0 else f'injection_{clones}'
        print(f'\nCONTROL — {clones} CLONE(S) PER ELIGIBLE ORIGINAL UNIT',flush=True)
        transformed=prefix;added=0
        if clones:
            print('[2/3] Constructing and verifying exact duplicated packet records.',flush=True)
            transformed=scratch/f'injection_{clones}.pcap'
            with open(transformed,'wb') as dst:
                dst.write(h)
                for idx,ts,rh,payload in packets(prefix):
                    record=rh+payload;dst.write(record)
                    if idx in by_index:
                        for _ in range(clones):dst.write(record);added+=1
            with open(transformed,'rb') as f:
                if f.read(24)!=h:raise Stop('PCAP header changed')
                for idx,ts,rh,payload in packets(prefix):
                    record=rh+payload
                    if f.read(len(record))!=record:raise Stop('Original packet altered')
                    if idx in by_index:
                        for _ in range(clones):
                            if f.read(len(record))!=record:raise Stop('Clone differs from its declared source packet')
                if f.read(1):raise Stop('Unexpected extra bytes')
            if added!=clones*len(eligible):raise Stop('Added packet count differs')
            d,events,available,elapsed=run(transformed,name)
        else:d,events,available,elapsed=baseline_dir,clean_events,clean_available,clean_seconds
        expected_fp_counts={fp:len(indices) for fp,indices in raw.items()}
        for k in eligible:expected_fp_counts[clone_fp[k]]+=clones
        mapped=Counter();bad=Counter();owners=defaultdict(set);uid_owner=defaultdict(set);tracked=Counter();class_rows=[]
        for fp,uids in events.items():
            if fp not in raw:
                for u in uids:uid_owner[u].add('UNINDEXED')
        for fp,count in expected_fp_counts.items():
            uids=events.get(fp,[]);owner=source_groups[fp]
            if count==len(uids) and owner!='AMBIGUOUS_SOURCE_CLASS':
                label=owner if owner is not None else 'OUTSIDE_SELECTED'
                for u,n in Counter(uids).items():
                    uid_owner[u].add(label)
                    if owner is not None:mapped[owner]+=n;owners[owner].add(u);tracked[u]+=n
                    class_rows.append({'fingerprint_sha256':hashlib.sha256(repr(fp).encode()).hexdigest(),'original_ks':label,'uid':u,'occurrences':n})
            else:
                if owner not in [None,'AMBIGUOUS_SOURCE_CLASS']:bad[owner]+=count
                for u in uids:uid_owner[u].add('AMBIGUOUS')
        needed=set().union(*owners.values()) if owners else set();selected={};conn={}
        for row in log_rows(d/'conn.log'):
            ident=(row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower())
            if ident in selected_tuples:
                k=key(row)
                if k in wanted:
                    if k in selected:raise Stop('Duplicate selected-start key; no arbitrary record chosen')
                    selected[k]={**feature(row),'ks':k,'y':int(ci.loc[k,'y'])}
            if row['uid'] in needed:
                if row['uid'] in conn:raise Stop('Duplicate UID record')
                conn[row['uid']]={**feature(row),'uid':row['uid']}
        present=[k for k in clean.ks if k in selected]
        if not present:raise Stop('No selected-start records retained')
        sf=pd.DataFrame([selected[k] for k in present]);uid_order=sorted(conn);cf=pd.DataFrame([conn[u] for u in uid_order],columns=F+['uid'])
        sf.to_csv(OUT/f'selected_features_k{clones}.csv.gz',index=False,compression='gzip');cf.to_csv(OUT/f'descendant_features_k{clones}.csv.gz',index=False,compression='gzip')
        event_count=Counter(u for vv in events.values() for u in vv)
        pure={u:bool(len(uid_owner[u])==1 and not uid_owner[u]&{'OUTSIDE_SELECTED','UNINDEXED','AMBIGUOUS'} and tracked[u]==int(conn[u]['orig_pkts']+conn[u]['resp_pkts'])==event_count[u]) for u in uid_order}
        audit=[]
        for k in mk:
            target=expected[k]+(clones if k in eligible else 0)
            complete=mapped[k]==target and bad[k]==0 and bool(owners[k]) and owners[k].issubset(conn)
            audit.append({'ks':k,'expected_packets_including_clones':target,'mapped_packets':mapped[k],'unresolved_packets':bad[k],
                          'descendant_records':len(owners[k]),'packet_membership_complete':bool(complete),
                          'all_descendants_pure':bool(owners[k]) and all(pure.get(u,False) for u in owners[k])})
        at=pd.DataFrame(audit);at.to_csv(OUT/f'packet_membership_k{clones}.csv',index=False)
        pd.DataFrame(class_rows).to_csv(OUT/f'fingerprint_class_UIDs_k{clones}.csv.gz',index=False,compression='gzip')
        pd.DataFrame([{'uid':u,'availability_network_time_us':t} for u,t in available.items()]).to_csv(OUT/f'record_availability_k{clones}.csv',index=False)
        complete=at.set_index('ks').packet_membership_complete.to_dict()
        print('[3/3] Evaluating the unchanged nine models and record-availability horizons.',flush=True)
        with threadpool_limits(limits=2):
            for (family,seed),model in sorted(models.items()):
                protocol=family=='PROTOCOL_ONLY_LR'
                if list(model.classes_)!=[0,1]:raise Stop('Unexpected model class order')
                d0=model.predict_proba(encode(clean,protocol))[:,1]>=.5;initial=d0[y==1]
                sp=model.predict_proba(encode(sf,protocol))[:,1];sd=sp>=.5;selected_dec=dict(zip(sf.ks,sd))
                alarms=dict(zip(uid_order,model.predict_proba(encode(cf,protocol))[:,1]>=.5)) if len(cf) else {}
                pos=neg=unknown=overlap=0;lower={t:0 for t in HORIZONS};upper={t:0 for t in HORIZONS};missing_time=0
                for k,initial_d in zip(mk,initial):
                    uu=owners[k];positive_uids=[u for u in uu if alarms.get(u,False)]
                    pure_positive=[u for u in positive_uids if pure.get(u,False)]
                    witness=bool(pure_positive);none=bool(complete[k] and not positive_uids)
                    state='DETECTED_PURE_WITNESS' if witness else ('NO_DESCENDANT_ALARM' if none else 'UNRESOLVED')
                    pos+=int(witness);neg+=int(none);unknown+=int(state=='UNRESOLVED');overlap+=int(bool(positive_uids))
                    t0=us(ci.loc[k,'ts']);time_unknown=any(u not in available or available[u]<t0 for u in positive_uids)
                    missing_time+=int(time_unknown)
                    for hh in HORIZONS:
                        bound=t0+hh*1000000
                        known=any(u in available and t0<=available[u]<=bound for u in pure_positive)
                        possible=any(u in available and t0<=available[u]<=bound for u in positive_uids)
                        lower[hh]+=int(known);upper[hh]+=int(known or possible or time_unknown or not complete[k])
                    units.append({'clones':clones,'family':family,'seed':int(seed),'ks':k,'clone_eligible':k in eligible,
                                  'clean_detected':bool(initial_d),'selected_record_detected':selected_dec.get(k),
                                  'packet_membership_complete':bool(complete[k]),'classification':state,'any_overlap_alarm':bool(positive_uids)})
                yy=sf.y.to_numpy(int)
                results.append({'clones_per_eligible_unit':clones,'family':family,'seed':int(seed),'injection_eligible_units':len(eligible),
                    'added_packets':added,'selected_records_retained':len(sf),'selected_record_accuracy':float((sd==yy).mean()),
                    'selected_record_recall':float(sd[yy==1].mean()) if (yy==1).any() else np.nan,
                    'selected_record_benign_FPR':float(sd[yy==0].mean()) if (yy==0).any() else np.nan,
                    'original_units':len(mk),'clean_detected_units':int(initial.sum()),'pure_witness_detected':pos,
                    'no_descendant_alarm':neg,'unresolved_units':unknown,'unit_detection_lower':pos/len(mk),
                    'unit_detection_upper':(pos+unknown)/len(mk),
                    'unit_detection_drop_lower':float(initial.mean()-(pos+unknown)/len(mk)),
                    'unit_detection_drop_upper':float(initial.mean()-pos/len(mk)),'any_overlap_alarm_units':overlap})
                for hh in HORIZONS:timings.append({'clones':clones,'family':family,'seed':int(seed),'horizon_seconds':hh,
                    'original_units':len(mk),'pure_alarm_available_lower_count':lower[hh],'possible_alarm_available_upper_count':upper[hh],
                    'availability_detection_lower':lower[hh]/len(mk),'availability_detection_upper':upper[hh]/len(mk),
                    'units_missing_positive_record_time':missing_time,'physical_latency_measured':False})
        proofs.append({'clones':clones,'source_packets':input_count,'expected_output_packets':input_count+added,'verified_added_packets':added,
            'condition_sha256':sha(transformed),'source_prefix_sha256':old['prefix_sha256'],
            'exact_duplicate_record_construction_verified':True,'complete_original_packet_memberships':int(at.packet_membership_complete.sum()),
            'replay_wall_seconds':elapsed})
        js(OUT/'condition_proofs.json',proofs);pd.DataFrame(results).to_csv(OUT/'injection_model_results.csv',index=False)
        pd.DataFrame(units).to_csv(OUT/'original_unit_results.csv.gz',index=False,compression='gzip');pd.DataFrame(timings).to_csv(OUT/'record_availability_horizons.csv',index=False)
        print('\nPACKET MEMBERSHIP\n'+at.drop(columns='ks').sum(numeric_only=True).to_string(),flush=True)
        print('\nMODEL RESULTS\n'+pd.DataFrame([r for r in results if r['clones_per_eligible_unit']==clones]).to_string(index=False),flush=True)
        print('\nRECORD AVAILABILITY (seed 8101)\n'+pd.DataFrame([t for t in timings if t['clones']==clones and t['seed']==8101]).to_string(index=False),flush=True)
        shutil.rmtree(d)
        if clones:transformed.unlink()
    R.update({'status':'CAPTURE1_OBSERVED_UID_NULL_K1_K3_CONTROL_COMPLETE','source_models_reused':len(models),
        'source_run':str(previous),'injection_eligible_units':len(eligible),'original_cohort_resampled':False,
        'conditions':[0,1,3],'record_availability_logged':True,
        'interpretation':'Ownership is established using observed clean Zeek UIDs. Clone multiplicity is verified, not individual identical-clone identity. New group-disjoint within-capture development control; not historical result reproduction, physical latency, or functionality validation.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    if scratch is not None and scratch.is_dir() and R['status']=='CAPTURE1_OBSERVED_UID_NULL_K1_K3_CONTROL_COMPLETE':
        shutil.rmtree(scratch);R['only_this_run_scratch_removed']=True
    elif scratch is not None and scratch.is_dir():R['scratch_retained_for_diagnosis']=True
    js(OUT/'receipt.json',R)
    try:R['evidence_checkpoint']=checkpoint()
    except Exception as error:R['checkpoint_error']=str(error)
    js(OUT/'receipt.json',R)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
