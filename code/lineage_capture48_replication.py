# Cross-capture development replication: Capture 48, clean and historical 10s.
# Three tests: clean membership, exact transformed membership, frozen-model transfer.
# No model training, target tuning, or changes to Capture-49 results.
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from collections import defaultdict, Counter
from contextlib import contextmanager
import ast, gzip, hashlib, io, json, shutil, sqlite3, struct, subprocess, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');SC='CTU-IoT-Malware-Capture-48-1';OLD='CTU-IoT-Malware-Capture-49-1'
OUT=W/('LINEAGE_CAPTURE48_REPLICATION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
R={'status':'STARTED','models_trained':False,'new_PCAP_replays':0,'injection_control_completed':False,
   'independent_confirmation':False,'capture_previously_exposed':True,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def latest(pattern,status):
    found=[]
    for p in W.glob(pattern):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        try:r=json.loads(rp.read_text())
        except (OSError,ValueError):continue
        if r.get('status')==status:found.append(p)
    if not found:raise Stop('Required completed stage missing: '+status)
    return max(found,key=lambda p:p.name)
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def data(a,limit=128*1024**2):
    with opened(a) as f:b=f.read(limit+1)
    if len(b)>limit:raise Stop('Bounded input read exceeded')
    return b

def sha(a):
    h=hashlib.sha256()
    with opened(a) as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def file_sha(p):return sha({'path':str(p),'member':''})
def csv(a):
    b=data(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded input too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)
def norm(df,labelled=True):
    df=df.copy()
    if not set(F+(['ks','y'] if labelled else [])).issubset(df.columns):raise Stop('Missing predictor/sample fields')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid feature '+c)
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    if labelled:
        yy=pd.to_numeric(df.y,errors='raise')
        if not yy.isin([0,1]).all():raise Stop('Invalid labels')
        df['y']=yy.astype(int)
    return df

def encode(df,protocol_only=False):
    pr=np.column_stack([df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']])
    return pr if protocol_only else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),pr])
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def num(x):return 0. if x in ['-','',None] else float(x)
def ep(r):return tuple(sorted([(r['id.orig_h'],int(r['id.orig_p'])),(r['id.resp_h'],int(r['id.resp_p']))]))
def keyrow(r):return (us(r['ts']),r['id.orig_h'],int(r['id.orig_p']),r['id.resp_h'],int(r['id.resp_p']),r['proto'].lower())

def rows(a):
    with opened(a) as raw:
        buffered=io.BufferedReader(raw)
        stream=gzip.GzipFile(fileobj=buffered) if buffered.peek(2)[:2]==b'\x1f\x8b' else buffered
        with io.TextIOWrapper(stream,encoding='utf-8') as f:
            fields=None
            for line in f:
                if line.startswith('#fields'):fields=line.rstrip('\n').split('\t')[1:]
                elif not line.startswith('#') and line.strip():
                    if fields is None:raise Stop('Zeek fields missing')
                    values=line.rstrip('\n').split('\t')
                    if len(values)!=len(fields):raise Stop('Malformed Zeek row')
                    yield dict(zip(fields,values))

def helper_namespace():
    found=[]
    for p in W.glob('ZEEK_DEPENDENCY_REPAIR_*'):
        rp=p/'receipt.json';sp=p/'resumed_batch2_source.py'
        if rp.is_file() and sp.is_file():
            meta=json.loads(rp.read_text());s=sp.read_text()
            if hashlib.sha256(s.encode()).hexdigest()==meta.get('batch2_source_sha256'):found.append((p,s,sp))
    if not found:raise Stop('Verified packet parser source missing')
    _,s,sp=max(found,key=lambda x:x[0].name);ns={'__name__':'capture48_packet_helpers','__file__':str(sp)}
    exec(compile(s,str(sp),'exec'),ns)
    return ns

def replace_scenario(a):
    a=dict(a);changed=False
    for field in ['path','member']:
        if OLD in a.get(field,''):a[field]=a[field].replace(OLD,SC);changed=True
    if not changed:raise Stop('Scenario is not encoded in the known input path; no guessed replacement')
    a.pop('sha256',None);a.pop('semantic_sha256',None)
    return a

def sibling(a,name):
    a=dict(a)
    if a.get('member'):a['member']=str(Path(a['member']).with_name(name))
    else:a['path']=str(Path(a['path']).with_name(name))
    return a

def find_source_conn(pcap_asset):
    value=pcap_asset.get('member') or pcap_asset['path']
    if SC not in value:raise Stop('Capture identity absent from source PCAP path')
    prefix=value[:value.index(SC)+len(SC)]
    if pcap_asset.get('member'):
        with zipfile.ZipFile(pcap_asset['path']) as z:
            matches=[{'path':pcap_asset['path'],'member':m.filename} for m in z.infolist()
                     if m.filename.startswith(prefix+'/') and m.filename.endswith('/conn.log')]
    else:matches=[{'path':str(p),'member':''} for p in Path(prefix).rglob('conn.log') if p.is_file()]
    if len(matches)!=1:raise Stop(f'Expected one E1 Capture-48 conn.log; found {len(matches)}')
    return matches[0]

connection=None;temp=None
try:
    a=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    matched=latest('LINEAGE_MATCHED_MODEL_FAMILIES_*','MATCHED_MODEL_FAMILIES_AND_PROTOCOL_CONTROL_COMPLETE')
    base49=latest('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    manifest=json.loads((a/'input_manifest.json').read_text());H=helper_namespace()
    ten=next(x for x in manifest['conditions'] if int(x['delay_seconds'])==10)
    attack_asset=replace_scenario(ten['candidate_asset'])
    checks=json.loads(data(sibling(attack_asset,'packet_checks.json')))
    expected_source=checks['source_pcap_sha256'];expected_transformed=checks['transformed_pcap_sha256']
    zero_asset=dict(attack_asset)
    for field in ['path','member']:
        if '/delay_10s/' in zero_asset.get(field,''):zero_asset[field]=zero_asset[field].replace('/delay_10s/','/delay_0s/')
    clean=norm(csv(zero_asset));attacked=norm(csv(attack_asset))
    if len(clean)!=1024 or clean.ks.duplicated().any() or attacked.ks.duplicated().any() or set(clean.ks)!=set(attacked.ks):raise Stop('Historical Capture-48 sample contract failed')
    attacked=attacked.set_index('ks').loc[clean.ks].reset_index()
    y=clean.y.to_numpy(int)
    if not np.array_equal(y,attacked.y.to_numpy(int)) or int((y==1).sum())!=512:raise Stop('Unexpected historical labels')
    pc49=json.loads((base49/'selected_slice.json').read_text());source_asset=replace_scenario(pc49)
    try:actual_source=sha(source_asset)
    except (OSError,KeyError):actual_source=None
    if actual_source!=expected_source:
        H['SCENARIO']=SC
        candidates=H['find_slice']();source_asset=None
        for candidate in candidates:
            if sha(candidate)==expected_source:source_asset=candidate;break
        if source_asset is None:raise Stop('The historical hash-bound E1 Capture-48 slice was not found')
    conn_asset=find_source_conn(source_asset)
    # Reuse only the exact key-format functions from the original user-owned helper.
    model_asset=manifest['models'];key_asset=dict(model_asset)
    if key_asset.get('member'):key_asset['member']=str(Path(key_asset['member']).parent.parent/'run_streaming_confirmatory_batch_A_v1_2_fixed.py')
    else:key_asset['path']=str(Path(key_asset['path']).parent.parent/'run_streaming_confirmatory_batch_A_v1_2_fixed.py')
    key_source=data(key_asset).decode('utf-8');tree=ast.parse(key_source)
    defs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'key','skey'}]
    if {n.name for n in defs}!={'key','skey'}:raise Stop('Original flow-key functions missing')
    kns=dict(globals());exec(compile(ast.fix_missing_locations(ast.Module(body=defs,type_ignores=[])),'verified_flow_key_helpers','exec'),kns)
    wanted=set(clean.ks);original={};separators=set()
    print('[1/3] Validating Capture-48 original units and instrumented clean replay.',flush=True)
    for r in rows(conn_asset):
        k0=kns['key'](r['ts'],r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto'])
        for sep in ['|','::',',']:
            k=kns['skey'](k0,sep)
            if k in wanted:
                if k in original:raise Stop('Duplicate selected original connection')
                original[k]=r;separators.add(sep);break
    if set(original)!=wanted or len(separators)!=1:raise Stop('Original flow-key linkage failed')
    matched_clean=norm(pd.DataFrame([original[k] for k in clean.ks]),labelled=False)
    if not np.allclose(matched_clean[F[:-1]].to_numpy(float),clean[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9) or not np.array_equal(matched_clean.proto,clean.proto):raise Stop('E1 clean features differ from the historical identity condition')
    ci=clean.set_index('ks');mk=list(clean.loc[y==1,'ks'])
    if any(original[k]['proto'].lower()!='tcp' for k in mk):raise Stop('This controlled implementation requires TCP membership for every selected malicious original unit')
    descriptions=defaultdict(list);start_keys={}
    for k in mk:
        r=original[k];start=us(r['ts']);end=start+us(str(num(r['duration'])))+1000
        descriptions[ep(r)].append((start,end,k));start_keys[keyrow(r)]=k
    watched=set()
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
    tap_path=OUT/'capture48_packet_membership.zeek';tap_path.write_text(tap)
    zeek=shutil.which('zeek') or '/opt/zeek/bin/zeek'
    ver=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30)
    version=(ver.stdout+ver.stderr).strip()
    if '8.0.10' not in version:raise Stop('Expected Zeek 8.0.10')
    compile_test=subprocess.run([zeek,'-b',str(tap_path)],cwd=OUT,capture_output=True,text=True,timeout=30)
    (OUT/'zeek_compile_stderr.txt').write_text(compile_test.stderr)
    if compile_test.returncode:raise Stop('Instrumentation compilation failed')
    if shutil.disk_usage(W).free<4*1024**3:raise Stop('At least 4 GiB free is required')
    temp=OUT/'temporary_replay';temp.mkdir()
    if source_asset.get('member'):
        pcap=temp/'original.pcap'
        with opened(source_asset) as src,open(pcap,'wb') as dst:shutil.copyfileobj(src,dst,4*1024**2)
    else:pcap=Path(source_asset['path'])
    raw_by_delay={0:defaultdict(list),10:defaultdict(list)};source_count=Counter();first={};packet_owner={};total=0
    for idx,ts,link,payload in H['packets'](pcap):
        total+=1;info=H['ipv4_tcp'](payload,link)
        if info is None:continue
        ee=tuple(sorted([(info[0],info[1]),(info[2],info[3])]))
        if ee not in descriptions:continue
        tt=(ts+500)//1000;possible=[k for begin,end,k in descriptions[ee] if begin<=tt<=end]
        if len(possible)>1:raise Stop('Ambiguous source packet ownership')
        owner=possible[0] if possible else None
        if owner is not None:packet_owner[idx]=owner;source_count[owner]+=1;first.setdefault(owner,idx)
        raw_by_delay[0][(tt,)+info].append((idx,owner))
        delta=10*10**9 if owner is not None and idx!=first[owner] else 0
        raw_by_delay[10][((ts+delta+500)//1000,)+info].append((idx,owner))
    expected={k:int(ci.loc[k,'orig_pkts']+ci.loc[k,'resp_pkts']) for k in mk}
    if dict(source_count)!=expected or min(expected.values())<2:raise Stop('Selected source packet counts or historical pacing eligibility differ')
    def replay(path,delay):
        run_dir=temp/f'replay_{delay}s';run_dir.mkdir()
        event_path=OUT/f'packet_events_{delay}s.txt'
        R['new_PCAP_replays']+=1
        with open(event_path,'w') as so,open(OUT/f'zeek_stderr_{delay}s.txt','w') as se:
            result=subprocess.run([zeek,'-C','-r',str(path),str(tap_path)],cwd=run_dir,stdout=so,stderr=se,timeout=1800)
        if result.returncode or not (run_dir/'conn.log').is_file():raise Stop('Zeek replay failed')
        event=defaultdict(list)
        with open(event_path) as h:
            for line in h:
                if not line.startswith('PACKET|'):continue
                x=line.rstrip('\r\n').split('|')
                if len(x)!=12:raise Stop('Unexpected packet-event schema')
                fingerprint=(us(x[1]),x[3],int(x[4]),x[5],int(x[6]),*[int(v) for v in x[7:12]])
                event[fingerprint].append(x[2])
        if not event:raise Stop('No watched packet events')
        raw=raw_by_delay[delay];mapped=Counter();bad=Counter();owners=defaultdict(set);uid_owner=defaultdict(set);map_rows=[]
        for fp,uids in event.items():
            if fp not in raw:
                for u in uids:uid_owner[u].add('UNINDEXED')
        for fp,occurrences in raw.items():
            uids=event.get(fp,[])
            if len(occurrences)==1 and len(uids)==1:
                idx,k=occurrences[0];u=uids[0];uid_owner[u].add(k if k else 'OUTSIDE_SELECTED')
                if k:mapped[k]+=1;owners[k].add(u);map_rows.append({'packet_index':idx,'original_ks':k,'uid':u,'timestamp_us':fp[0]})
            else:
                for _,k in occurrences:
                    if k:bad[k]+=1
                for u in uids:uid_owner[u].add('AMBIGUOUS_OCCURRENCE')
        needed=set().union(*owners.values()) if owners else set();conn={};start_rows={}
        for r in rows({'path':str(run_dir/'conn.log'),'member':''}):
            if r['uid'] in needed:
                if r['uid'] in conn:raise Stop('Duplicate extracted UID')
                conn[r['uid']]=r
                k=start_keys.get(keyrow(r))
                if k:
                    if k in start_rows:raise Stop('Duplicate original-start record')
                    start_rows[k]=r
        audits=[]
        for k in mk:
            uids=owners[k];count=sum(int(num(conn[u]['orig_pkts'])+num(conn[u]['resp_pkts'])) for u in uids if u in conn)
            good=bool(uids) and mapped[k]==expected[k] and bad[k]==0 and all(uid_owner[u]=={k} for u in uids) and uids.issubset(conn) and count==expected[k]
            if delay==0:good=good and len(uids)==1 and k in start_rows and uids=={start_rows[k]['uid']}
            audits.append({'ks':k,'expected_packets':expected[k],'mapped_packets':mapped[k],'unresolved_packets':bad[k],
                           'descendant_records':len(uids),'descendant_packet_sum':count,'membership_validated':bool(good)})
        audit=pd.DataFrame(audits);audit.to_csv(OUT/f'membership_{delay}s.csv',index=False)
        pd.DataFrame(map_rows).to_csv(OUT/f'packet_UID_mapping_{delay}s.csv.gz',index=False,compression='gzip')
        if set(start_rows)!=set(mk):raise Stop('Original-start feature coverage incomplete')
        ordered=norm(pd.DataFrame([start_rows[k] for k in mk]),labelled=False)
        reference=(clean if delay==0 else attacked).set_index('ks').loc[mk]
        eq=np.isclose(ordered[F[:-1]].to_numpy(float),reference[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9).all(axis=1)&(ordered.proto.to_numpy()==reference.proto.to_numpy())
        pd.DataFrame({'ks':mk,'historical_start_features_equal':eq}).to_csv(OUT/f'feature_identity_{delay}s.csv',index=False)
        conn_df=norm(pd.DataFrame(conn.values()),labelled=False)
        conn_df.to_csv(OUT/f'selected_connection_records_{delay}s.csv.gz',index=False,compression='gzip')
        print(f'\nMEMBERSHIP TEST — {delay}s\n'+audit.drop(columns='ks').sum(numeric_only=True).to_string(),flush=True)
        if not audit.membership_validated.all() or not eq.all():raise Stop('Membership or historical selected features failed validation; artifacts retained')
        return conn_df,owners
    clean_conn,clean_owners=replay(pcap,0)
    R['clean_membership_validated']=512
    print('[2/3] Rebuilding and validating the exact historical Capture-48 10s transformation.',flush=True)
    with open(pcap,'rb') as h:header=h.read(24)
    endian,unit=H['MAGIC'][header[:4]]
    connection=sqlite3.connect(temp/'schedule.sqlite');connection.execute('PRAGMA journal_mode=OFF');connection.execute('PRAGMA synchronous=OFF');connection.execute('PRAGMA temp_store=FILE')
    connection.execute('CREATE TABLE p(ts INTEGER,idx INTEGER,off INTEGER,cap INTEGER,wire INTEGER)')
    batch=[];offset=24;count=0;delayed=0
    with open(pcap,'rb') as src:
        src.seek(24)
        while True:
            h=src.read(16)
            if not h:break
            if len(h)!=16:raise Stop('Truncated record')
            sec,frac,cap,wire=struct.unpack(endian+'IIII',h)
            if cap>16*1024**2:raise Stop('Invalid packet size')
            payload=src.read(cap)
            if len(payload)!=cap:raise Stop('Truncated packet')
            ts=sec*10**9+frac*unit;k=packet_owner.get(count)
            delta=10*10**9 if k is not None and count!=first[k] else 0
            batch.append((ts+delta,count,offset+16,cap,wire));offset+=16+cap;count+=1;delayed+=int(delta>0)
            if len(batch)>=50000:connection.executemany('INSERT INTO p VALUES(?,?,?,?,?)',batch);batch=[]
            if count%500000==0:print('Scheduled packets:',count,flush=True)
    if batch:connection.executemany('INSERT INTO p VALUES(?,?,?,?,?)',batch)
    connection.commit();connection.execute('CREATE INDEX ordered ON p(ts,idx)');connection.commit()
    transformed=temp/'capture48_paced10s.pcap';last_ts=-1;last_idx={};written=0
    with open(pcap,'rb') as src,open(transformed,'wb') as dst:
        dst.write(header)
        for ts,idx,off,cap,wire in connection.execute('SELECT ts,idx,off,cap,wire FROM p ORDER BY ts,idx'):
            if ts<last_ts:raise Stop('Output timestamps unordered')
            last_ts=ts;k=packet_owner.get(idx)
            if k is not None:
                if idx<=last_idx.get(k,-1):raise Stop('Selected packet order changed')
                last_idx[k]=idx
            src.seek(off);payload=src.read(cap)
            if len(payload)!=cap:raise Stop('Incomplete packet copy')
            dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(payload);written+=1
    connection.close();connection=None;(temp/'schedule.sqlite').unlink()
    observed=sha({'path':str(transformed),'member':''})
    identity={'source_pcap_sha256':expected_source,'historical_transformed_pcap_sha256':expected_transformed,'reconstructed_sha256':observed,
              'exact_hash_match':observed==expected_transformed,'source_packets':total,'output_packets':written,'delayed_packets':delayed}
    js(OUT/'transformation_identity.json',identity);print('\nTRANSFORMATION IDENTITY\n'+json.dumps(identity,indent=2),flush=True)
    if observed!=expected_transformed:raise Stop('Historical transformed trace did not reproduce; no replacement attack accepted')
    attack_conn,attack_owners=replay(transformed,10)
    R['transformed_membership_validated']=512
    print('[3/3] Applying historical and matched models without fitting.',flush=True)
    model_hash=sha(model_asset)
    old_models=joblib.load(io.BytesIO(data(model_asset)))['models']
    new_models=joblib.load(matched/'new_matched_comparison_models.joblib')
    models={('HISTORICAL_HGB',int(seed)):bank['PRIMARY'] for seed,bank in old_models.items()}
    models.update({(str(family),int(seed)):model for (family,seed),model in new_models.items()})
    if len(models)!=12:raise Stop('Expected 3 historical and 9 matched/control models')
    result_rows=[];unit_rows=[]
    with threadpool_limits(limits=2):
        for (family,seed),model in sorted(models.items()):
            protocol=family=='PROTOCOL_ONLY_LR'
            d0=model.predict_proba(encode(clean,protocol))[:,1]>=.5
            for delay,frame,conn_df,owners in [(0,clean,clean_conn,clean_owners),(10,attacked,attack_conn,attack_owners)]:
                d=model.predict_proba(encode(frame,protocol))[:,1]>=.5
                alarms=dict(zip(conn_df.uid,model.predict_proba(encode(conn_df,protocol))[:,1]>=.5))
                unit_alarm=np.array([any(alarms[u] for u in owners[k]) for k in mk],dtype=bool)
                initial=d0[y==1];selected=d[y==1];lost=initial&~unit_alarm
                result_rows.append({'capture':SC,'family':family,'seed':seed,'delay_seconds':delay,
                    'record_accuracy':float((d==y).mean()),'record_accuracy_drop':float((d0==y).mean()-(d==y).mean()),
                    'benign_FPR':float(d[y==0].mean()),'selected_record_recall':float(selected.mean()),
                    'original_units':len(mk),'clean_detected_units':int(initial.sum()),'selected_record_detected_units':int(selected.sum()),
                    'any_descendant_detected_units':int(unit_alarm.sum()),'original_unit_detection_drop':float(initial.mean()-unit_alarm.mean()),
                    'selected_misses_with_descendant_alarm':int((~selected&unit_alarm).sum()),
                    'loss_fraction_among_clean_detected':float(lost.sum()/initial.sum()) if initial.sum() else np.nan,
                    'zero_clean_detection_floor':bool(initial.sum()==0),'functionality_preservation_proved':False})
                unit_rows.extend({'family':family,'seed':seed,'delay_seconds':delay,'ks':k,'clean_detected':bool(cd),
                                  'selected_record_detected':bool(sd),'any_descendant_alarm':bool(ad)}
                                 for k,cd,sd,ad in zip(mk,initial,selected,unit_alarm))
    result=pd.DataFrame(result_rows);result.to_csv(OUT/'capture48_model_transfer_results.csv',index=False)
    pd.DataFrame(unit_rows).to_csv(OUT/'capture48_unit_predictions.csv.gz',index=False,compression='gzip')
    js(OUT/'input_manifest.json',{'capture':SC,'source_pcap_asset':source_asset,'source_conn_asset':conn_asset,
        'clean_features_asset':zero_asset,'attack_features_asset':attack_asset,'key_helper_asset':key_asset,
        'historical_models_sha256':model_hash,'new_matched_models_sha256':file_sha(matched/'new_matched_comparison_models.joblib')})
    print('\nEXPERIMENT 3 — MODEL TRANSFER TO CAPTURE 48\n'+result.to_string(index=False),flush=True)
    R.update({'status':'CAPTURE48_CLEAN_TRANSFORM_AND_MODEL_TRANSFER_COMPLETE','zeek_version':version,
              'selected_original_units':512,'historical_transformed_trace_reproduced':True,
              'models_evaluated':len(models),'new_independent_capture_claimed':False,
              'interpretation':'Development replication on another previously exposed IoT-23 capture; clean detection floors remain visible. No application-functionality or independent-confirmation claim.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    if connection is not None:connection.close()
    if temp is not None and temp.is_dir() and R['status']=='CAPTURE48_CLEAN_TRANSFORM_AND_MODEL_TRANSFER_COMPLETE':
        shutil.rmtree(temp);R['only_this_run_temporary_replay_removed']=True
    elif temp is not None and temp.is_dir():R['temporary_replay_retained_for_diagnosis']=True
    js(OUT/'receipt.json',R)
    package=OUT/'capture48_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
