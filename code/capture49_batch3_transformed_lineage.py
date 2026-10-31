# Batch 3: exact 10-second transformation, packet membership, detector outcome.
# Source transformation contract: uploaded notebook cells 249–251. [file:5]
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
import ast, hashlib, io, json, re, shutil, sqlite3, struct, subprocess, traceback
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

WORK=Path('/kaggle/working')
OUT=WORK/('LINEAGE_TRANSFORM_BATCH3_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
R={'status':'STARTED','tests':{},'models_retrained':False,'new_PCAP_replays':0,
   'malicious_functionality_tested':False,'historical_outputs_overwritten':False,
   'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def file_sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def decode(line):
    if not line.startswith('PACKET'):return line
    return re.sub(r'\\+t','\t',re.sub(r'\\+x09','\t',line,flags=re.I)).replace('|','\t')
def completed(pattern,status):
    found=[]
    for d in WORK.glob(pattern):
        p=d/'receipt.json'
        if p.is_file():
            try:r=json.loads(p.read_text())
            except (OSError,ValueError):continue
            if r.get('status')==status:found.append(d)
    if not found:raise Stop('Required completed stage missing: '+status)
    return max(found,key=lambda p:p.name)
def load_helpers():
    found=[]
    for d in WORK.glob('ZEEK_DEPENDENCY_REPAIR_*'):
        p=d/'resumed_batch2_source.py';rp=d/'receipt.json'
        if not p.is_file() or not rp.is_file():continue
        meta=json.loads(rp.read_text());s=p.read_text()
        if hashlib.sha256(s.encode()).hexdigest()==meta.get('batch2_source_sha256'):
            found.append((d,s,p))
    if not found:raise Stop('Verified saved Batch 2 source is unavailable')
    _,s,p=max(found,key=lambda x:x[0].name)
    ns={'__name__':'batch3_verified_helpers','__file__':str(p)}
    exec(compile(s,str(p),'exec'),ns)
    return ns

connection=None;temp=None
try:
    base=completed('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    batch1=completed('LINEAGE_SCREEN_BATCH1_REPAIRED_*','BATCH1_COMPLETED_NOT_PACKET_LINEAGE_PROOF')
    H=load_helpers();F=H['F']
    assets=json.loads((batch1/'resolved_inputs.json').read_text())
    for k in ['clean','selected10','associated','models']:
        if assets[k].get('sha256') and H['sha'](assets[k])!=assets[k]['sha256']:
            raise Stop('Changed input artifact: '+k)
    clean=H['norm'](H['table'](assets['clean'])).set_index('ks')
    selected=H['norm'](H['table'](assets['selected10'])).set_index('ks')
    assoc=H['table'](assets['associated'])
    starts=assoc[H['flag'](assoc.is_original_start_key)].copy()
    membership=pd.read_csv(base/'test2_clean_packet_membership.csv',dtype={'ks':str})
    if len(membership)!=512 or not membership.clean_membership_validated.astype(str).str.lower().eq('true').all():
        raise Stop('Clean packet membership is not fully validated')
    ledger=pd.read_csv(base/'clean_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'zeek_uid':str})
    if ledger.packet_index.duplicated().any():raise Stop('Duplicate source packet occurrences')
    expected=membership.set_index('ks').expected_total_packets.astype(int).to_dict()
    if set(ledger.original_ks)!=set(expected):raise Stop('Packet ledger population mismatch')
    actual=ledger.groupby('original_ks').size().to_dict()
    if actual!=expected:raise Stop('Clean packet ledger counts differ from validated counts')
    if min(expected.values())<2:raise Stop('Historical pacing eligibility contract violated')
    owner_by_index=dict(zip(ledger.packet_index.astype(int),ledger.original_ks))
    first=ledger.groupby('original_ks').packet_index.min().astype(int).to_dict()
    source_asset=json.loads((base/'selected_slice.json').read_text())
    source_hash=H['sha'](source_asset)
    if source_hash!=source_asset['sha256']:raise Stop('Source PCAP hash mismatch')
    checks_asset=dict(assets['selected10'])
    if checks_asset.get('member'):
        checks_asset['member']=str(Path(checks_asset['member']).with_name('packet_checks.json'))
    else:
        checks_asset['path']=str(Path(checks_asset['path']).with_name('packet_checks.json'))
    checks=json.loads(H['data'](checks_asset))
    if checks.get('source_pcap_sha256')!=source_hash:raise Stop('Historical transformation uses a different source PCAP')
    target_hash=checks.get('transformed_pcap_sha256')
    if not target_hash:raise Stop('Historical transformed-PCAP hash missing')
    R['historical_transformed_pcap_sha256']=target_hash
    R['source_pcap_sha256']=source_hash
    if shutil.disk_usage(WORK).free<4*1024**3:raise Stop('At least 4 GiB free space is required for bounded replay/sorting')
    temp=OUT/'temporary_replay';temp.mkdir()
    if source_asset.get('member'):
        original_pcap=temp/'original_slice.pcap'
        with H['opened'](source_asset) as src,open(original_pcap,'wb') as dst:
            shutil.copyfileobj(src,dst,4*1024**2)
    else:original_pcap=Path(source_asset['path'])
    with open(original_pcap,'rb') as f:header=f.read(24)
    if header[:4] not in H['MAGIC']:raise Stop('Unsupported PCAP container')
    endian,unit=H['MAGIC'][header[:4]]
    link=struct.unpack(endian+'I',header[20:24])[0]&65535
    if 10*10**9%unit:raise Stop('Delay cannot be represented exactly')
    endpoints={H['ep'](r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p']) for r in starts.to_dict('records')}
    connection=sqlite3.connect(temp/'schedule.sqlite')
    connection.execute('PRAGMA journal_mode=OFF');connection.execute('PRAGMA synchronous=OFF')
    connection.execute('PRAGMA temp_store=FILE');connection.execute('PRAGMA cache_size=-32768')
    connection.execute('CREATE TABLE packets(ts INTEGER, idx INTEGER, off INTEGER, cap INTEGER, wire INTEGER)')
    raw=defaultdict(list);rows=[];seen=Counter();count=0;delayed=0;offset=24
    print('[1/3] Rebuilding the exact historical 10s trace using validated packet indices.',flush=True)
    with open(original_pcap,'rb') as f:
        f.seek(24)
        while True:
            h=f.read(16)
            if not h:break
            if len(h)!=16:raise Stop('Truncated PCAP record')
            sec,fraction,cap,wire=struct.unpack(endian+'IIII',h)
            if cap>16*1024**2:raise Stop('Implausible captured packet size')
            b=f.read(cap)
            if len(b)!=cap:raise Stop('Truncated packet payload')
            ts=sec*10**9+fraction*unit
            owner=owner_by_index.get(count)
            delta=10*10**9 if owner is not None and count!=first[owner] else 0
            new_ts=ts+delta
            if owner is not None:seen[owner]+=1
            delayed+=int(delta>0)
            info=H['ipv4_tcp'](b,link)
            if info is not None and H['ep'](info[0],info[1],info[2],info[3]) in endpoints:
                # Microsecond fingerprint matches the verified clean event format.
                fingerprint=((new_ts+500)//1000,)+info
                raw[fingerprint].append((count,owner))
            rows.append((new_ts,count,offset+16,cap,wire))
            offset+=16+cap;count+=1
            if len(rows)>=50000:
                connection.executemany('INSERT INTO packets VALUES(?,?,?,?,?)',rows);rows=[]
            if count%500000==0:print('Scheduled packets:',count,flush=True)
    if rows:connection.executemany('INSERT INTO packets VALUES(?,?,?,?,?)',rows)
    if dict(seen)!=expected:raise Stop('Original packet ledger did not fully reproduce')
    connection.commit();connection.execute('CREATE INDEX ordered ON packets(ts,idx)');connection.commit()
    transformed=temp/'paced10s.pcap';last_index={};last_ts=-1;written=0
    with open(original_pcap,'rb') as src,open(transformed,'wb') as dst:
        dst.write(header)
        for ts,idx,off,cap,wire in connection.execute('SELECT ts,idx,off,cap,wire FROM packets ORDER BY ts,idx'):
            if ts<last_ts:raise Stop('Timestamp ordering violation')
            last_ts=ts;owner=owner_by_index.get(idx)
            if owner is not None:
                if idx<=last_index.get(owner,-1):raise Stop('Original-unit packet order changed')
                last_index[owner]=idx
            src.seek(off);payload=src.read(cap)
            if len(payload)!=cap:raise Stop('Incomplete packet copy')
            dst.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//unit,cap,wire));dst.write(payload);written+=1
    connection.close();connection=None
    (temp/'schedule.sqlite').unlink()
    observed_hash=file_sha(transformed)
    reconstruction={'source_packets':count,'output_packets':written,'selected_packet_occurrences':len(ledger),
                    'delayed_packet_occurrences':delayed,'delay_seconds':10,
                    'historical_hash':target_hash,'reconstructed_hash':observed_hash,
                    'exact_historical_hash_match':observed_hash==target_hash}
    js(OUT/'test1_transformation_identity.json',reconstruction)
    print('\nTEST 1 — TRANSFORMATION IDENTITY\n'+json.dumps(reconstruction,indent=2),flush=True)
    if observed_hash!=target_hash:raise Stop('Rebuilt trace differs from the historically tested trace; no changed attack substituted')
    R['tests']['transformation_identity']='PASSED'
    script=base/'packet_membership.zeek'
    if not script.is_file():raise Stop('Validated clean instrumentation script missing')
    shutil.copyfile(script,OUT/'packet_membership.zeek')
    zeek=shutil.which('zeek') or '/opt/zeek/bin/zeek'
    version=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30)
    version_text=(version.stdout+version.stderr).strip()
    if '8.0.10' not in version_text:raise Stop('Expected the validated Zeek 8.0.10 executable')
    R['zeek_version']=version_text
    print('[2/3] One instrumented replay of the hash-identical transformed trace.',flush=True)
    event_path=OUT/'transformed_packet_events.txt'
    with open(event_path,'w') as so,open(OUT/'zeek_stderr.txt','w') as se:
        result=subprocess.run([zeek,'-C','-r',str(transformed),str((OUT/'packet_membership.zeek').resolve())],cwd=temp,stdout=so,stderr=se,timeout=1800)
    R['new_PCAP_replays']=1
    if result.returncode or not (temp/'conn.log').is_file():raise Stop('Transformed Zeek replay failed; logs retained')
    events=defaultdict(list)
    with open(event_path) as h:
        for line in h:
            if not line.startswith('PACKET'):continue
            x=decode(line).rstrip('\r\n').split('\t')
            if len(x)!=12:raise Stop('Invalid decoded packet-event schema')
            fingerprint=(H['us'](x[1]),x[3],int(x[4]),x[5],int(x[6]),*[int(v) for v in x[7:12]])
            events[fingerprint].append(x[2])
    if not events:raise Stop('No transformed packet events')
    mapped=Counter();unresolved=Counter();owner_uids=defaultdict(set);uid_owners=defaultdict(set);packet_rows=[]
    for fingerprint,uids in events.items():
        if fingerprint not in raw:
            for uid in uids:uid_owners[uid].add('UNINDEXED_PACKET')
    for fingerprint,occurrences in raw.items():
        uids=events.get(fingerprint,[])
        if len(occurrences)==1 and len(uids)==1:
            idx,owner=occurrences[0];uid=uids[0]
            uid_owners[uid].add(owner if owner is not None else 'OUTSIDE_SELECTED_UNITS')
            if owner is not None:
                mapped[owner]+=1;owner_uids[owner].add(uid)
                packet_rows.append({'packet_index':idx,'original_ks':owner,'transformed_uid':uid,'timestamp_us':fingerprint[0]})
        else:
            for _,owner in occurrences:
                if owner is not None:unresolved[owner]+=1
            for uid in uids:uid_owners[uid].add('AMBIGUOUS_PACKET_OCCURRENCE')
    pd.DataFrame(packet_rows,columns=['packet_index','original_ks','transformed_uid','timestamp_us']).to_csv(OUT/'transformed_packet_uid_mapping.csv.gz',index=False,compression='gzip')
    needed=set().union(*owner_uids.values()) if owner_uids else set()
    conn_rows={}
    for r in H['read_conn'](temp/'conn.log'):
        if r['uid'] in needed:
            if r['uid'] in conn_rows:raise Stop('Duplicate transformed connection UID')
            conn_rows[r['uid']]=r
    # Retain only the actual transformed rows referenced by the packet ledger.
    if conn_rows:pd.DataFrame(conn_rows.values()).to_csv(OUT/'transformed_selected_connection_records.csv.gz',index=False,compression='gzip')
    lineage=[]
    for k in sorted(expected):
        uids=owner_uids[k]
        pure=bool(uids) and all(uid_owners[u]=={k} for u in uids)
        row_packets=sum(int(H['num'](conn_rows[u]['orig_pkts'])+H['num'](conn_rows[u]['resp_pkts'])) for u in uids if u in conn_rows)
        good=(mapped[k]==expected[k] and unresolved[k]==0 and pure and uids.issubset(conn_rows) and row_packets==expected[k])
        lineage.append({'ks':k,'expected_packets':expected[k],'uniquely_mapped_packets':mapped[k],
                        'unresolved_packet_occurrences':unresolved[k],'descendant_records':len(uids),
                        'descendant_UIDs_pure':pure,'descendant_record_packet_sum':row_packets,
                        'transformed_membership_validated':bool(good)})
    lt=pd.DataFrame(lineage);lt.to_csv(OUT/'test2_transformed_membership.csv',index=False)
    R['tests']['transformed_membership']='COMPLETED'
    print('\nTEST 2 — TRANSFORMED MEMBERSHIP\n'+lt.drop(columns='ks').sum(numeric_only=True).to_string(),flush=True)
    print('[3/3] Comparing matched-record decisions with packet-mapped descendant alarms.',flush=True)
    original_by_key={r['associated_original_ks']:r for r in starts.to_dict('records')}
    expected_start={H['rowkey'](r):k for k,r in original_by_key.items()}
    start_rows={}
    for r in conn_rows.values():
        k=expected_start.get(H['rowkey'](r))
        if k:
            if k in start_rows:raise Stop('Multiple transformed original-start records')
            start_rows[k]=r
    ks=sorted(expected)
    if set(start_rows)!=set(ks):raise Stop('Missing transformed original-start record; see retained connection table')
    start_frame=H['norm'](pd.DataFrame([start_rows[k] for k in ks]))
    historical=selected.loc[ks]
    eq=np.isclose(start_frame[F[:-1]].to_numpy(float),historical[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9).all(axis=1)&(start_frame.proto.to_numpy()==historical.proto.to_numpy())
    pd.DataFrame({'ks':ks,'historical_selected_features_equal':eq}).to_csv(OUT/'test3_historical_feature_reproduction.csv',index=False)
    if not eq.all():raise Stop('Transformed selected features differ from the historical model inputs; no same-experiment interpretation allowed')
    uid_order=sorted(conn_rows)
    all_frame=H['norm'](pd.DataFrame([conn_rows[u] for u in uid_order]))
    bundle=joblib.load(io.BytesIO(H['data'](assets['models'])))
    good=lt.set_index('ks').transformed_membership_validated.to_dict()
    units=[];summaries=[]
    with threadpool_limits(limits=2):
        for seed,bank in sorted(bundle['models'].items(),key=lambda kv:int(kv[0])):
            model=bank['PRIMARY']
            clean_pred=model.predict_proba(H['matrix'](clean.loc[ks]))[:,1]>=.5
            start_pred=model.predict_proba(H['matrix'](start_frame))[:,1]>=.5
            descendant_p=model.predict_proba(H['matrix'](all_frame))[:,1]
            alarms=dict(zip(uid_order,descendant_p>=.5))
            n_alarm=0;q=0;recovered=0;residual=0
            for i,k in enumerate(ks):
                valid=bool(good[k]);alarm=any(alarms[u] for u in owner_uids[k]) if valid else None
                n_alarm+=int(alarm is True);q+=int(not valid)
                recovered+=int(valid and clean_pred[i] and not start_pred[i] and alarm)
                residual+=int(valid and clean_pred[i] and not start_pred[i] and not alarm)
                units.append({'seed':int(seed),'ks':k,'membership_validated':valid,'descendant_records':len(owner_uids[k]),
                              'clean_detected':bool(clean_pred[i]),'selected_record_detected':bool(start_pred[i]),
                              'any_packet_mapped_descendant_alarm':alarm})
            summaries.append({'seed':int(seed),'original_units':len(ks),'validated_units':len(ks)-q,'unresolved_units':q,
                              'clean_detected':int(clean_pred.sum()),'selected_record_detected':int(start_pred.sum()),
                              'units_with_descendant_alarm':n_alarm,'selected_losses_recovered':recovered,
                              'selected_losses_without_descendant_alarm':residual,
                              'detection_fraction_lower':n_alarm/len(ks),'detection_fraction_upper':(n_alarm+q)/len(ks),
                              'functionality_preservation_proved':False})
    pd.DataFrame(units).to_csv(OUT/'test3_unit_detection.csv',index=False)
    st=pd.DataFrame(summaries);st.to_csv(OUT/'test3_detection_summary.csv',index=False)
    print('\nTEST 3 — PACKET-MAPPED DETECTION\n'+st.to_string(index=False),flush=True)
    R['tests']['historical_selected_feature_reproduction']='PASSED'
    R['tests']['original_unit_detection']='COMPLETED'
    R['validated_original_units']=int(lt.transformed_membership_validated.sum())
    R['status']='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' if lt.transformed_membership_validated.all() else 'TRANSFORMED_PACKET_MEMBERSHIP_PARTIAL'
    R['interpretation']='Offline detection for the 512 selected original labelled traffic units under an any-descendant-record alarm rule. Not application-functionality validation, a real deployment claim, or independent statistical confirmation.'
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED'
    R['reason']=str(e);(OUT/'error.txt').write_text(traceback.format_exc())
    print('\n'+R['status']+': '+str(e),flush=True)
finally:
    if connection is not None:connection.close()
    if temp is not None and temp.is_dir() and R['status']=='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED':
        shutil.rmtree(temp);R['only_this_run_temporary_replay_removed']=True
    elif temp is not None and temp.is_dir():
        R['temporary_replay_retained_for_diagnosis']=True
    js(OUT/'receipt.json',R)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
