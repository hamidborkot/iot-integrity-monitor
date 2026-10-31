# Batch 2: instrumented clean-PCAP replay and packet-to-Zeek-UID baseline.
# new_packet is an offline packet event: https://docs.zeek.org/en/v8.0.9/scripts/base/bif/event.bif.zeek.html
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from contextlib import contextmanager
from collections import defaultdict, Counter
import os, io, json, gzip, hashlib, zipfile, struct, socket, shutil, subprocess, traceback
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

WORK = Path('/kaggle/working')
OWNER = Path('/kaggle/input/datasets/mdhamidborkottulla')
ROOTS = [OWNER/n for n in ['all-kaggle-work','complete-backup','full-backup','last-day-backup','one-last','ran-files','the-last-update','whole-in-one','the-last-days-backup']]
SCENARIO = 'CTU-IoT-Malware-Capture-49-1'
F = ['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
LIMIT=256*1024**2
class Stop(Exception): pass

def js(p,x): p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z, z.open(a['member']) as f: yield f
    else:
        with open(a['path'],'rb') as f: yield f

def sha(a):
    h=hashlib.sha256()
    with opened(a) as f:
        for b in iter(lambda:f.read(4*1024**2),b''): h.update(b)
    return h.hexdigest()

def data(a):
    with opened(a) as f: b=f.read(LIMIT+1)
    if len(b)>LIMIT: raise Stop('Small input exceeds limit')
    return b

def table(a):
    b=data(a)
    if b[:2]==b'\x1f\x8b': b=gzip.decompress(b)
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def us(t): return int((Decimal(str(t))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def num(x): return 0.0 if x in ['-','',None] else float(x)
def norm(df):
    df=df.copy()
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or (df[c]<0).any(): raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower()
    return df

def matrix(df):
    return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])

def flag(s):
    v=s.str.lower()
    if not v.isin(['true','false','1','0']).all(): raise Stop('Invalid Boolean')
    return v.isin(['true','1'])

def ep(src,sp,dst,dp): return tuple(sorted([(str(src),int(sp)),(str(dst),int(dp))]))
def rowkey(r): return (us(r['ts']),r['id.orig_h'],int(r['id.orig_p']),r['id.resp_h'],int(r['id.resp_p']),r['proto'].lower())

def read_conn(path):
    fields=None
    with open(path) as f:
        for line in f:
            if line.startswith('#fields'): fields=line.rstrip('\n').split('\t')[1:]
            elif line.startswith('#') or not line.strip(): continue
            else:
                if not fields: raise Stop('Missing Zeek field header')
                values=line.rstrip('\n').split('\t')
                if len(values)!=len(fields): raise Stop('Malformed Zeek row')
                yield dict(zip(fields,values))

MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def packets(path):
    with open(path,'rb') as f:
        header=f.read(24)
        if len(header)!=24 or header[:4] not in MAGIC: raise Stop('Expected classic PCAP, not PCAPNG')
        endian,unit=MAGIC[header[:4]]
        link=struct.unpack(endian+'I',header[20:24])[0]&65535
        i=0
        while True:
            h=f.read(16)
            if not h: break
            if len(h)!=16: raise Stop('Truncated packet record')
            sec,sub,cap,wire=struct.unpack(endian+'IIII',h)
            if cap>16*1024**2: raise Stop('Implausible captured packet size')
            b=f.read(cap)
            if len(b)!=cap: raise Stop('Truncated packet bytes')
            yield i,sec*10**9+sub*unit,link,b
            i+=1

def ipv4_tcp(b,link):
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
    elif link in [101,228,12]: o=0
    else: raise Stop('Unsupported PCAP link type '+str(link))
    if len(b)<o+20 or b[o]>>4!=4:return None
    ihl=(b[o]&15)*4
    if ihl<20 or b[o+9]!=6:return None
    frag=int.from_bytes(b[o+6:o+8],'big')
    if frag&0x3fff:return None
    t=o+ihl
    if len(b)<t+20:return None
    src=socket.inet_ntoa(b[o+12:o+16]);dst=socket.inet_ntoa(b[o+16:o+20])
    sp,dp,seq,ack=struct.unpack('!HHII',b[t:t+12])
    return (src,sp,dst,dp,seq,ack,b[t+13],int.from_bytes(b[o+4:o+6],'big'),int.from_bytes(b[o+2:o+4],'big'))

def find_slice():
    matches=[]
    def wanted(s):return SCENARIO in s and 'E1_BLIND_TARGETS_' in s and s.endswith('slice.pcap')
    for root in ROOTS+[WORK]:
        if not root.is_dir():continue
        for current,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if not d.startswith(('LINEAGE_SCREEN_BATCH','LINEAGE_PACKET_BASELINE_')) and d not in ['.git','__pycache__']]
            for name in files:
                p=Path(current)/name
                if p.is_symlink():continue
                if wanted(str(p)):
                    matches.append({'path':str(p),'member':'','bytes':p.stat().st_size})
                elif name.lower().endswith('.zip'):
                    try:
                        with zipfile.ZipFile(p) as z:
                            for m in z.infolist():
                                if wanted(m.filename):matches.append({'path':str(p),'member':m.filename,'bytes':m.file_size})
                    except (OSError,zipfile.BadZipFile):pass
    unique={}
    for a in matches:unique[(a['path'],a['member'])]=a
    return list(unique.values())

def main():
    if not WORK.is_dir():raise RuntimeError('Run in Kaggle')
    out=WORK/('LINEAGE_PACKET_BASELINE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir()
    receipt={'status':'STARTED','tests':{},'models_retrained':False,'new_PCAP_replays':0,'transformed_trace_evaluated':False,'malicious_functionality_tested':False,'output_directory':str(out)}
    temp=None
    try:
        previous=[]
        for d in WORK.glob('LINEAGE_SCREEN_BATCH1_REPAIRED_*'):
            rp=d/'receipt.json'
            if rp.is_file():
                r=json.loads(rp.read_text())
                if r.get('status')=='BATCH1_COMPLETED_NOT_PACKET_LINEAGE_PROOF':previous.append(d)
        if not previous:raise Stop('Completed repaired Batch 1 directory is required')
        prev=max(previous,key=lambda p:p.name)
        assets=json.loads((prev/'resolved_inputs.json').read_text())
        for k in ['clean','associated','models']:
            expected=assets[k].get('sha256')
            if expected and sha(assets[k])!=expected:raise Stop('Input hash mismatch: '+k)
        clean=norm(table(assets['clean']));assoc=table(assets['associated'])
        audit=pd.read_csv(prev/'test1_association_audit.csv',dtype={'ks':str})
        if len(audit)!=512 or not audit.usable_for_conditional_screen.astype(str).str.lower().eq('true').all():raise Stop('Prior association screen not fully usable')
        original=assoc[flag(assoc.is_original_start_key)].copy()
        if original.associated_original_ks.duplicated().any() or len(original)!=512:raise Stop('Expected one original-start row for each selected unit')
        clean=clean.set_index('ks')
        descriptions=defaultdict(list);keys_to_start={}
        for r in original.to_dict('records'):
            k=r['associated_original_ks'];start=us(r['ts']);end=start+us(str(clean.loc[k,'duration']))+1000
            descriptions[ep(r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'])].append((start,end,k))
            rk=rowkey(r)
            if rk in keys_to_start:raise Stop('Duplicate original start identity')
            keys_to_start[rk]=k
        for values in descriptions.values():values.sort()
        zeek=shutil.which('zeek')
        if not zeek:
            for p in ['/opt/zeek/bin/zeek','/usr/local/zeek/bin/zeek']:
                if Path(p).is_file():zeek=p;break
        if not zeek:raise Stop('Zeek is not installed in this fresh runtime. No replay attempted. The model/data tests remain preserved.')
        v=subprocess.run([zeek,'--version'],capture_output=True,text=True,timeout=30)
        receipt['zeek_version']=(v.stdout+v.stderr).strip()
        def quote(s):return json.dumps(s)
        endpoints=set()
        for e in descriptions:
            (h1,p1),(h2,p2)=e
            endpoints.add(f'{h1}|{p1}|{h2}|{p2}')
            endpoints.add(f'{h2}|{p2}|{h1}|{p1}')
        entries=',\n'.join(quote(s) for s in sorted(endpoints))
        tap="""# Offline packet-to-connection membership instrumentation.
const watched: set[string] = {ENTRIES};
event new_packet(c: connection, p: pkt_hdr)
    {
    if ( ! p?$ip || ! p?$tcp ) return;
    local k = fmt("%s|%d|%s|%d", p$ip$src, port_to_count(p$tcp$sport), p$ip$dst, port_to_count(p$tcp$dport));
    if ( k !in watched ) return;
    print fmt("PACKET\\t%.6f\\t%s\\t%s\\t%d\\t%s\\t%d\\t%d\\t%d\\t%d\\t%d\\t%d", network_time(), c$uid, p$ip$src, port_to_count(p$tcp$sport), p$ip$dst, port_to_count(p$tcp$dport), p$tcp$seq, p$tcp$ack, p$tcp$flags, p$ip$id, p$ip$len);
    }
""".replace('ENTRIES',entries)
        # Zeek strings require a single escape before t, not two.
        tap=tap.replace('\\\\t','\\t')
        script=out/'packet_membership.zeek';script.write_text(tap)
        compilecheck=subprocess.run([zeek,'-b',str(script)],capture_output=True,text=True,timeout=30,cwd=out)
        (out/'zeek_compile_stderr.txt').write_text(compilecheck.stderr)
        if compilecheck.returncode:raise Stop('Zeek instrumentation compile failed; see zeek_compile_stderr.txt')
        receipt['tests']['instrumentation_compile']='PASSED'
        print('[1/3] Resolving and hashing the original E1 Capture-49 slice.',flush=True)
        candidates=find_slice();pd.DataFrame(candidates).to_csv(out/'slice_candidates.csv',index=False)
        variants=defaultdict(list)
        for a in candidates:
            a=dict(a,sha256=sha(a));variants[a['sha256']].append(a)
        if len(variants)!=1:raise Stop(f'Expected one distinct E1 slice, found {len(variants)}. No arbitrary PCAP chosen.')
        a=min(next(iter(variants.values())),key=lambda x:(bool(x['member']),len(x['path']),x['path']))
        js(out/'selected_slice.json',a)
        if shutil.disk_usage(WORK).free<max(2*1024**3,a['bytes']*3):raise Stop('Insufficient conservative replay reserve')
        temp=out/'temporary_replay';temp.mkdir()
        if a['member']:
            pcap=temp/'original_slice.pcap'
            with opened(a) as src, open(pcap,'wb') as dst:shutil.copyfileobj(src,dst,4*1024**2)
        else:pcap=Path(a['path'])
        raw=defaultdict(list);ownership_count=Counter();ambiguous=Counter();total=0
        for idx,ts,link,b in packets(pcap):
            total+=1
            info=ipv4_tcp(b,link)
            if info is None:continue
            src,sp,dst,dp,*_=info;e=ep(src,sp,dst,dp)
            if e not in descriptions:continue
            t=(ts+500)//1000
            owners=[k for begin,end,k in descriptions[e] if begin<=t<=end]
            for k in owners:
                ownership_count[k]+=1
                if len(owners)!=1:ambiguous[k]+=1
            fingerprint=(t,)+info
            raw[fingerprint].append((idx,tuple(owners)))
            if len(raw)>1000000:raise Stop('Endpoint packet index exceeds the declared memory bound')
        receipt['input_packets']=total;receipt['indexed_packet_occurrences']=sum(map(len,raw.values()))
        print('[2/3] One instrumented clean replay; original PCAP bytes are unchanged.',flush=True)
        stdout=out/'packet_uid_events.tsv';stderr=out/'zeek_replay_stderr.txt'
        with open(stdout,'w') as so,open(stderr,'w') as se:
            run=subprocess.run([zeek,'-C','-r',str(pcap),str(script)],cwd=temp,stdout=so,stderr=se,timeout=1800)
        receipt['new_PCAP_replays']=1
        if run.returncode or not (temp/'conn.log').is_file():raise Stop('Clean Zeek replay failed; stderr retained')
        events=defaultdict(list)
        with open(stdout) as h:
            for line in h:
                if not line.startswith('PACKET\t'):continue
                x=line.rstrip('\n').split('\t')
                if len(x)!=12:raise Stop('Unexpected packet-event schema: '+line[:150])
                key=(us(x[1]),x[3],int(x[4]),x[5],int(x[6]),*[int(v) for v in x[7:12]])
                events[key].append(x[2])
                if sum(1 for _ in [])>0:pass
        if not events:raise Stop('Instrumentation produced no watched packet events')
        mapped=Counter();unmapped=Counter();uid_owners=defaultdict(set);owner_uids=defaultdict(set);mapping=[]
        for fingerprint,occurrences in raw.items():
            uids=events.get(fingerprint,[])
            owners_all=set(k for _,ks in occurrences for k in ks)
            if len(occurrences)==1 and len(uids)==1:
                idx,owners=occurrences[0];uid=uids[0]
                if len(owners)==1:
                    k=owners[0];mapped[k]+=1;owner_uids[k].add(uid);uid_owners[uid].add(k)
                    mapping.append({'packet_index':idx,'original_ks':k,'zeek_uid':uid,'timestamp_us':fingerprint[0]})
                else:
                    uid_owners[uid].add('UNASSIGNED_OR_AMBIGUOUS')
                    for k in owners:unmapped[k]+=1
            else:
                for _,owners in occurrences:
                    for k in owners:unmapped[k]+=1
                for uid in uids:uid_owners[uid].add('UNASSIGNED_OR_AMBIGUOUS')
        pd.DataFrame(mapping,columns=['packet_index','original_ks','zeek_uid','timestamp_us']).to_csv(out/'clean_packet_uid_mapping.csv.gz',index=False,compression='gzip')
        clean_rows={};all_selected_uids=set().union(*owner_uids.values()) if owner_uids else set()
        for r in read_conn(temp/'conn.log'):
            k=keys_to_start.get(rowkey(r))
            if k:
                if k in clean_rows:raise Stop('Duplicate clean connection start')
                clean_rows[k]=r
        membership=[]
        for k in sorted(set(original.associated_original_ks)):
            r=clean_rows.get(k);uids=owner_uids[k]
            counter_expected=int(clean.loc[k,'orig_pkts']+clean.loc[k,'resp_pkts'])
            mixed=any(uid_owners[u]!={k} for u in uids)
            exact=(r is not None and uids=={r['uid']} and ownership_count[k]==counter_expected and mapped[k]==counter_expected and unmapped[k]==0 and ambiguous[k]==0 and not mixed)
            membership.append({'ks':k,'clean_log_found':r is not None,'expected_total_packets':counter_expected,'source_packets_assigned':ownership_count[k],'packets_uniquely_mapped':mapped[k],'unmapped_or_collision_packets':unmapped[k],'ambiguous_original_assignment_packets':ambiguous[k],'mapped_UID_count':len(uids),'mixed_or_unassigned_UID':mixed,'clean_membership_validated':exact})
        mt=pd.DataFrame(membership);mt.to_csv(out/'test2_clean_packet_membership.csv',index=False)
        receipt['tests']['clean_packet_membership']='COMPLETED'
        print('\nTEST 2: CLEAN PACKET MEMBERSHIP\n'+mt.drop(columns='ks').sum(numeric_only=True).to_string())
        print('[3/3] Checking predictor and detector invariance on all 512 selected malicious units.',flush=True)
        if len(clean_rows)!=512:raise Stop(f'Clean replay matched {len(clean_rows)}/512 original units')
        ks=sorted(clean_rows)
        new=norm(pd.DataFrame([dict(clean_rows[k],ks=k) for k in ks]));old=clean.loc[ks].reset_index()
        same=np.isclose(new[F[:-1]].to_numpy(float),old[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9).all(axis=1)&(new.proto.to_numpy()==old.proto.to_numpy())
        pd.DataFrame({'ks':ks,'features_equal':same}).to_csv(out/'test3_clean_feature_invariance.csv',index=False)
        bundle=joblib.load(io.BytesIO(data(assets['models'])))
        results=[]
        with threadpool_limits(limits=2):
            for seed,bank in sorted(bundle['models'].items(),key=lambda kv:int(kv[0])):
                model=bank['PRIMARY'];p0=model.predict_proba(matrix(old))[:,1];p1=model.predict_proba(matrix(new))[:,1]
                results.append({'seed':int(seed),'units':len(ks),'feature_equal_units':int(same.sum()),'clean_decisions_changed':int(((p0>=.5)!=(p1>=.5)).sum()),'max_probability_difference':float(abs(p0-p1).max()),'clean_detected_before':int((p0>=.5).sum()),'clean_detected_replay':int((p1>=.5).sum())})
        rt=pd.DataFrame(results);rt.to_csv(out/'test3_clean_prediction_invariance.csv',index=False)
        print('\nTEST 3: CLEAN REPLAY INVARIANCE\n'+rt.to_string(index=False))
        passed=bool(mt.clean_membership_validated.all() and same.all() and rt.clean_decisions_changed.eq(0).all())
        receipt['tests']['clean_invariance']='PASSED' if passed else 'NOT_FULLY_VALIDATED'
        receipt['status']='CLEAN_BASELINE_VALIDATED' if passed else 'CLEAN_BASELINE_REQUIRES_RECONCILIATION'
        receipt['validated_original_units']=int(mt.clean_membership_validated.sum())
        receipt['next_step']='Rebuild the exact 10s PCAP with packet-occurrence bookkeeping and replay the same instrumentation; do not claim transformed lineage from this baseline.'
    except Exception as e:
        receipt['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED'
        receipt['reason']=str(e)
        (out/'error.txt').write_text(traceback.format_exc())
        print('\n'+receipt['status']+': '+str(e),flush=True)
    finally:
        if temp is not None and temp.is_dir():
            shutil.rmtree(temp)
            receipt['only_this_run_temporary_replay_removed']=True
        js(out/'receipt.json',receipt)
        print('\nRECEIPT\n'+json.dumps(receipt,indent=2),flush=True)

if __name__=='__main__': main()
