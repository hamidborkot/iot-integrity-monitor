"""Resolve the packet-input blocker and compute actual capture transformations.
Reads existing real classic-PCAP files (optionally gzip compressed), preserves all
packet bytes and record order, applies bounded nonnegative timestamp delays,
and independently verifies the written captures. No synthetic packets/labels.
This establishes only byte/order/timing constraints, NOT full IDS semantic validity.
Exact feature re-extraction and capture-to-CSV mapping are still required.
"""
import gzip
import hashlib
import json
import struct
import traceback
from pathlib import Path

import pandas as pd

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
OUT=BASE/'real_packet_timing_constraints_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
MAX_DELAY_SECONDS=[.001,.010,.100]
MAX_FILES_PER_DATASET=1
MAX_UNCOMPRESSED_CAPTURE_BYTES=256_000_000
MAX_PACKET_BYTES=16_000_000
SEARCH_ROOTS=[Path('/kaggle/input')]
# Add explicit paths here if captures are outside /kaggle/input.
# Example: EXTRA_CAPTURE_PATHS = {'CICIoT2023': [Path('your_attached_capture.pcap')]}
EXTRA_CAPTURE_PATHS={}
MARKERS={
    'CICIoT2023':['ciciot2023','ciciot23'],
    'CICIoMT2024':['ciciomt2024','ciciomtdataset2024'],
    'CSE':['csecicids2018'],
    'NSL':['nslkdd'],
    'TONIoT':['toniot'],
}
MAGIC={
    b'\xd4\xc3\xb2\xa1':('<',1_000_000),
    b'\xa1\xb2\xc3\xd4':('>',1_000_000),
    b'\x4d\x3c\xb2\xa1':('<',1_000_000_000),
    b'\xa1\xb2\x3c\x4d':('>',1_000_000_000),
}


def norm(text): return ''.join(c for c in str(text).lower() if c.isalnum())


def save_csv(rows,path,columns=None):
    frame=pd.DataFrame(rows,columns=columns) if columns is not None else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def file_hash(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        while True:
            block=f.read(1024*1024)
            if not block: break
            h.update(block)
    return h.hexdigest()


def open_capture(path):
    return gzip.open(path,'rb') if str(path).lower().endswith('.gz') else open(path,'rb')


def header(stream):
    raw=stream.read(24)
    if len(raw)<24: raise ValueError('Capture is empty or its global header is incomplete.')
    if raw[:4]==b'\x0a\x0d\x0d\x0a':
        raise ValueError('PCAPNG requires a separately validated interface-preserving reader; this code does not silently convert it.')
    if raw[:4] not in MAGIC: raise ValueError('Unsupported capture format/magic.')
    endian,resolution=MAGIC[raw[:4]]
    _,major,minor,_,_,snaplen,linktype=struct.unpack(endian+'IHHIIII',raw)
    if (major,minor)!=(2,4): raise ValueError(f'Unsupported classic-PCAP version: {major}.{minor}')
    return raw,endian,resolution,snaplen,linktype


def packet_record(stream,endian,resolution,snaplen):
    raw=stream.read(16)
    if not raw: return None
    if len(raw)!=16: raise ValueError('Truncated PCAP packet header.')
    seconds,fraction,captured,wire=struct.unpack(endian+'IIII',raw)
    if fraction>=resolution: raise ValueError('Invalid PCAP timestamp fraction.')
    if captured>MAX_PACKET_BYTES: raise ValueError('Packet record exceeds configured resource limit.')
    if snaplen and captured>snaplen: raise ValueError('Captured length exceeds source snaplen.')
    if captured>wire: raise ValueError('Captured length exceeds recorded wire length.')
    payload=stream.read(captured)
    if len(payload)!=captured: raise ValueError('Truncated PCAP packet payload.')
    return seconds*resolution+fraction,captured,wire,payload


def transform(source,destination,max_delay_seconds):
    temporary=destination.with_suffix('.tmp')
    count=changed=truncated=total_bytes=0
    first_time=previous=None
    packet_hash=hashlib.sha256()
    try:
        with open_capture(source) as input_stream,open(temporary,'wb') as output_stream:
            global_header,endian,resolution,snaplen,linktype=header(input_stream)
            output_stream.write(global_header)
            maximum_ticks=int(round(max_delay_seconds*resolution))
            maximum_observed=0
            total_bytes=24
            while True:
                record=packet_record(input_stream,endian,resolution,snaplen)
                if record is None: break
                timestamp,captured,wire,payload=record
                if previous is not None and timestamp<previous:
                    raise ValueError('Source packet timestamps are unordered; refusing to sort or silently alter the source sequence.')
                if first_time is None: first_time=timestamp
                # Nondecreasing delay ramp, capped at the declared budget.
                # Entire packet bytes and packet order remain unchanged.
                delay=min(maximum_ticks,max(0,timestamp-first_time)//100)
                new_time=timestamp+delay
                seconds,fraction=divmod(new_time,resolution)
                if seconds>0xffffffff: raise ValueError('Modified timestamp exceeds classic-PCAP seconds range.')
                output_stream.write(struct.pack(endian+'IIII',seconds,fraction,captured,wire))
                output_stream.write(payload)
                packet_hash.update(struct.pack('!II',captured,wire));packet_hash.update(payload)
                count+=1;changed+=int(delay>0);truncated+=int(captured<wire)
                maximum_observed=max(maximum_observed,delay)
                total_bytes+=16+captured
                if total_bytes>MAX_UNCOMPRESSED_CAPTURE_BYTES:
                    raise ValueError('Full capture exceeds the configured byte limit; no truncated prefix is certified.')
                previous=timestamp
        if not count: raise ValueError('Source capture contains no packets.')
        temporary.replace(destination)
        return {'packets':count,'timestamp_modified_packets':changed,
                'truncated_packet_records':truncated,'uncompressed_bytes':total_bytes,
                'maximum_delay_seconds':maximum_observed/resolution,
                'packet_payload_and_length_sha256':packet_hash.hexdigest(),
                'timestamp_resolution_ticks_per_second':resolution,'linktype':linktype}
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def verify(source,destination,max_delay_seconds):
    count=0;previous_new=None;source_previous=None;max_delay=0
    h_source=hashlib.sha256();h_target=hashlib.sha256()
    with open_capture(source) as source_stream,open(destination,'rb') as target_stream:
        source_header,endian,resolution,snaplen,_=header(source_stream)
        target_header,target_endian,target_resolution,target_snaplen,_=header(target_stream)
        if source_header!=target_header: raise AssertionError('PCAP global header changed.')
        while True:
            original=packet_record(source_stream,endian,resolution,snaplen)
            modified=packet_record(target_stream,target_endian,target_resolution,target_snaplen)
            if original is None or modified is None:
                if original is not None or modified is not None: raise AssertionError('Packet counts differ.')
                break
            original_time,original_length,original_wire,original_payload=original
            new_time,new_length,new_wire,new_payload=modified
            if (original_length,original_wire,original_payload)!=(new_length,new_wire,new_payload):
                raise AssertionError('Packet bytes or packet lengths changed.')
            delay=new_time-original_time
            if delay<0 or delay>int(round(max_delay_seconds*resolution)):
                raise AssertionError('Nonnegative bounded-delay constraint failed.')
            if previous_new is not None and new_time<previous_new:
                raise AssertionError('Modified packet timestamps are unordered.')
            if source_previous is not None and original_time<source_previous:
                raise AssertionError('Source packet timestamps are unordered.')
            for h,payload,length,wire in [(h_source,original_payload,original_length,original_wire),
                                           (h_target,new_payload,new_length,new_wire)]:
                h.update(struct.pack('!II',length,wire));h.update(payload)
            max_delay=max(max_delay,delay);count+=1
            previous_new=new_time;source_previous=original_time
    if h_source.digest()!=h_target.digest(): raise AssertionError('Packet byte/order fingerprints differ.')
    return {'verified_packet_count':count,'all_packet_bytes_preserved':True,
            'packet_order_preserved':True,'all_delays_nonnegative':True,
            'all_delays_within_budget':True,'verified_maximum_delay_seconds':max_delay/resolution,
            'packet_sequence_sha256':h_source.hexdigest()}


def discover():
    found={dataset:[] for dataset in DATASETS};unassigned=[];seen=set()
    for dataset,paths in EXTRA_CAPTURE_PATHS.items():
        if dataset not in found: raise ValueError(f'Unknown dataset key {dataset}')
        for path in paths:
            path=Path(path)
            if not path.exists(): raise FileNotFoundError(path)
            found[dataset].append(path);seen.add(str(path.resolve()))
    for root in SEARCH_ROOTS:
        if not root.exists(): continue
        for path in root.rglob('*'):
            if not path.is_file(): continue
            if not any(str(path).lower().endswith(s) for s in ['.pcap','.pcp','.pcap.gz','.pcapng','.pcapng.gz']): continue
            identity=str(path.resolve())
            if identity in seen: continue
            seen.add(identity)
            matches=[d for d,markers in MARKERS.items() if any(marker in norm(path) for marker in markers)]
            if len(matches)==1: found[matches[0]].append(path)
            else: unassigned.append({'path':str(path),'candidate_datasets':'|'.join(matches),
                                     'status':'DATASET_ASSOCIATION_REQUIRED'})
    return found,unassigned


def progress_counts():
    rows=[]
    repair=BASE/'neural_postprocessing_repair_and_replay_v2'/'dataset_status.csv'
    if repair.exists():
        frame=pd.read_csv(repair)
        passed=frame[frame.status=='REPAIRED_AND_REPLAY_VERIFIED']
        rows.append({'metric':'Datasets passing saved-neural replay audit','count':len(passed)})
        rows.append({'metric':'Saved neural attack settings verified','count':int(passed.verified_saved_attacks.sum())})
    banks=BASE/'independent_estimator_bank_repetition_v1'
    bank_count=sum((banks/d/f'bank_{seed}'/'completion.json').exists()
                   for d in DATASETS for seed in [2201,2301,2401,2501,2601])
    rows.append({'metric':'Completed fresh whole-estimator-bank repetitions','count':bank_count})
    rows.append({'metric':'Expected neural members in completed fresh banks','count':9*bank_count})
    algebraic=BASE/'saved_attack_algebraic_screen_v1'/'dataset_status.csv'
    if algebraic.exists():
        frame=pd.read_csv(algebraic)
        passed=frame[frame.status=='CANDIDATE_SCREEN_AND_RESTORATION_COMPUTED']
        rows.append({'metric':'Saved-case algebraic/restoration audits completed','count':int(passed.saved_cases.sum())})
    return rows


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    progress=progress_counts();save_csv(progress,OUT/'completed_computation_counts.csv')
    found,unassigned=discover()
    save_csv(unassigned,OUT/'unassigned_capture_paths.csv',columns=['path','candidate_datasets','status'])
    inventory=[{'dataset':d,'path':str(p),'file_bytes':p.stat().st_size,
                'association':'Explicit override' if d in EXTRA_CAPTURE_PATHS and p in [Path(x) for x in EXTRA_CAPTURE_PATHS[d]] else 'Path-marker candidate, not source-label validation'}
               for d,paths in found.items() for p in paths]
    save_csv(inventory,OUT/'raw_capture_inventory.csv',columns=['dataset','path','file_bytes','association'])
    statuses=[];receipts=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        if not found[dataset]:
            statuses.append({'dataset':dataset,'packet_input_status':'NEEDS_RAW_PACKET_CAPTURE',
                'trace_constraints_status':'NOT_RUN_NO_PACKET_INPUT',
                'model_feature_validation_status':'REQUIRES_ORIGINAL_EXTRACTOR_AND_RECORD_MAPPING',
                'detail':'Attach real captures from this dataset; CSV summaries alone are insufficient.'})
            continue
        successful_captures=0;errors=[]
        for source in sorted(found[dataset],key=lambda p:p.stat().st_size):
            if successful_captures>=MAX_FILES_PER_DATASET: break
            capture_id=hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:12]
            source_hash=file_hash(source)
            try:
                local_receipts=[]
                for delay in MAX_DELAY_SECONDS:
                    destination=directory/f'{capture_id}_bounded_delay_{delay:.3f}s.pcap'
                    receipt_path=destination.with_suffix('.json')
                    expected={'source_sha256':source_hash,'maximum_delay_seconds':delay}
                    if destination.exists() and receipt_path.exists():
                        old=json.loads(receipt_path.read_text())
                        if old['source_sha256']!=source_hash or old['declared_delay_budget_seconds']!=delay:
                            raise RuntimeError('Source/budget changed; use a new output directory.')
                        produced=old['transformation']
                    else: produced=transform(source,destination,delay)
                    verified=verify(source,destination,delay)
                    if file_hash(source)!=source_hash: raise AssertionError('Source capture changed during the computation.')
                    receipt={'dataset':dataset,'source_path':str(source),'source_sha256':source_hash,
                        'output_path':str(destination),'output_sha256':file_hash(destination),
                        'declared_delay_budget_seconds':delay,'transformation':produced,
                        'verification':verified,'trace_constraint_status':'BYTE_ORDER_TIMING_CONSTRAINTS_VERIFIED',
                        'model_feature_reproduction':'NOT_EVALUATED_NO_ORIGINAL_EXTRACTOR',
                        'end_to_end_attack_semantics':'NOT_EVALUATED_NO_LIVE_REPLAY',
                        'synthetic_packets_generated':False}
                    receipt_path.write_text(json.dumps(receipt,indent=2));local_receipts.append(receipt)
                    print(dataset,source.name,f'delay_budget={delay}s','PACKET BYTES/ORDER/TIMING VERIFIED',flush=True)
                receipts.extend(local_receipts);successful_captures+=1
            except Exception as error:
                errors.append(f'{source}: {error}')
                (directory/f'{capture_id}_error.txt').write_text(traceback.format_exc())
        statuses.append({'dataset':dataset,'packet_input_status':'REAL_CAPTURE_FOUND',
            'trace_constraints_status':'BYTE_ORDER_TIMING_CONSTRAINTS_VERIFIED' if successful_captures else 'UNSUPPORTED_OR_INVALID_CAPTURE',
            'model_feature_validation_status':'REQUIRES_ORIGINAL_EXTRACTOR_AND_RECORD_MAPPING',
            'detail':' | '.join(errors) if not successful_captures else f'{successful_captures} full real capture(s) checked; no learned-model accuracy claim.'})
    save_csv(statuses,OUT/'packet_pipeline_status.csv')
    (OUT/'all_trace_receipts.json').write_text(json.dumps(receipts,indent=2))
    requirements={
       'what_is_verified_here':'Existing packet byte sequences, container/order integrity, and bounded nonnegative timestamp delays',
       'what_is_not_verified':'Original packet protocol validity, live TCP/application behavior, attack-label invariance, or feature-level/model-level packet semantics',
       'needed_to_establish_model_level_semantics':[
           'Real original capture(s) with dataset/attack provenance',
           'The actual feature-extractor source, version and configuration used for the frozen CSV representation',
           'Mapping from capture packet/flow/window indices to the frozen CSV row IDs',
           'Baseline extraction equivalence before evaluating any transformed capture',
           'Re-extraction after an approved primitive transformation',
           'Protocol/application validity checks and an appropriate label-preservation argument',
           'Frozen-model evaluation on those consistently re-extracted predictors'],
       'important_feature_caution':[
           'Duration in CICIoT2023 is documented as TTL, not elapsed flow duration',
           'Do not treat the similarly named CICIoMT2024 field as a pacing primitive without original extractor confirmation',
           'This transformation changes recorded timestamps only; packet fields including TTL are byte-identical'],
       'data_only':'No generated packets, payloads or labels; no CSV feature fabrication',
       'scope':'A concrete first packet-level step, not a numerical status-flag fix or complete physical-validity certificate'}
    (OUT/'exact_remaining_packet_requirements.json').write_text(json.dumps(requirements,indent=2))
    print('\nCOMPLETED COMPUTATION COUNTS\n'+pd.DataFrame(progress).to_string(index=False),flush=True)
    print('\nPACKET PIPELINE STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    return statuses

if __name__=='__main__':
    PACKET_PIPELINE_STATUS=main()
