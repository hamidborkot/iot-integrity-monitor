"""Two offline pipeline-validity experiments: null time offset and affine pacing.
Method-engineering only on the already inspected Capture-8 pilot. No model or attack-efficacy evaluation.
Keeps packet bytes, lengths and order exactly. Does not claim live functionality/TCP validity.
"""
import bisect,hashlib,json,re,struct,subprocess,zipfile
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import pandas as pd

WORK=Path('/kaggle/working');PILOT=WORK/'TRACE_CLEAN_REPLAY_20261011T161846072286Z'
OUT=WORK/('TRACE_C0_PAIRED_VALIDITY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
ZEEK='/opt/zeek/bin/zeek'
CORE=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
UNCHANGED=[f for f in CORE if f!='duration']
MICRO_TOLERANCE=2
CASES=[{'name':'offset_null_control','numerator':1,'denominator':1,'offset_seconds':1},
       {'name':'affine_pacing_5pct','numerator':21,'denominator':20,'offset_seconds':0}]

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')
def load_log(p):
 fields=None;rows=[]
 with p.open('r',encoding='utf-8')as f:
  for number,line in enumerate(f,1):
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   parts=line.strip().split()
   if fields is None or len(parts)!=len(fields):raise ValueError('Invalid log schema/row: '+str(p))
   row=dict(zip(fields,parts));row['_line']=number;rows.append(row)
 return rows

def records(p):
 with p.open('rb')as f:
  header=f.read(24)
  magic={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
  if len(header)!=24 or header[:4]not in magic:raise ValueError('Only classic micro/nanosecond PCAP supported; no format guessing.')
  endian,scale=magic[header[:4]]
  yield ('header',header,endian,scale)
  while True:
   raw=f.read(16)
   if not raw:break
   if len(raw)!=16:raise ValueError('Truncated packet header.')
   seconds,fraction,caplen,wirelen=struct.unpack(endian+'IIII',raw)
   if fraction>=scale or caplen>64*1024**2 or caplen>wirelen:raise ValueError('Invalid capture record.')
   payload=f.read(caplen)
   if len(payload)!=caplen:raise ValueError('Truncated captured packet.')
   yield ('packet',seconds*scale+fraction,caplen,wirelen,payload)

def transform(source,dest,case):
 first=None;count=0;max_delay=0
 iterator=records(source);_,header,endian,scale=next(iterator)
 with dest.open('wb')as f:
  f.write(header)
  for _,ticks,caplen,wirelen,payload in iterator:
   if first is None:first=ticks
   delta=ticks-first
   # Integer rounding at the original PCAP precision, not floating timestamp synthesis.
   shifted=first+(delta*case['numerator']+case['denominator']//2)//case['denominator']+case['offset_seconds']*scale
   if shifted<ticks:raise ValueError('Transformation introduces a negative delay.')
   sec,frac=divmod(shifted,scale)
   if not 0<=sec<=0xffffffff:raise ValueError('Timestamp overflow.')
   f.write(struct.pack(endian+'IIII',sec,frac,caplen,wirelen));f.write(payload)
   max_delay=max(max_delay,shifted-ticks);count+=1
 return {'first_timestamp_ticks':first,'precision_ticks_per_second':scale,'packets':count,'max_delay_seconds':max_delay/scale}

def verify_packet_identity(a,b,case):
 x=records(a);y=records(b);ha=next(x);hb=next(y)
 if ha!=hb:raise ValueError('Global capture header changed.')
 first=None;count=0;digest=hashlib.sha256();inversions_a=0;inversions_b=0;last_a=last_b=None
 while True:
  ra=next(x,None);rb=next(y,None)
  if ra is None or rb is None:
   if ra is not None or rb is not None:raise ValueError('Packet count changed.')
   break
  if first is None:first=ra[1]
  expected=first+((ra[1]-first)*case['numerator']+case['denominator']//2)//case['denominator']+case['offset_seconds']*ha[3]
  if rb[1]!=expected or ra[2:]!=rb[2:]:raise ValueError('Timestamp transformation or packet bytes/lengths/order failed.')
  if last_a is not None and ra[1]<last_a:inversions_a+=1
  if last_b is not None and rb[1]<last_b:inversions_b+=1
  last_a,last_b=ra[1],rb[1]
  digest.update(struct.pack('>II',ra[2],ra[3]));digest.update(ra[4]);count+=1
 return {'all_packet_bytes_lengths_order_preserved':True,'all_timestamp_transformations_verified':True,'packets':count,
  'packet_content_sequence_sha256':digest.hexdigest(),'original_timestamp_inversions':inversions_a,'transformed_timestamp_inversions':inversions_b}

def micros(s):return int((Decimal(s)*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def flowtuple(r):return (r['id.orig_h'],r['id.orig_p'],r['id.resp_h'],r['id.resp_p'],r['proto'].lower())
def numeq(a,b):
 if a=='-'or b=='-':return a==b
 return Decimal(a)==Decimal(b)

selection=json.loads((PILOT/'smoke_selection.json').read_text());capture=Path(selection['capture']);reference=Path(selection['reference'])
if selection['scenario']!='CTU-IoT-Malware-Capture-8-1':raise ValueError('This engineering pilot is locked to the already linked Capture-8-1.')
if sha(capture)!=selection['pcap_sha256']or sha(reference)!=selection['reference_log_sha256']:raise ValueError('Pilot source changed.')
ref=load_log(reference);v=subprocess.run([ZEEK,'--version'],capture_output=True,text=True,timeout=30)
if v.returncode:raise RuntimeError('Zeek not runnable.')
plan={'purpose':'EXTRACTION_METHOD_VALIDATION_ONLY_NOT_CONFIRMATION_OR_ATTACK_SUCCESS','source_capture':str(capture),
 'source_capture_sha256':sha(capture),'source_reference_sha256':sha(reference),'cases':CASES,'timestamp_mapping_tolerance_microseconds':MICRO_TOLERANCE,
 'labels':'Supplied labels only on uniquely mapped connections; no inferred replacement labels.',
 'runtime_version':v.stdout.strip()or v.stderr.strip(),'protocol_scope':'Recorded-trace timing transformation; packet contents preserved; no live-network functionality claim',
 'primary_model_training_allowed':False,'confirmatory_scenario_selection':False}
save(OUT/'engineering_protocol_before_results.json',plan)
results=[];errors=[]
for case in CASES:
 folder=OUT/case['name'];folder.mkdir();pcap=folder/'transformed.pcap'
 try:
  transformed=transform(capture,pcap,case);identity=verify_packet_identity(capture,pcap,case)
  save(folder/'packet_identity_receipt.json',{**transformed,**identity,'pcap_sha256':sha(pcap)})
  replay=folder/'replay';replay.mkdir()
  with (folder/'zeek.log').open('w')as f:
   r=subprocess.run([ZEEK,'-C','-r',str(pcap)],cwd=replay,stdout=f,stderr=subprocess.STDOUT,timeout=900)
  if r.returncode or not(replay/'conn.log').is_file():raise RuntimeError('Zeek transformed replay failed; see zeek.log.')
  gen=load_log(replay/'conn.log');origin=Decimal(transformed['first_timestamp_ticks'])/Decimal(transformed['precision_ticks_per_second'])
  expected=defaultdict(list)
  for index,row in enumerate(ref):
   ts=origin+(Decimal(row['ts'])-origin)*Decimal(case['numerator'])/Decimal(case['denominator'])+case['offset_seconds']
   expected[flowtuple(row)].append((micros(str(ts)),index))
  sorted_times={};sorted_ids={}
  for k,pairs in expected.items():
   pairs.sort();sorted_times[k]=[p[0]for p in pairs];sorted_ids[k]=[p[1]for p in pairs]
  candidates=[]
  for g in gen:
   k=flowtuple(g);ts=micros(g['ts']);times=sorted_times.get(k,[]);ids=sorted_ids.get(k,[])
   a=bisect.bisect_left(times,ts-MICRO_TOLERANCE);b=bisect.bisect_right(times,ts+MICRO_TOLERANCE)
   candidates.append(ids[a:b])
  claims=Counter(ids[0]for ids in candidates if len(ids)==1)
  unmatched=ambiguous=0;matched=0;diff=Counter();duration_diff=[];label_counts=Counter();mapped_rows=[]
  for g,ids in zip(gen,candidates):
   if not ids:unmatched+=1;continue
   if len(ids)!=1 or claims[ids[0]]!=1:ambiguous+=1;continue
   original=ref[ids[0]];matched+=1;label_counts[original['label'].lower()]+=1
   for f in UNCHANGED:
    eq=original[f]==g[f]if f=='proto'else numeq(original[f],g[f])
    if not eq:diff[f]+=1
   if original['duration']!='-'and g['duration']!='-':duration_diff.append(float(Decimal(g['duration'])-Decimal(original['duration'])))
   mapped_rows.append({'reference_line':original['_line'],'transformed_line':g['_line'],'published_label':original['label'],
    'original_duration':original['duration'],'transformed_duration':g['duration'],'flow_start_error_microseconds':micros(g['ts'])-sorted_times[flowtuple(g)][sorted_ids[flowtuple(g)].index(ids[0])]})
  pd.DataFrame(mapped_rows).to_csv(folder/'unique_transformed_flow_mapping.csv',index=False)
  info={'case':case['name'],'original_records':len(ref),'transformed_records':len(gen),'unique_label_linked_records':matched,
   'unmatched_transformed_records':unmatched,'ambiguous_transformed_records':ambiguous,'unlinked_original_records':len(ref)-matched,
   'mapped_published_label_counts':dict(label_counts),'unchanged_counter_or_protocol_differences':dict(diff),
   'mean_duration_change_seconds':sum(duration_diff)/len(duration_diff)if duration_diff else None,
   'duration_changes_checked':len(duration_diff),'full_unique_mapping':matched==len(ref)==len(gen),**identity,
   'maximum_packet_delay_seconds':transformed['max_delay_seconds'],'labels_replaced':False,
   'live_application_functionality_tested':False,'TCP_semantic_validity_certified':False,'packet_valid_attack_approved':False}
  save(folder/'result.json',info);results.append(info)
  print(case['name'],'MAPPED',matched,'/',len(gen),'UNMATCHED',unmatched,'COUNTER DIFF',dict(diff),flush=True)
 except Exception as e:errors.append({'case':case['name'],'error':f'{type(e).__name__}: {e}'})
pd.DataFrame(results).to_csv(OUT/'paired_validity_results.csv',index=False)
pd.DataFrame(errors,columns=['case','error']).to_csv(OUT/'explicit_errors.csv',index=False)
receipt={'output_directory':str(OUT),'engineering_cases_planned':len(CASES),'engineering_cases_completed':len(results),'explicit_errors':len(errors),
 'packet_content_identity_checks_computed':len(results),'label_mapping_computed':len(results),'models_trained':False,
 'detector_attack_efficacy_evaluated':False,'confirmatory_results_generated':False,'primary_allocation_frozen':False,
 'published_labels_replaced':False,'NF_changed':False,'packet_valid_attack_approved':False,
 'next_step':'Review actual format/flow mapping and duration changes, then precommit final transformation budget and trace allocation before training/attack-efficacy outcomes.'}
save(OUT/'receipt.json',receipt)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED)as z:
 for p in OUT.rglob('*'):
  if p.is_file()and p.suffix in {'.json','.csv'}:z.write(p,str(p.relative_to(OUT)))
with zipfile.ZipFile(package)as z:
 if z.testzip()is not None:raise RuntimeError('Review ZIP integrity failure.')
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package)},indent=2))
print('\nPAIRED PIPELINE VALIDITY RESULTS');print(pd.DataFrame(results).to_string(index=False))
print('\nERRORS');print(pd.DataFrame(errors).to_string(index=False)if errors else'None')
