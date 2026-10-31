"""Bounded new Zeek record-count sensitivity experiment. No model or label use.
Two original captures; 32 MiB prefixes; pacing 0/1/3/10 s; four one-factor settings.
Never substitutes five-tuple groups for packet-attributed security units.
"""
import os,json,hashlib,struct,socket,shutil,subprocess,urllib.request,re,time,zipfile,sys
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter

W=Path('/kaggle/working')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
VERSION='8.0.10'
CONFIG={'captures':[48,49],'prefix_MiB':32,'max_packets':400000,'delays_seconds':[0,1,3,10],
 'settings':['DEFAULT','SYN_15S','ATTEMPT_15S','INACTIVITY_15S'],
 'unit':'bidirectional IPv4 TCP five-tuple group in the fixed prefix, NOT original labelled traffic unit',
 'pacing':'retain first packet timestamp of each IPv4 TCP group; add delay to its subsequent packets; stable timestamp sort',
 'detector_scoring':False,'label_use':False,'second_extractor':False,
 'scope':'new bounded offline extraction sensitivity, not reproduction of historical pacing or host functionality'}
O=W/('ZEEK_COUNT_SWEEP_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));O.mkdir(parents=True)
RESULTS=[];ERRORS=[];INPUTS=[]
def js(p,x):p.write_text(json.dumps(x,indent=2,default=str))
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def command(args,log,timeout=900):
 with open(log,'w') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 if r.returncode:raise RuntimeError(str(args[:3])+' failed; '+Path(log).read_text(errors='replace')[-1600:])
def zeek():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek']:
  if p and Path(p).is_file():
   v=subprocess.check_output([p,'--version'],stderr=subprocess.STDOUT,text=True).strip()
   if re.search(r'\b8\.0\.10\b',v):return p,v
   raise RuntimeError('Installed Zeek differs from frozen version: '+v)
 if os.geteuid()!=0:raise RuntimeError('Zeek missing; installation requires root')
 rel=dict(x.split('=',1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
 if rel.get('ID','').strip('"')!='ubuntu':raise RuntimeError('Automatic installation restricted to Ubuntu')
 ubuntu=rel['VERSION_ID'].strip('"')
 repo='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_'+ubuntu+'/'
 with urllib.request.urlopen(repo+'Release.key',timeout=60) as r:key=r.read()
 if b'BEGIN PGP PUBLIC KEY BLOCK' not in key:raise RuntimeError('Repository signing key invalid')
 kp=Path('/etc/apt/keyrings/zeek-count-sweep.asc');kp.parent.mkdir(exist_ok=True);kp.write_bytes(key)
 Path('/etc/apt/sources.list.d/zeek-count-sweep.list').write_text(f'deb [signed-by={kp}] {repo} /\n')
 command(['apt-get','update'],O/'apt_update.log')
 versions=subprocess.check_output(['apt-cache','madison','zeek-8.0'],text=True)
 matches=[x.split('|')[1].strip() for x in versions.splitlines() if len(x.split('|'))>1 and re.search(r'(^|:)8\.0\.10-',x.split('|')[1].strip())]
 if not matches:raise RuntimeError('Exact Zeek 8.0.10 not available; no replacement installed')
 command(['apt-get','install','-y','--no-install-recommends','zeek-8.0='+matches[0]],O/'apt_install.log')
 p='/opt/zeek/bin/zeek';v=subprocess.check_output([p,'--version'],stderr=subprocess.STDOUT,text=True).strip()
 if not re.search(r'\b8\.0\.10\b',v):raise RuntimeError('Installed version verification failed')
 return p,v
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def group(b,link):
 if link==1:
  if len(b)<14:return None
  typ=int.from_bytes(b[12:14],'big');o=14
  while typ in (0x8100,0x88a8,0x9100):
   if len(b)<o+4:return None
   typ=int.from_bytes(b[o+2:o+4],'big');o+=4
  if typ!=0x800:return None
 elif link==113:o=16
 elif link==276:o=20
 elif link in (101,228,12):o=0
 else:raise RuntimeError('Unsupported link type '+str(link))
 if len(b)<o+20 or b[o]>>4!=4:return None
 ihl=(b[o]&15)*4
 if b[o+9]!=6 or int.from_bytes(b[o+6:o+8],'big')&0x3fff or len(b)<o+ihl+4:return None
 a=socket.inet_ntoa(b[o+12:o+16]);z=socket.inet_ntoa(b[o+16:o+20]);p,q=struct.unpack('!HH',b[o+ihl:o+ihl+4])
 return tuple(sorted(((a,p),(z,q))))
def read_prefix(path):
 records=[];first={};counts=Counter();used=24
 with open(path,'rb') as f:
  header=f.read(24)
  if len(header)!=24 or header[:4] not in MAGIC:raise RuntimeError('Classic PCAP required: '+str(path))
  endian,scale=MAGIC[header[:4]];link=struct.unpack(endian+'I',header[20:24])[0]&65535
  while len(records)<CONFIG['max_packets']:
   h=f.read(16)
   if not h:break
   if len(h)!=16:raise RuntimeError('Truncated packet header')
   sec,sub,cap,wire=struct.unpack(endian+'IIII',h)
   if used+16+cap>CONFIG['prefix_MiB']*1024**2:break
   if cap>16*1024**2:raise RuntimeError('Implausible packet length')
   payload=f.read(cap)
   if len(payload)!=cap:raise RuntimeError('Truncated packet')
   k=group(payload,link);ts=sec*10**9+sub*scale
   if k is not None:first.setdefault(k,len(records));counts[k]+=1
   records.append((ts,cap,wire,payload,k));used+=16+cap
 return header,endian,scale,records,first,counts

def write_trace(path,header,endian,scale,records,first,delay):
 ordered=sorted(range(len(records)),key=lambda i:(records[i][0]+(delay*10**9 if records[i][4] is not None and first[records[i][4]]!=i else 0),i))
 h1=hashlib.sha256();h2=hashlib.sha256();prev={}
 for _,cap,wire,b,k in records:h1.update(struct.pack('!II',cap,wire)+b)
 with open(path,'wb') as f:
  f.write(header)
  for i in ordered:
   ts,cap,wire,b,k=records[i]
   if k is not None:
    if i<=prev.get(k,-1):raise RuntimeError('Within-group ordering changed; input timestamps may be unsorted')
    prev[k]=i
   ts+=delay*10**9 if k is not None and first[k]!=i else 0
   f.write(struct.pack(endian+'IIII',ts//10**9,(ts%10**9)//scale,cap,wire));f.write(b)
 # Payload identity is exact by construction: every input packet index is written once.
 if len(ordered)!=len(records) or len(set(ordered))!=len(records):raise RuntimeError('Packet identity check failed')
 return {'packets':len(records),'delayed_packets':sum(1 for i,r in enumerate(records) if delay and r[4] is not None and first[r[4]]!=i),
 'packet_bytes_unchanged':True,'packet_occurrences_preserved':True,'five_tuple_group_order_preserved':True,'sha256':sha(path)}
TAP="""@load base/protocols/conn
redef LogAscii::use_json = T;
event zeek_init() {
 print fmt("SETTINGS|%s|%s|%s", tcp_SYN_timeout, tcp_attempt_delay, tcp_inactivity_timeout);
}
"""
def replay(binary,pcap,folder,setting,cap,delay,groups):
 folder.mkdir();tap=folder/'settings.zeek'
 red={'DEFAULT':'','SYN_15S':'redef tcp_SYN_timeout = 15 secs;\n',
 'ATTEMPT_15S':'redef tcp_attempt_delay = 15 secs;\n','INACTIVITY_15S':'redef tcp_inactivity_timeout = 15 secs;\n'}[setting]
 tap.write_text(TAP+red)
 command([binary,'-b',str(tap.resolve())],folder/'compile.log',60)
 start=time.monotonic()
 with open(folder/'stdout.txt','w') as so,open(folder/'stderr.txt','w') as se:
  r=subprocess.run([binary,'-C','-r',str(pcap.resolve()),str(tap.resolve())],cwd=folder,stdout=so,stderr=se,timeout=1800)
 if r.returncode:raise RuntimeError('Replay failed: '+(folder/'stderr.txt').read_text(errors='replace')[-1200:])
 settings=[x for x in (folder/'stdout.txt').read_text().splitlines() if x.startswith('SETTINGS|')]
 if len(settings)!=1:raise RuntimeError('Actual settings not reported')
 log=folder/'conn.log'
 if not log.is_file():raise RuntimeError('conn.log absent')
 per=Counter();types=Counter();states=Counter();total=0
 with open(log) as f:
  for line in f:
   x=json.loads(line);total+=1;types[x.get('proto','?')]+=1;states[x.get('conn_state','?')]+=1
   if x.get('proto')=='tcp':
    k=tuple(sorted(((x['id.orig_h'],int(x['id.orig_p'])),(x['id.resp_h'],int(x['id.resp_p'])))))
    if k in groups:per[k]+=1
 counts=[per[k] for k in groups]
 row={'capture':cap,'delay_seconds':delay,'setting':setting,'actual_settings':settings[0],'packet_sha256':sha(pcap),
 'replay_seconds':time.monotonic()-start,'records_total':total,'records_tcp':types['tcp'],'input_tcp_groups':len(groups),
 'groups_with_zero_records':sum(x==0 for x in counts),'groups_with_multiple_records':sum(x>1 for x in counts),
 'records_per_input_group_mean':sum(counts)/len(counts) if counts else None,'connection_states':json.dumps(states,sort_keys=True),
 'conn_log_sha256':sha(log),'scope':'five-tuple counts only; no packet-to-unit lineage or security scoring'}
 with open(folder/'counts_by_group.csv','w') as f:
  f.write('group_sha256,input_packets,extracted_records\n')
  for k,n in groups.items():f.write(hashlib.sha256(repr(k).encode()).hexdigest()+f',{n},{per[k]}\n')
 js(folder/'receipt.json',dict(status='REPLAY_COUNT_COMPLETE',**row))
 # Full extraction log is hashed before deletion; compact counts and settings are retained.
 log.unlink()
 for q in folder.glob('*.log'):
  if q.name!='compile.log':q.unlink()
 return row

def main():
 js(O/'FROZEN_PROTOCOL.json',CONFIG)
 if not RAW.is_dir():raise RuntimeError('Attach the original IoT-23 dataset at '+str(RAW))
 if shutil.disk_usage(W).free<2*1024**3:raise RuntimeError('Need 2 GiB free; no existing work deleted')
 binary,version=zeek();js(O/'environment.json',{'zeek':version,'binary':binary,'python':sys.version})
 for cap in CONFIG['captures']:
  paths=[p for p in RAW.rglob('*.pcap') if f'CTU-IoT-Malware-Capture-{cap}-1' in p.parts]
  if not paths:raise RuntimeError('Original PCAP absent for capture '+str(cap))
  source=max(paths,key=lambda p:p.stat().st_size)
  header,endian,scale,records,first,groups=read_prefix(source)
  if not records:raise RuntimeError('Empty prefix')
  INPUTS.append({'capture':cap,'source':str(source),'prefix_packets':len(records),'tcp_groups':len(groups),'prefix_budget_MiB':CONFIG['prefix_MiB']})
  for delay in CONFIG['delays_seconds']:
   trace=O/f'capture{cap}_delay{delay}.pcap';proof=write_trace(trace,header,endian,scale,records,first,delay)
   js(O/f'capture{cap}_delay{delay}_packet_checks.json',proof)
   for setting in CONFIG['settings']:
    name=f'capture{cap}_delay{delay}_{setting}';folder=O/name
    print('RUN',name,flush=True)
    try:
     row=replay(binary,trace,folder,setting,cap,delay,groups);RESULTS.append(row)
     print('RESULT',json.dumps(row),flush=True)
    except Exception as ex:ERRORS.append({'job':name,'error':str(ex)});print('FAILED',name,str(ex),flush=True)
    js(O/'RESULTS.json',RESULTS);js(O/'errors.json',ERRORS)
   trace.unlink()
  del records,first,groups
 expected=len(CONFIG['captures'])*len(CONFIG['delays_seconds'])*len(CONFIG['settings'])
 js(O/'receipt.json',{'status':'COMPLETE_FOR_FROZEN_GRID' if len(RESULTS)==expected and not ERRORS else 'PARTIAL',
 'expected_replays':expected,'successful_replays':len(RESULTS),'errors':ERRORS,'model_fits':0,'detector_scoring':False,
 'other_extractors_tested':False,'extractor_generality_claimed':False,'scope':CONFIG['scope']})

try:main()
except Exception as e:
 ERRORS.append({'stage':'setup_or_intake','error':str(e)})
 js(O/'receipt.json',{'status':'STOPPED_WITH_REASON','reason':str(e),'successful_replays':len(RESULTS)})
 print('STOPPED:',e,flush=True)
finally:
 js(O/'inputs.json',INPUTS);js(O/'RESULTS.json',RESULTS);js(O/'errors.json',ERRORS)
 import csv
 if RESULTS:
  with open(O/'RESULTS.csv','w',newline='') as f:
   wr=csv.DictWriter(f,fieldnames=list(RESULTS[0]));wr.writeheader();wr.writerows(RESULTS)
 notes=['# New Zeek record-count sensitivity experiment',
 'This is a new bounded extraction experiment, not a reproduction of historical selected-unit pacing.',
 'Grouping is by bidirectional IPv4 TCP five-tuple within a fixed prefix, not labelled original traffic units.',
 'Each input packet is preserved once with unchanged bytes. Subsequent TCP-group packets are delayed and stably sorted.',
 'Default is compared with one-factor changes to SYN timeout, attempt delay, and inactivity timeout.',
 'Protocol/port-specific inactivity overrides may still apply. These settings are not all equivalent for all connection states.',
 'Per-group counts do not measure malicious recall, attribution purity, application functionality, or monitor accuracy.',
 'NFStream/Argus are not run. Cross-extractor generality remains untested.',
 'Use only jobs with REPLAY_COUNT_COMPLETE. See receipt.json for completeness of this fixed 32-job grid.']
 (O/'METHOD_AND_SCOPE.md').write_text('\n\n'.join(notes))
 zpath=O/'PRIVATE_COUNT_SWEEP.zip'
 with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(O.rglob('*')):
   if p.is_file() and p!=zpath and p.suffix!='.pcap':z.write(p,str(p.relative_to(O)))
 with zipfile.ZipFile(zpath) as z:
  if z.testzip():raise RuntimeError('ZIP CRC failed')
 print('\nFINAL RECEIPT\n'+(O/'receipt.json').read_text(),flush=True)
 print('OUTPUT:',O,'\nPACKAGE:',zpath,flush=True)
