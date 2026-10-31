"""E1 - BLIND TARGET BUILDER (free: Kaggle CPU + Zeek). Builds independent IoT-23 target scenarios from time-slices of the original PCAPs, re-extracted with Zeek,
labels from the published labeled conn.log by exact connection key. Rules are declared BEFORE any model outcome: candidate order, slice plan, minimum 512 flows per class,
exclusion of flows starting in the last 120 s of a slice (truncation), reference-log margin 1800 s (flows longer than that cannot be labeled and are dropped; counted).
Design scenarios (1-1, 3-1, 8-1) are excluded. No model is trained or evaluated here."""
import glob,gzip,hashlib,json,os,re,shutil,struct,subprocess,traceback,warnings
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');MB=1024*1024
CANDIDATES=['CTU-Honeypot-Capture-5-1','CTU-IoT-Malware-Capture-7-1','CTU-IoT-Malware-Capture-9-1','CTU-IoT-Malware-Capture-33-1','CTU-IoT-Malware-Capture-36-1','CTU-IoT-Malware-Capture-39-1',
 'CTU-IoT-Malware-Capture-43-1','CTU-IoT-Malware-Capture-48-1','CTU-IoT-Malware-Capture-49-1','CTU-IoT-Malware-Capture-52-1','CTU-IoT-Malware-Capture-60-1']
DESIGN_EXCLUDED=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']
SLICE_PLAN=[(0,100*MB),(0,250*MB),(0,500*MB),(1000*MB,250*MB),(3000*MB,250*MB)]
MIN_CLASS=512;TRUNC_MARGIN=120.0;LOG_MARGIN=1800.0;ZEEK_TIMEOUT=3300;MIN_FREE=3*1024**3
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes']
MAGICS={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def zkey(ts,o,op,r,rp,pr):return (int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN)),o,str(op),r,str(rp),pr.lower())
def skey(k):return '|'.join(map(str,k))
def num(x):return 0.0 if x in('-','') else float(x)
def ensure_zeek():
 for p in [shutil.which('zeek'),'/opt/zeek/bin/zeek']:
  if p and Path(p).is_file() and os.access(p,os.X_OK):return p
 import requests
 release={}
 for line in Path('/etc/os-release').read_text().splitlines():
  if '='in line:k,v=line.split('=',1);release[k]=v.strip('"')
 if release.get('ID')!='ubuntu' or release.get('VERSION_ID')!='24.04':raise RuntimeError('Zeek auto-install implemented only for Ubuntu 24.04.')
 tools=WORK/'trace_tools';tools.mkdir(exist_ok=True);base='https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/'
 key=tools/'Release.key';r=requests.get(base+'Release.key',timeout=(20,90));r.raise_for_status();key.write_bytes(r.content);ring=tools/'zeek.gpg'
 subprocess.run(['gpg','--batch','--yes','--dearmor','--output',str(ring),str(key)],check=True)
 lst=tools/'sources.list';existing=Path('/etc/apt/sources.list').read_text() if Path('/etc/apt/sources.list').is_file() else ''
 lst.write_text(existing+'\n'+f'deb [signed-by={ring}] {base} /\n');opts=['-o',f'Dir::Etc::sourcelist={lst}','-o','Dir::Etc::sourceparts=/etc/apt/sources.list.d'];env=os.environ|{'DEBIAN_FRONTEND':'noninteractive'}
 subprocess.run(['apt-get',*opts,'update'],check=True,env=env,timeout=900)
 pol=subprocess.run(['apt-cache',*opts,'policy','zeek-8.0'],check=True,text=True,capture_output=True).stdout;m=re.search(r'Candidate:\s*(\S+)',pol)
 if not m or m.group(1)=='(none)':raise RuntimeError('zeek-8.0 candidate unavailable.')
 pkg='zeek-8.0='+m.group(1);sim=subprocess.run(['apt-get',*opts,'--simulate','--no-install-recommends','install',pkg],check=True,text=True,capture_output=True,env=env).stdout
 if re.search(r'^Remv\s|^Inst\s+\S+\s+\[',sim,re.M):raise RuntimeError('Install would upgrade/remove packages; stopped.')
 subprocess.run(['apt-get',*opts,'-y','--no-install-recommends','--no-upgrade','install',pkg],check=True,env=env,timeout=1800);return '/opt/zeek/bin/zeek'
def slice_pcap(src,dst,offset,max_bytes):
 with open(src,'rb')as f:
  hdr=f.read(24);magic=hdr[:4]
  if magic not in MAGICS:raise ValueError('Only classic pcap supported (pcapng refused).')
  endian,unit=MAGICS[magic];consumed=0
  while consumed<offset:
   rh=f.read(16)
   if len(rh)<16:return None
   incl=struct.unpack(endian+'IIII',rh)[2];f.seek(incl,1);consumed+=16+incl
  written=24;n=0;first=last=None
  with open(dst,'wb')as g:
   g.write(hdr)
   while written<max_bytes:
    rh=f.read(16)
    if len(rh)<16:break
    sec,frac,incl,orig=struct.unpack(endian+'IIII',rh);payload=f.read(incl)
    if len(payload)<incl:break
    g.write(rh);g.write(payload);written+=16+incl;n+=1;t=sec+frac*unit/1e9
    if first is None:first=t
    last=t
 if n==0:return None
 return {'bytes':written,'packets':n,'first_ts':first,'last_ts':last}
def read_conn(path):
 fields=None
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#'):
    if line.startswith('#fields'):fields=line.rstrip('\n').split('\t')[1:]
   else:break
 return pd.read_csv(path,sep='\t',comment='#',header=None,names=fields,dtype=str,keep_default_na=False)
def load_reference(path,t0,t1):
 labels={};fields=None;idx={};scanned=0;bad=0
 with open(path,encoding='utf-8',errors='replace')as f:
  for line in f:
   if line.startswith('#'):
    if line.startswith('#fields'):fields=line.split()[1:];idx={n:i for i,n in enumerate(fields)}
    continue
   if fields is None:continue
   tok=line.split()
   if len(tok)!=len(fields):bad+=1;continue
   ts=float(tok[0])
   if ts>t1+LOG_MARGIN:break
   scanned+=1
   if ts<t0-1 or ts>t1+1:continue
   lab=tok[idx['label']].lower();key=zkey(tok[0],tok[idx['id.orig_h']],tok[idx['id.orig_p']],tok[idx['id.resp_h']],tok[idx['id.resp_p']],tok[idx['proto']])
   labels[key]=(lab,tuple(num(tok[idx[c]]) for c in NUM))
 return labels,scanned,bad
def build_frame(gen,labels,first,last):
 g=gen.copy();g['ts_f']=pd.to_numeric(g['ts']);g=g[(g.ts_f<=last-TRUNC_MARGIN)&(g.ts_f>=first)]
 keys=[zkey(a,b,c,d,e,f) for a,b,c,d,e,f in zip(g['ts'],g['id.orig_h'],g['id.orig_p'],g['id.resp_h'],g['id.resp_p'],g['proto'])]
 hits=[labels.get(k) for k in keys];ok=np.array([h is not None for h in hits]);eligible=len(g)
 g=g[ok].copy();hits=[h for h in hits if h is not None];keys=[k for k,o in zip(keys,ok) if o]
 g['y']=[1 if h[0]=='malicious' else 0 if h[0]=='benign' else -1 for h in hits];g['ks']=[skey(k) for k in keys]
 for c in NUM:g[c]=pd.to_numeric(g[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 ref=np.array([h[1] for h in hits]) if hits else np.zeros((0,len(NUM)));fid=float(np.isclose(g[NUM].to_numpy(float),ref).all(axis=1).mean()) if len(g) else np.nan
 g=g[g.y>=0];dup=g.ks.duplicated(keep=False);g=g[~dup]
 g['resp_p']=pd.to_numeric(g['id.resp_p'],errors='coerce').fillna(-1);g['proto']=g['proto'].str.lower()
 return g[['ks','ts','resp_p','proto']+NUM+['y']],eligible,fid,int(dup.sum())
def main():
 OUT=WORK/('E1_BLIND_TARGETS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False);zeek=ensure_zeek()
 ev=sorted(glob.glob(str(WORK/'TRACE_LABEL_RECOVERY_*/scenario_label_evidence.csv')))
 if not ev:raise FileNotFoundError('Restored scenario_label_evidence.csv not found.')
 evidence=pd.read_csv(ev[0],keep_default_na=False);summary=[]
 for name in CANDIDATES:
  row={'scenario':name,'status':'NOT_ATTEMPTED','attempts':0}
  try:
   r=evidence[evidence.official_scenario==name]
   if len(r)!=1:raise RuntimeError('Scenario evidence ambiguous/missing.')
   caps=[Path(p) for p in json.loads(r.iloc[0]['local_capture_paths']) if Path(p).is_file()];logs=[Path(p) for p in json.loads(r.iloc[0]['local_log_paths']) if Path(p).is_file()]
   if not caps or len(logs)!=1:raise RuntimeError('Capture or single labeled log not mounted.')
   cap=max(caps,key=lambda p:p.stat().st_size);ref_log=logs[0];row.update({'capture':str(cap),'capture_bytes':cap.stat().st_size,'capture_choice':'largest PCAP in scenario (declared rule)'})
   sdir=OUT/name;sdir.mkdir()
   for attempt,(offset,size) in enumerate(SLICE_PLAN,1):
    row['attempts']=attempt
    if shutil.disk_usage(WORK).free<MIN_FREE:raise RuntimeError('Free disk below 3 GiB; stopped.')
    if offset>=cap.stat().st_size:row['status']='SLICE_OFFSET_BEYOND_CAPTURE';continue
    sl=sdir/'slice.pcap';meta=slice_pcap(cap,sl,offset,size)
    if meta is None:row['status']='EMPTY_SLICE';continue
    job=sdir/'zeek';shutil.rmtree(job,ignore_errors=True);job.mkdir()
    run=subprocess.run([zeek,'-C','-r',str(sl)],cwd=job,capture_output=True,text=True,timeout=ZEEK_TIMEOUT)
    if run.returncode or not (job/'conn.log').is_file():raise RuntimeError('Zeek failed: '+run.stderr[-400:])
    gen=read_conn(job/'conn.log');labels,scanned,bad=load_reference(ref_log,meta['first_ts'],meta['last_ts'])
    frame,eligible,fid,dup=build_frame(gen,labels,meta['first_ts'],meta['last_ts']);benign=int((frame.y==0).sum());mal=int((frame.y==1).sum())
    row.update({'slice_offset_MB':offset/MB,'slice_MB':meta['bytes']/MB,'packets':meta['packets'],'span_seconds':meta['last_ts']-meta['first_ts'],'generated_flows':len(gen),'eligible_flows_after_truncation_margin':eligible,
     'mapped_flows':len(frame),'mapped_fraction':len(frame)/max(eligible,1),'benign':benign,'malicious':mal,'core_field_identical_fraction_on_matched':fid,'duplicate_key_rows_removed':dup,'reference_lines_scanned':scanned,'reference_malformed_lines':bad})
    if benign>=MIN_CLASS and mal>=MIN_CLASS:
     feat=sdir/'features.csv.gz';frame.to_csv(feat,index=False,compression='gzip')
     with open(job/'conn.log','rb')as a,gzip.open(sdir/'conn.log.gz','wb',compresslevel=3)as b:shutil.copyfileobj(a,b)
     shutil.rmtree(job,ignore_errors=True)
     row.update({'status':'ACCEPTED','accepted_plan':f'offset {offset/MB:.0f} MB, slice {size/MB:.0f} MB','features_sha256':sha(feat),'slice_pcap_sha256':sha(sl),'source_pcap_sha256':sha(cap),'reference_log_sha256':sha(ref_log) if ref_log.stat().st_size<2*1024**3 else 'NOT_HASHED_LARGE'})
     break
    row['status']='REJECTED_MINORITY_CLASS_BELOW_MINIMUM';sl.unlink(missing_ok=True);shutil.rmtree(job,ignore_errors=True)
   else:
    if row['status'] not in('ACCEPTED',):row['status']=row['status'] if row['status']!='NOT_ATTEMPTED' else 'REJECTED_ALL_SLICES'
   if row['status']!='ACCEPTED':shutil.rmtree(sdir,ignore_errors=True)
  except Exception as error:
   row['status']='ERROR';row['error']=f'{type(error).__name__}: {error}';row['trace']=traceback.format_exc()[-800:]
  summary.append(row);pd.DataFrame(summary).to_csv(OUT/'blind_target_manifest.csv',index=False);print(name,row['status'],row.get('accepted_plan',''),'benign',row.get('benign'),'malicious',row.get('malicious'),flush=True)
 sm=pd.DataFrame(summary);acc=sm[sm.status=='ACCEPTED']
 receipt={'output_directory':str(OUT),'declared':{'candidates':CANDIDATES,'design_excluded':DESIGN_EXCLUDED,'slice_plan_MB':[(o/MB,s/MB) for o,s in SLICE_PLAN],'min_class':MIN_CLASS,'truncation_margin_s':TRUNC_MARGIN,'reference_margin_s':LOG_MARGIN},
  'candidates_attempted':len(sm),'accepted_blind_targets':len(acc),'accepted':acc.scenario.tolist(),'model_trained_or_evaluated':False,'labels_replaced':False,'prospective_design':'frozen source detector will be trained on design scenarios only'}
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 cols=['scenario','status','attempts','accepted_plan','packets','span_seconds','generated_flows','mapped_flows','mapped_fraction','benign','malicious','core_field_identical_fraction_on_matched']
 print('\nBLIND TARGET MANIFEST');print(sm[[c for c in cols if c in sm]].round(4).to_string(index=False))
 if 'error' in sm:print('\nERRORS');print(sm[sm.status=='ERROR'][['scenario','error']].to_string(index=False))
main()
