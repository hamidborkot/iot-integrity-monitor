# Ground-truth provenance extension. No training, replay, or relabeling.
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from collections import defaultdict
import gzip, hashlib, io, json, os, traceback, zipfile
import numpy as np
import pandas as pd

WORK=Path('/kaggle/working')
OUT=WORK/('PUBLISHED_GROUND_TRUTH_LINKAGE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
PREVIOUS_RUN='EXPERIMENTAL_COMPLETION_20261028T082656379467Z'
PREVIOUS_SHA='3ef69c8f15ee0f572bad5159a1eb3c951f8098e1fe0d17ad24f6a39092fef19e'
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
INDEX=[];LABEL_FILES=[];USED=[];LEDGER=[]
SOURCES={
 'publisher':'https://www.stratosphereips.org/datasets-iot23',
 'v1_doi':'10.5281/zenodo.4743746',
 'v2_readme_for_version_distinction_only':'https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html',
 'zeek_connection_semantics':'https://docs.zeek.org/en/lts/scripts/base/protocols/conn/main.zeek.html',
}
class Blocked(Exception):pass

def js(p,x):Path(p).write_text(json.dumps(x,indent=2,default=str,allow_nan=False),encoding='utf-8')
def sha_file(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def origin(a):return a['path']+('::'+a['member'] if a.get('member') else '')
def read(a):
 if a.get('member'):
  with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:b=f.read(128*1024**2+1)
 else:
  with open(a['path'],'rb') as f:b=f.read(128*1024**2+1)
 if len(b)>128*1024**2:raise Blocked('Cohort artifact too large: '+origin(a))
 return b

def discover():
 archives=[]
 for root in [WORK,Path('/kaggle/input')]:
  if not root.exists():continue
  for base,dirs,files in os.walk(root):
   bp=Path(base)
   dirs[:]=[x for x in dirs if bp/x!=OUT and x not in {'.git','__pycache__','site-packages'} and not x.startswith('.zeek')]
   for name in files:
    p=bp/name
    if name in ['conn.log.labeled','conn.log.labeled.gz']:
     if 'IoT-23-Dataset-v2' not in str(p):LABEL_FILES.append(p)
    if p.suffix.lower()=='.zip':archives.append(p)
    elif name=='frozen_clean_cohort.csv.gz' or name=='frozen_clean_cohort.csv':
     INDEX.append({'path':str(p),'member':None,'verified_previous_archive':False})
 for p in archives:
  try:
   with zipfile.ZipFile(p) as z:
    members=[n for n in z.infolist() if Path(n.filename).name in ['frozen_clean_cohort.csv.gz','frozen_clean_cohort.csv'] and n.file_size<128*1024**2]
    if not members:continue
    verified=(p.name=='CHECKPOINT.zip' or PREVIOUS_RUN in str(p)) and sha_file(p)==PREVIOUS_SHA
    for n in members:INDEX.append({'path':str(p),'member':n.filename,'verified_previous_archive':bool(verified)})
  except (OSError,zipfile.BadZipFile):pass
 js(OUT/'discovery.json',{'cohort_candidates':[origin(a) for a in INDEX],'mounted_label_logs':[str(p) for p in LABEL_FILES]})
 if not INDEX:raise Blocked('Attach the previous original CHECKPOINT.zip/output containing frozen_clean_cohort.csv.gz, not only the later small MD3 repair package.')
 if not LABEL_FILES:raise Blocked('Attach original IoT-23 v1 labelled logs. No v2 labels or guessed labels substituted.')

def cohort(scope):
 options=[a for a in INDEX if scope in origin(a) and (PREVIOUS_RUN in origin(a) or a['verified_previous_archive'])]
 hashes=defaultdict(list)
 for a in options:hashes[hashlib.sha256(read(a)).hexdigest()].append(a)
 if len(hashes)!=1:raise Blocked(scope+': expected one distinct frozen cohort, found '+str(len(hashes)))
 a=next(iter(hashes.values()))[0];b=read(a)
 if b[:2]==b'\x1f\x8b':b=gzip.decompress(b)
 df=pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)
 if not set(F+['ks','y'])<=set(df):raise Blocked('Frozen cohort fields missing')
 if len(df)!=1024 or df.ks.duplicated().any():raise Blocked('Frozen1024-unit cohort mismatch')
 df['y']=pd.to_numeric(df.y,errors='raise').astype(int)
 if df.y.eq(0).sum()!=512 or df.y.eq(1).sum()!=512:raise Blocked('Frozen512+512class counts mismatch')
 USED.append({'role':scope,'origin':origin(a),'sha256':hashlib.sha256(read(a)).hexdigest()})
 return df

def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def legacy(k):
 for sep in ['|','::',',']:
  v=str(k).split(sep)
  if len(v)==6:
   try:return int(v[0]),v[1],int(v[2]),v[3],int(v[4]),v[5].lower()
   except ValueError:pass
 raise Blocked('Unrecognized original unit key')
def numeric(x):
 value=0.0 if x in ['', '-', None] else float(x)
 if not np.isfinite(value) or value<0:raise Blocked('Invalid nonnegative feature')
 return value

def label_file(capture):
 scenario=f'CTU-IoT-Malware-Capture-{capture}-1'
 options=[p for p in LABEL_FILES if scenario in p.parts]
 by_hash=defaultdict(list)
 for p in options:by_hash[sha_file(p)].append(p)
 if len(by_hash)!=1:raise Blocked(scenario+': expected one distinct mounted original label log, found '+str(len(by_hash)))
 digest,paths=next(iter(by_hash.items()));p=sorted(paths,key=str)[0]
 USED.append({'role':'published_v1_label_log_capture'+str(capture),'path':str(p),'observed_sha256':digest,
              'identity_compared_with_publisher_download_checksum':False})
 return p,digest

def reference_identity(row):
 return (us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower())

def audit_capture(capture,scope,style):
 d=OUT/('capture'+str(capture));d.mkdir(exist_ok=True)
 df=cohort(scope);wanted={}
 for row in df.to_dict('records'):
  identity=reference_identity(row) if style=='hash' else legacy(row['ks'])
  if identity in wanted:raise Blocked('Two frozen keys have the same original identity')
  if style=='hash':
   expected=hashlib.sha256(json.dumps(identity,separators=(',',':')).encode()).hexdigest()
   if expected!=row['ks']:raise Blocked('Frozen hash key disagrees with its endpoint/time metadata')
  wanted[identity]=row
 label_path,file_hash=label_file(capture)
 physical=records=matched_lines=0;fields=None;matches=defaultdict(list)
 requested_times={k[0] for k in wanted}
 opener=gzip.open if label_path.suffix=='.gz' else open
 with opener(label_path,'rb') as handle, gzip.open(d/'matched_published_raw_lines.jsonl.gz','wt',encoding='utf-8') as rawout:
  for physical,raw in enumerate(handle,1):
   line=raw.decode('utf-8',errors='strict')
   if line.startswith('#fields'):
    fields=line.strip().split()[1:]
    required={'ts','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','label'}|set(F)
    if not required<=set(fields):raise Blocked('Published v1 header fields missing: '+str(required-set(fields)))
    continue
   if line.startswith('#') or not line.strip():continue
   if fields is None:raise Blocked('Published label log lacks a fields header')
   records+=1
   values=line.rstrip().split()
   if len(values)!=len(fields):raise Blocked('Published row width mismatch at physical line '+str(physical))
   row=dict(zip(fields,values))
   if us(row['ts']) not in requested_times:continue
   identity=reference_identity(row)
   if identity not in wanted:continue
   frozen=wanted[identity]
   label=row['label'].strip().lower()
   published_y={'benign':0,'malicious':1}.get(label)
   feature_mismatches=[]
   for feature in F:
    okay=(str(row[feature]).lower()==str(frozen[feature]).lower()) if feature=='proto' else bool(np.isclose(numeric(row[feature]),numeric(frozen[feature]),atol=1e-9,rtol=1e-9))
    if not okay:feature_mismatches.append(feature)
   record={'capture':capture,'ks':frozen['ks'],'frozen_y':int(frozen['y']),
     'published_primary_label':row['label'],'published_y':published_y,
     'published_detailed_label':row.get('detailed-label',row.get('detailed_label','')),
     'published_uid':row.get('uid',''),'published_physical_line':physical,
     'published_row_sha256':hashlib.sha256(raw).hexdigest(),
     'label_log_sha256':file_hash,'numeric_feature_mismatches':'|'.join(feature_mismatches),
     'label_agrees':published_y==int(frozen['y']) if published_y is not None else False}
   matches[frozen['ks']].append(record);matched_lines+=1
   rawout.write(json.dumps({'physical_line':physical,'ks':frozen['ks'],'original_line':line,'row_sha256':record['published_row_sha256']})+'\n')
   if records%1000000==0:print('Capture',capture,'published rows scanned',records,flush=True)
 # Finish the whole label log: stopping at the first match would miss conflicting duplicates.
 result=[]
 for k in df.ks:
  rr=matches.get(k,[])
  if len(rr)==1:
   r=dict(rr[0]);r['published_identity_matches']=1
   r['row_linkage_status']='VERIFIED' if r['label_agrees'] and not r['numeric_feature_mismatches'] else 'DISCREPANCY'
  else:
   r={'capture':capture,'ks':k,'frozen_y':int(df.set_index('ks').loc[k,'y']),
      'published_identity_matches':len(rr),'row_linkage_status':'MISSING' if not rr else 'AMBIGUOUS_PUBLISHED_IDENTITY'}
  result.append(r)
 report=pd.DataFrame(result)
 report.to_csv(d/'PUBLISHED_GROUND_TRUTH_PER_UNIT.csv',index=False)
 pd.DataFrame([x for records_for_key in matches.values() for x in records_for_key]).to_csv(d/'ALL_PUBLISHED_IDENTITY_MATCHES.csv',index=False)
 df.to_csv(d/'frozen_cohort_used.csv.gz',index=False,compression='gzip')
 good=bool(report.row_linkage_status.eq('VERIFIED').all())
 receipt={'capture':capture,'status':'PUBLISHED_LABEL_ROW_LINKAGE_VERIFIED' if good else 'PUBLISHED_LABEL_LINKAGE_DISCREPANCIES',
   'original_units':len(df),'verified_units':int(report.row_linkage_status.eq('VERIFIED').sum()),
   'full_published_log_records_scanned':records,'physical_lines_scanned':physical,
   'label_log_observed_sha256':file_hash,'label_log_mount_path':str(label_path),
   'published_label_ground_truth':'dataset-supplied analyst/rule annotations for original connections',
   'new_independent_expert_packet_ledger_created':False,'transformed_packet_mapping_validated_by_published_class_labels':False,
   'labels_changed':False,'new_model_fits':0,'new_PCAP_replays':0,'publisher_download_checksum_match_established':False}
 js(d/'receipt.json',receipt);LEDGER.append(receipt);package('capture'+str(capture))
 print(json.dumps(receipt,indent=2),flush=True)


def package(stage):
 js(OUT/'ledger.json',LEDGER);js(OUT/'used_inputs.json',USED)
 members=[]
 for p in sorted(OUT.rglob('*')):
  if p.is_file() and p.name not in {'GROUND_TRUTH_PROVENANCE.zip','GROUND_TRUTH_PROVENANCE.zip.tmp','manifest.json','PACKAGE.sha256'}:
   members.append({'name':p.relative_to(OUT).as_posix(),'sha256':sha_file(p),'bytes':p.stat().st_size})
 js(OUT/'manifest.json',{'stage':stage,'files':members})
 tmp=OUT/'GROUND_TRUTH_PROVENANCE.zip.tmp'
 with zipfile.ZipFile(tmp,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as z:
  for row in members:z.write(OUT/row['name'],arcname=row['name'])
  z.write(OUT/'manifest.json',arcname='manifest.json')
 with zipfile.ZipFile(tmp) as z:
  bad=z.testzip()
  if bad:raise RuntimeError('ZIP integrity failure: '+bad)
 os.replace(tmp,OUT/'GROUND_TRUTH_PROVENANCE.zip')
 digest=sha_file(OUT/'GROUND_TRUTH_PROVENANCE.zip');(OUT/'PACKAGE.sha256').write_text(digest+'\n')
 print('PACKAGE',OUT/'GROUND_TRUTH_PROVENANCE.zip','SHA256',digest,flush=True)
 try:
  from IPython.display import display,FileLink
  display(FileLink(str(OUT/'GROUND_TRUTH_PROVENANCE.zip')))
 except Exception:pass


def main():
 js(OUT/'ONLINE_SOURCE_PROVENANCE.json',{'sources':SOURCES,
   'publisher_documentation_checked_in_assistant_response':'2026-10-28',
   'source_statement':'IoT23v1 authors describe manual PCAP analysis and analyst-created rules applied with Flaber; final labels in bro/conn.log.labeled.',
   'version_policy':'Use the experiment original v1 annotations. Do not substitute the revised v2 labels.',
   'online_pages_do_not_provide_this_experiment_transformed_packet_UID_ledger':True})
 (OUT/'GROUND_TRUTH_SCOPE.md').write_text(
   '# Ground-truth scope\n\n'
   'Published benign/malicious ground truth exists for the original IoT-23 connections. '
   'This program audits the exact identity and label linkage for the two frozen1024-unit cohorts and saves matched original rows.\n\n'
   'This is annotation provenance and consistency verification, not a new set of independent expert labels. '
   'Published class annotations do not independently adjudicate transformed packet ownership, Zeek UID purity or the unresolved historical unit. '
   'Existing attribution intervals and the separate implementation check remain as reported.\n\n'
   'Mounted log hashes are recorded. Publisher-download byte identity is not asserted without a separately verified publisher checksum.\n',encoding='utf-8')
 try:
  source=Path(__file__)
  if source.is_file():(OUT/'executed_source.py').write_text(source.read_text())
 except NameError:pass
 try:discover()
 except Exception as e:
  (OUT/'discovery_error.txt').write_text(traceback.format_exc());LEDGER.append({'task':'discovery','status':'BLOCKED','reason':str(e)})
  package('discovery_blocked');return
 for capture,scope,style in [(48,'05_FRESH48_BENIGN_DESCENDANTS','hash'),(49,'08_HISTORICAL49_BENIGN_DESCENDANTS','legacy')]:
  try:audit_capture(capture,scope,style)
  except Exception as e:
   (OUT/('capture'+str(capture)+'_error.txt')).write_text(traceback.format_exc())
   LEDGER.append({'capture':capture,'status':'BLOCKED' if isinstance(e,Blocked) else 'FAILED','reason':str(e)})
   package('capture'+str(capture)+'_stopped')
 package('FINAL')
 print('\nGROUND-TRUTH PROVENANCE LEDGER\n'+pd.DataFrame(LEDGER).to_string(index=False),flush=True)
 print('Preserve this package together with the completed experimental packages. No experimental outcome was relabelled.',flush=True)

if __name__=='__main__':main()
