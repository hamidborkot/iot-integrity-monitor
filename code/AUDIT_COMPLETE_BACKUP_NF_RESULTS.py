# Read-only audit of all NF-related artifacts in the specified backup.
# No installs, joblib/pickle loading, training, predictions, replay, restore or deletion.
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
import contextlib, csv, gzip, hashlib, io, json, os, re, shutil, sys, time, traceback, zipfile
import pandas as pd

ROOT=Path('/kaggle/input/datasets/mdhamidborkottulla/complete-backup')
WORK=Path('/kaggle/working')
MAX_FILES=200000
MAX_ARCHIVE_MEMBERS=250000
MAX_ARCHIVE_DEPTH=2
MAX_NESTED_ZIP_BYTES=64*1024**2
MAX_ARTIFACT_BYTES=16*1024**2
MAX_EXPANDED_BYTES=32*1024**2
MAX_TOTAL_LOGICAL_READ_BYTES=512*1024**2
MAX_CSV_ROWS=20000
MAX_JSON_LEAVES=20000
MIN_DISK_FREE_BYTES=512*1024**2
MAX_AUDIT_OUTPUT_BYTES=128*1024**2
PRINT_ROWS_PER_BLOCK=100
PRINT_SAVED_METRIC_TABLES=True

NF_RE=re.compile(r'(?i)(nfstream|nf[-_ ]?(?:ton|unsw|botiot|bot[-_]?iot|cse|cic)|(?<![a-z0-9])nf(?:$|[/_.\s-])|nf(?:step|source|boundary|completed))')
METRIC_RE=re.compile(r'(?i)(accuracy|balanced.?acc|auroc|roc.?auc|(?:^|[_\s])auc(?:$|[_\s])|recall|precision|specificity|(?:^|[_\s])f1(?:$|[_\s])|fpr|tpr|false.?positive|false.?negative|true.?positive|true.?negative|(?:^|[_\s])(?:tp|tn|fp|fn)(?:$|[_\s])|bacc|coverage|abstain|mean.?absolute.?error|(?:^|[_\s])mae(?:$|[_\s])|unit.?detection|detection.?fraction|family.?error)')
CONTEXT_RE=re.compile(r'(?i)(dataset|corpus|extractor|model|family|scenario|capture|seed|split|domain|target|threshold|alpha|rule|policy|scope|interpretation|status|claim|protocol|config|hash|sha256|rows|sample|label)')
A=[];READ_BYTES=0;ARCHIVE_MEMBERS=0;INV=[];ERRORS=[];COVERAGE=[];SCHEMAS=[];METRICS=[];RECEIPTS=[];MENTIONS=[];OPAQUE=[];STATUS=[];SAVED_TABLES=[]
OUT=None
class AuditLimit(Exception):pass


def logical(a):return str(a['path'])+''.join('::'+x for x in a['chain'])
def leaf(a):return Path(a['chain'][-1] if a['chain'] else a['path']).name

def nf_match(x):return bool(NF_RE.search(str(x)))
def category(text):
 s=str(text).lower()
 if 'nfstream' in s:return 'NFSTREAM_MENTION_PRESENT__CHECK_EXACT_ROLE'
 if re.search(r'nf[-_ ]?(ton|unsw|bot|cse|cic)',s):return 'NF_DATASET_OR_REPRESENTATION_STUDY__NOT_AUTOMATICALLY_NFSTREAM'
 if nf_match(s):return 'NF_NAMED_STUDY__EXTRACTOR_NOT_ESTABLISHED'
 return 'GENERIC_NAME_WITH_NF_CONTENT'

def sha(b):return hashlib.sha256(b).hexdigest()
def js(p,obj):Path(p).write_text(json.dumps(obj,indent=2,default=str,allow_nan=False),encoding='utf-8')
def clean_value(x):
 if isinstance(x,float) and pd.isna(x):return None
 if isinstance(x,(str,int,float,bool)) or x is None:return x
 return str(x)

def issue(a,stage,e):
 ERRORS.append({'origin':logical(a) if isinstance(a,dict) else str(a),'stage':stage,'reason':str(e)})

@contextlib.contextmanager
def open_asset(a):
 with contextlib.ExitStack() as stack:
  if not a['chain']:
   yield stack.enter_context(open(a['path'],'rb'));return
  z=stack.enter_context(zipfile.ZipFile(a['path']))
  for member in a['chain'][:-1]:
   info=z.getinfo(member)
   if info.file_size>MAX_NESTED_ZIP_BYTES:raise AuditLimit('Nested archive exceeds declared in-memory limit')
   raw=z.read(member)
   z=stack.enter_context(zipfile.ZipFile(io.BytesIO(raw)))
  yield stack.enter_context(z.open(a['chain'][-1]))

def bounded_read(a,limit=MAX_ARTIFACT_BYTES):
 global READ_BYTES
 remaining=MAX_TOTAL_LOGICAL_READ_BYTES-READ_BYTES
 if remaining<=0:raise AuditLimit('Total logical-read budget exhausted; inventory retained')
 n=min(limit,remaining)
 with open_asset(a) as f:b=f.read(n+1)
 READ_BYTES+=len(b)
 if len(b)>n:raise AuditLimit('Artifact exceeds bounded read; no complete-content conclusion made')
 return b

def payload(a):
 b=bounded_read(a)
 if b[:2]==b'\x1f\x8b':
  with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:data=f.read(MAX_EXPANDED_BYTES+1)
  if len(data)>MAX_EXPANDED_BYTES:raise AuditLimit('Expanded gzip exceeds declared limit')
 else:data=b
 return data,sha(b)


def inventory(root):
 global ARCHIVE_MEMBERS
 archives=[];count=0
 def add(path,chain,size):
  a={'path':str(path),'chain':list(chain),'bytes':int(size),'nf_path_match':nf_match(str(path)+'/'+ '/'.join(chain))}
  A.append(a);INV.append({'origin':logical(a),'bytes':size,'container_depth':len(chain),'nf_path_match':a['nf_path_match']})
  return a
 def walk_archive(path,z,chain,depth):
  global ARCHIVE_MEMBERS
  for info in z.infolist():
   if info.is_dir():continue
   if ARCHIVE_MEMBERS>=MAX_ARCHIVE_MEMBERS:
    COVERAGE.append({'scope':str(path),'stage':'archive_inventory','complete':False,'reason':'MAX_ARCHIVE_MEMBERS reached'});return
   ARCHIVE_MEMBERS+=1;a=add(path,chain+[info.filename],info.file_size)
   if info.filename.lower().endswith('.zip'):
    if depth>=MAX_ARCHIVE_DEPTH:
     COVERAGE.append({'scope':logical(a),'stage':'nested_archive','complete':False,'reason':'Declared archive-depth limit'});continue
    if info.file_size>MAX_NESTED_ZIP_BYTES:
     COVERAGE.append({'scope':logical(a),'stage':'nested_archive','complete':False,'reason':'Declared nested-archive size limit'});continue
    try:
     b=bounded_read(a,MAX_NESTED_ZIP_BYTES)
     with zipfile.ZipFile(io.BytesIO(b)) as child:walk_archive(path,child,chain+[info.filename],depth+1)
    except Exception as e:issue(a,'nested_archive_index',e)
 for base,dirs,files in os.walk(root,followlinks=False):
  dirs.sort();files.sort()
  for n in files:
   if count>=MAX_FILES:
    COVERAGE.append({'scope':str(root),'stage':'filesystem_inventory','complete':False,'reason':'MAX_FILES reached'});return
   p=Path(base)/n
   try:
    if p.is_symlink():
     COVERAGE.append({'scope':str(p),'stage':'symlink','complete':False,'reason':'Symlink not followed'});continue
    a=add(p,[],p.stat().st_size);count+=1
    if n.lower().endswith('.zip'):archives.append(p)
   except OSError as e:issue(p,'stat',e)
 COVERAGE.append({'scope':str(root),'stage':'filesystem_inventory','complete':True,'reason':'Full walk of regular files completed'})
 for p in archives:
  try:
   with zipfile.ZipFile(p) as z:walk_archive(p,z,[],1)
  except Exception as e:issue(p,'archive_index',e)


def flatten(x,prefix='',counter=None):
 if counter is None:counter=[0]
 if counter[0]>=MAX_JSON_LEAVES:return
 if isinstance(x,dict):
  for k,v in x.items():
   if counter[0]>=MAX_JSON_LEAVES:return
   yield from flatten(v,prefix+'.'+str(k) if prefix else str(k),counter)
 elif isinstance(x,list):
  for i,v in enumerate(x):
   if counter[0]>=MAX_JSON_LEAVES:return
   yield from flatten(v,prefix+'['+str(i)+']',counter)
 else:
  counter[0]+=1;yield prefix,clean_value(x)


def print_frame(title,frame):
 print('\n'+'='*100+'\n'+title+'\n'+'='*100,flush=True)
 if frame.empty:print('(none found in inspected contents)',flush=True);return
 for start in range(0,len(frame),PRINT_ROWS_PER_BLOCK):
  part=frame.iloc[start:start+PRINT_ROWS_PER_BLOCK]
  print(f'Rows {start+1}–{start+len(part)} of {len(frame)}',flush=True)
  with pd.option_context('display.max_columns',None,'display.max_colwidth',None,'display.width',None):
   print(part.to_string(index=False,max_rows=None,max_cols=None,max_colwidth=None,line_width=None),flush=True)


def inspect_json(a,data,digest,tag):
 obj=json.loads(data.decode('utf-8-sig'))
 nf=a['nf_path_match'] or nf_match(data[:2*1024**2].decode('utf-8',errors='replace'))
 if not nf:return False
 flat=list(flatten(obj));branch=category(logical(a)+' '+data[:512000].decode('utf-8',errors='replace'))
 for key,value in flat:
  if METRIC_RE.search(key):METRICS.append({'origin':logical(a),'json_key_or_table_column':key,'value':value,'branch':branch,'evidence':'REPORTED_IN_SAVED_JSON_NOT_PREDICTION_VERIFIED','sha256':digest})
  if CONTEXT_RE.search(key):RECEIPTS.append({'origin':logical(a),'key':key,'value':value,'branch':branch,'sha256':digest})
 js(OUT/'inspected_json'/(tag+'.json'),obj)
 SCHEMAS.append({'origin':logical(a),'kind':'json','branch':branch,'columns_or_keys':json.dumps(list(obj)[:200]) if isinstance(obj,dict) else type(obj).__name__,
  'rows_inspected':len(flat),'complete':len(flat)<MAX_JSON_LEAVES,'sha256':digest})
 if len(flat)>=MAX_JSON_LEAVES:COVERAGE.append({'scope':logical(a),'stage':'json_flatten','complete':False,'reason':'Leaf limit reached;full bounded JSON copied'})
 print('\nSAVED NF JSON:',logical(a),flush=True)
 # Print all metadata/metric leaves,not opaque model values.
 shown=pd.DataFrame([{'key':k,'value':v} for k,v in flat if METRIC_RE.search(k) or CONTEXT_RE.search(k)])
 print_frame('JSON METRICS / RECEIPT FIELDS',shown)
 return True


def inspect_csv(a,data,digest,tag):
 reader=pd.read_csv(io.BytesIO(data),dtype=str,keep_default_na=False,chunksize=2000,low_memory=False)
 parts=[];n=0;complete=True;columns=None
 try:
  for chunk in reader:
   if columns is None:columns=list(chunk.columns)
   if n+len(chunk)>MAX_CSV_ROWS:
    take=MAX_CSV_ROWS-n
    if take>0:parts.append(chunk.iloc[:take]);n+=take
    complete=False;break
   parts.append(chunk);n+=len(chunk)
 finally:reader.close()
 df=pd.concat(parts,ignore_index=True) if parts else pd.DataFrame(columns=columns or [])
 nf=a['nf_path_match'] or nf_match(' '.join(df.columns)) or nf_match(data[:min(len(data),1024*1024)].decode('utf-8',errors='replace'))
 if not nf:return False
 branch=category(logical(a)+' '+data[:512000].decode('utf-8',errors='replace'))
 metric_cols=[c for c in df if METRIC_RE.search(str(c))]
 context_cols=[c for c in df if CONTEXT_RE.search(str(c))]
 SCHEMAS.append({'origin':logical(a),'kind':'csv','branch':branch,'columns_or_keys':json.dumps(list(df.columns)),
   'rows_inspected':len(df),'complete':complete,'sha256':digest})
 if not complete:COVERAGE.append({'scope':logical(a),'stage':'csv_rows','complete':False,'reason':f'Only first{MAX_CSV_ROWS}rows inspected;not a full-table audit'})
 if metric_cols:
  target=OUT/'metric_tables'/(tag+'.csv');df.to_csv(target,index=False)
  SAVED_TABLES.append({'origin':logical(a),'saved_table':str(target.relative_to(OUT)),'branch':branch,'rows':len(df),'complete':complete,'metric_columns':json.dumps(metric_cols),'sha256':digest})
  for c in metric_cols:METRICS.append({'origin':logical(a),'json_key_or_table_column':c,'value':f'{len(df)}saved rows;see metric_tables/{tag}.csv',
      'branch':branch,'evidence':'REPORTED_SAVED_TABLE_NOT_PREDICTION_VERIFIED','sha256':digest})
  if PRINT_SAVED_METRIC_TABLES:print_frame('SAVED NF METRIC TABLE: '+logical(a)+'\nBRANCH: '+branch,df)
 else:
  MENTIONS.append({'origin':logical(a),'branch':branch,'kind':'NF_TABLE_WITHOUT_RECOGNIZED_METRIC_COLUMNS','sha256':digest})
  print('\nNF TABLE SCHEMA:',logical(a),'\nCOLUMNS:',list(df.columns),'\nROWS INSPECTED:',len(df),'COMPLETE:',complete,flush=True)
 return True


def inspect_text(a,data,digest,tag):
 text=data.decode('utf-8',errors='replace')
 if not(a['nf_path_match'] or nf_match(text)):return False
 matches=[]
 for i,line in enumerate(text.splitlines(),1):
  if nf_match(line) or (a['nf_path_match'] and (METRIC_RE.search(line) or CONTEXT_RE.search(line))):matches.append({'line':i,'text':line})
 target=OUT/'text_evidence'/(tag+'.json');js(target,matches)
 kind='SOURCE_CODE_NOT_EXECUTED' if leaf(a).lower().endswith('.py') else 'SAVED_TEXT_EVIDENCE_NOT_INDEPENDENT_VERIFICATION'
 MENTIONS.append({'origin':logical(a),'branch':category(logical(a)+' '+text[:512000]),'kind':kind,'matched_lines':len(matches),'saved_context':str(target.relative_to(OUT)),'sha256':digest})
 print_frame('NF TEXT / SOURCE MATCHES: '+logical(a),pd.DataFrame(matches))
 return True


def inspect_notebook(a,data,digest,tag):
 nb=json.loads(data.decode('utf-8'))
 found=[]
 for i,c in enumerate(nb.get('cells',[])):
  s=c.get('source',[]);s=s if isinstance(s,str) else ''.join(s)
  texts=[]
  for o in c.get('outputs',[]):
   value=o.get('text',[]) or o.get('data',{}).get('text/plain',[])
   texts.append(value if isinstance(value,str) else ''.join(value))
  output='\n'.join(texts)
  if nf_match(s+'\n'+output):
   found.append({'cell':i,'source':s,'printed_output':output,'interpretation':'saved output,not newly executed'})
   print('\nNF NOTEBOOK CELL:',logical(a),'CELL',i,'\n'+output,flush=True)
 if found:
  js(OUT/'text_evidence'/(tag+'_notebook_cells.json'),found)
  MENTIONS.append({'origin':logical(a),'kind':'NOTEBOOK_NF_CELLS_SOURCE_AND_OUTPUT_PRESERVED','matched_cells':len(found),'sha256':digest})
 return bool(found)



def inspect_npz(a,data,digest,tag):
 import numpy as np
 entries=[];branch=category(logical(a))
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  for info in z.infolist():
   if not info.filename.endswith('.npy'):continue
   with z.open(info.filename) as f:
    version=np.lib.format.read_magic(f)
    if version==(1,0):shape,fortran,dtype=np.lib.format.read_array_header_1_0(f,max_header_size=65536)
    elif version==(2,0):shape,fortran,dtype=np.lib.format.read_array_header_2_0(f,max_header_size=65536)
    else:
     entries.append({'array':info.filename,'header_version':str(version),'status':'unsupported_header_version_not_loaded'});continue
   item={'array':info.filename,'shape':str(shape),'dtype':str(dtype),'object_dtype':bool(dtype.hasobject),'uncompressed_bytes':info.file_size}
   # Only tiny,numeric metric scalars/vectors are read;prediction arrays and object arrays are not loaded.
   if METRIC_RE.search(info.filename) and not dtype.hasobject and dtype.kind in 'biuf' and info.file_size<=65536 and int(np.prod(shape,dtype=np.int64))<=100:
    with z.open(info.filename) as f:array=np.load(io.BytesIO(f.read(65537)),allow_pickle=False)
    item['reported_numeric_values']=json.dumps([clean_value(v.item()) for v in array.reshape(-1)])
    METRICS.append({'origin':logical(a),'json_key_or_table_column':info.filename,'value':item['reported_numeric_values'],
       'branch':branch,'evidence':'SAVED_NUMERIC_NPZ_METRIC_NOT_PREDICTION_VERIFIED','sha256':digest})
   entries.append(item)
 pd.DataFrame(entries).to_csv(OUT/'inspected_json'/(tag+'_npz_array_metadata.csv'),index=False)
 SCHEMAS.append({'origin':logical(a),'kind':'npz_safe_numeric_metadata','branch':branch,'columns_or_keys':json.dumps([e['array'] for e in entries]),
   'rows_inspected':len(entries),'complete':True,'sha256':digest})
 print_frame('NF NPZ ARRAY HEADERS / SMALL REPORTED METRICS: '+logical(a),pd.DataFrame(entries))
 return True


def inspect_all():
 inspected=0
 for a in sorted(A,key=lambda a:(not a['nf_path_match'],not bool(re.search('result|metric|summary|receipt|boundary',leaf(a),re.I)),a['bytes'],logical(a))):
  name=leaf(a).lower();path_nf=a['nf_path_match']
  if name.endswith(('.zip','.pcap','.pcapng','.joblib','.pkl','.pickle','.pt','.pth','.npy','.parquet','.pdf')):
   if path_nf:OPAQUE.append({'origin':logical(a),'bytes':a['bytes'],'reason':'inventoried only;not unpickled,executed,or loaded as raw data'})
   continue
  supported=name.endswith(('.csv','.csv.gz','.json','.json.gz','.txt','.txt.gz','.md','.py','.ipynb','.npz'))
  if not supported:continue
  # Named NF branches are inspected regardless of generic filenames. Outside those paths,probe small JSONs and likely result tables for NF identifiers.
  generic_probe=(name.endswith('.json') and a['bytes']<=512*1024) or (name.endswith(('.csv','.csv.gz','.txt','.md')) and a['bytes']<=256*1024 and re.search('result|metric|summary|receipt|manifest|boundary|validation',name))
  notebook_probe=name.endswith('.ipynb') and a['bytes']<=MAX_ARTIFACT_BYTES
  if not(path_nf or generic_probe or notebook_probe):continue
  if READ_BYTES>=MAX_TOTAL_LOGICAL_READ_BYTES:
   COVERAGE.append({'scope':'remaining content candidates','stage':'content_scan','complete':False,'reason':'Total declared logical-read budget exhausted'});break
  try:
   if a['bytes']>MAX_ARTIFACT_BYTES:raise AuditLimit('File exceeds16MiB content limit;metadata is inventoried')
   data,digest=payload(a);inspected+=1
   # Inspect duplicate bytes in each original context; never merge source/target result identities.
   tag='a'+str(inspected).zfill(5)+'_'+digest[:12]
   if name.endswith('.npz'):found=inspect_npz(a,data,digest,tag)
   elif name.endswith('.ipynb'):found=inspect_notebook(a,data,digest,tag)
   elif name.endswith(('.json','.json.gz')):found=inspect_json(a,data,digest,tag)
   elif name.endswith(('.csv','.csv.gz')):found=inspect_csv(a,data,digest,tag)
   else:found=inspect_text(a,data,digest,tag)
   if found:STATUS.append({'origin':logical(a),'status':'CONTENT_INSPECTED','sha256':digest,'bytes_read':len(data)})
   if sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file())>MAX_AUDIT_OUTPUT_BYTES:
    COVERAGE.append({'scope':'remaining contents','stage':'output_budget','complete':False,'reason':'128MiB output budget reached;no source files modified'});break
  except AuditLimit as e:
   COVERAGE.append({'scope':logical(a),'stage':'bounded_content_read','complete':False,'reason':str(e)})
  except Exception as e:issue(a,'content_inspection',e)
 return inspected


def save_outputs():
 outputs={'file_inventory':INV,'inspection_status':STATUS,'schemas':SCHEMAS,'reported_metrics':METRICS,
          'receipt_and_context_fields':RECEIPTS,'text_mentions':MENTIONS,'binary_and_large_artifacts_not_loaded':OPAQUE,
          'audit_coverage':COVERAGE,'audit_errors':ERRORS,'saved_metric_tables':SAVED_TABLES}
 for name,rows in outputs.items():pd.DataFrame(rows).to_csv(OUT/(name+'.csv'),index=False)
 incomplete=[x for x in COVERAGE if not x.get('complete',False)]
 metric_origins=sorted({x['origin'] for x in METRICS})
 nfstream_metric_tables=[x for x in SAVED_TABLES if 'nfstream' in x['origin'].lower()]
 receipt={'status':'READ_ONLY_AUDIT_WITH_EXPLICIT_LIMITS' if incomplete or ERRORS else 'READ_ONLY_AUDIT_COMPLETED',
  'root':str(ROOT),'inventory_entries':len(INV),'nf_path_candidates':sum(x['nf_path_match'] for x in INV),
  'metric_bearing_artifacts':len(metric_origins),'saved_metric_tables':len(SAVED_TABLES),
  'metric_table_paths_mentioning_nfstream':len(nfstream_metric_tables),'receipt_context_fields':len(RECEIPTS),
  'logical_content_bytes_read':READ_BYTES,'errors':len(ERRORS),'incomplete_or_bounded_scopes':len(incomplete),
  'input_files_modified':False,'models_loaded':False,'model_fits':0,'predictions_computed':0,'PCAP_replays':0,
  'meaning':'Reported saved metrics/provenance discovered;not a fresh prediction-reproduction or proof that an NF-named study used NFStream.',
  'absence_claim':'Not finding metrics within inspected contents is not proof that skipped/oversized/nested-limited files contain none.'}
 js(OUT/'audit_receipt.json',receipt)
 print_frame('1. NF-RELATED FILE SCHEMAS',pd.DataFrame(SCHEMAS))
 print_frame('2. REPORTED DETECTION / MONITORING METRIC LOCATIONS',pd.DataFrame(METRICS))
 print_frame('3. SAVED METRIC TABLES',pd.DataFrame(SAVED_TABLES))
 print_frame('4. RECEIPT AND DATASET / EXTRACTOR CONTEXT',pd.DataFrame(RECEIPTS))
 print_frame('5. SKIPPED / INCOMPLETE SCOPES',pd.DataFrame(incomplete))
 print_frame('6. AUDIT ERRORS',pd.DataFrame(ERRORS))
 print('\nFINAL AUDIT RECEIPT\n'+json.dumps(receipt,indent=2),flush=True)
 return receipt


def package():
 files=[]
 for p in sorted(OUT.rglob('*')):
  if p.is_file() and p.name not in {'NF_BACKUP_AUDIT.zip','audit_manifest.json','NF_BACKUP_AUDIT.sha256'}:
   files.append({'name':p.relative_to(OUT).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 js(OUT/'audit_manifest.json',{'files':files})
 target=OUT/'NF_BACKUP_AUDIT.zip'
 with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as z:
  for x in files:z.write(OUT/x['name'],arcname=x['name'])
  z.write(OUT/'audit_manifest.json',arcname='audit_manifest.json')
 with zipfile.ZipFile(target) as z:
  bad=z.testzip()
  if bad:raise RuntimeError('Audit ZIP integrity failure: '+bad)
 digest=hashlib.sha256(target.read_bytes()).hexdigest();(OUT/'NF_BACKUP_AUDIT.sha256').write_text(digest+'\n')
 print('\nAUDIT PACKAGE:',target,'\nSHA256:',digest,flush=True)
 try:
  from IPython.display import display,FileLink
  display(FileLink(str(target)))
 except Exception:pass

class Tee:
 def __init__(self,*handles):self.handles=handles
 def write(self,s):
  for h in self.handles:h.write(s)
  return len(s)
 def flush(self):
  for h in self.handles:h.flush()

def main():
 global OUT
 if not ROOT.is_dir():raise FileNotFoundError('Exact input mount not found: '+str(ROOT))
 WORK.mkdir(exist_ok=True,parents=True)
 if shutil.disk_usage(WORK).free<MIN_DISK_FREE_BYTES:raise RuntimeError('At least512MiB free required;no files deleted')
 OUT=WORK/('NF_COMPLETE_BACKUP_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
 OUT.mkdir(exist_ok=False)
 for name in ['metric_tables','inspected_json','text_evidence']:(OUT/name).mkdir()
 original=sys.stdout
 with open(OUT/'FULL_AUDIT_OUTPUT.txt','w',encoding='utf-8') as log:
  sys.stdout=Tee(original,log)
  try:
   print('EXACT ROOT:',ROOT,'\nOUTPUT:',OUT,'\nREAD-ONLY AUDIT;NO TRAINING,MODEL LOADING OR REPLAY.',flush=True)
   try:
    source=Path(__file__)
    if source.is_file():(OUT/'executed_audit.py').write_text(source.read_text())
   except NameError:pass
   inventory(ROOT)
   pd.DataFrame(INV).to_csv(OUT/'file_inventory.csv',index=False)
   print('Inventory entries:',len(INV),'NF path matches:',sum(x['nf_path_match'] for x in INV),flush=True)
   n=inspect_all();print('Bounded content reads:',n,flush=True)
   save_outputs()
  except BaseException as e:
   (OUT/'audit_failure.txt').write_text(traceback.format_exc())
   ERRORS.append({'origin':str(ROOT),'stage':'main','reason':str(e)})
   save_outputs()
   if isinstance(e,(KeyboardInterrupt,SystemExit)):raise
  finally:
   sys.stdout.flush();sys.stdout=original
   package()
 print('This is a backup-content audit,not a new experiment. Preserve the ZIP or Save Version with outputs.',flush=True)

if __name__=='__main__':main()
