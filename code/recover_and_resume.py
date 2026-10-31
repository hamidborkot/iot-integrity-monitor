# ONE CELL: recover the already supplied runners, preserve completed results, resume blocked tasks.
# No launcher filename or prior CODE_IDENTITY file is assumed to exist.
import ast, json, os, hashlib, shutil, runpy, zipfile
from pathlib import Path
from datetime import datetime, timezone

WORK=Path('/kaggle/working')
INPUT=Path('/kaggle/input')
RUN_ID='REVIEWER_EXPERIMENTS_20261027T191624929279Z'
RECOVERY=WORK/('RUNNER_RECOVERY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
RECOVERY.mkdir(parents=True,exist_ok=False)
DO_RUN=True

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda:f.read(4*1024**2),b''):h.update(chunk)
    return h.hexdigest()

def parsed_kind(text):
    if not isinstance(text,str) or len(text)>2_000_000:return None
    try:tree=ast.parse(text)
    except (SyntaxError,ValueError,RecursionError):return None
    funcs={n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    if {f'task{i}' for i in range(1,8)}|{'main','run_task','resolve_asset'} <= funcs:
        if 'same_cohort_bounds.csv' in text and 'M4_windows_REPRODUCTION.csv' in text:
            return 'experiments'
    if {'get_parent','get_zeek','canonical_parts','resolve_exact_asset','main'} <= funcs:
        if 'REVIEWER_BLOCKED_CONTINUATION_' in text:return 'continuation'
    return None

sources={'experiments':[],'continuation':[]}
def register(text,where,rank):
    kind=parsed_kind(text)
    if kind:sources[kind].append((rank,where,text));return
    # Some notebook cells contain the complete supplied program as a string literal.
    if not isinstance(text,str) or len(text)>2_000_000:return
    if 'def task1' not in text and 'def get_zeek' not in text:return
    try:tree=ast.parse(text)
    except Exception:return
    for node in ast.walk(tree):
        if isinstance(node,ast.Constant) and isinstance(node.value,str):
            kind=parsed_kind(node.value)
            if kind:sources[kind].append((rank,where+' [embedded program]',node.value))

def notebook_sources(p,rank):
    try:
        nb=json.loads(p.read_text(encoding='utf-8'))
        for i,c in enumerate(nb.get('cells',[])):
            src=c.get('source','');src=''.join(src) if isinstance(src,list) else src
            register(src,str(p)+f' cell {i}',rank+i)
    except Exception:pass

# First use real current-session input history. This is precisely where pasted code is retained.
try:
    history=list(get_ipython().history_manager.input_hist_raw)
except (NameError,AttributeError):history=[]
for i,text in enumerate(history):register(text,f'current IPython input {i}',1_000_000+i)

# Then inspect mounted/saved Python source and notebook source, without executing candidates.
# Use the previous audit inventory when available; also inspect the current working tree.
files=set()
indexes=sorted(WORK.glob('AUDIT_INVENTORY_*/file_index.csv'))
if indexes:
    import csv
    with open(indexes[-1],newline='') as f:
        for row in csv.DictReader(f):
            p=Path('/kaggle/input/datasets/mdhamidborkottulla')/row['backup']/row['relative_path']
            if p.suffix.lower() in ('.py','.ipynb') and p.is_file():files.add(p)
for root in [WORK,INPUT]:
    if not root.is_dir():continue
    for cur,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if (Path(cur)/d)!=RECOVERY and d not in ('.git','__pycache__')]
        for name in names:
            p=Path(cur)/name
            if p.suffix.lower() in ('.py','.ipynb'):files.add(p)
for p in sorted(files,key=str):
    try:
        if p.stat().st_size>25_000_000:continue
        if p.suffix.lower()=='.ipynb':notebook_sources(p,100)
        else:register(p.read_text(encoding='utf-8'),str(p),500)
    except Exception:pass

# Find exact old result directory. Do NOT rerun successful tasks to reconstruct it.
parents=[]
for root in [WORK,INPUT]:
    if not root.is_dir():continue
    for cur,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if (Path(cur)/d)!=RECOVERY and d not in ('.git','__pycache__')]
        if 'TASK_LEDGER.json' in names and RUN_ID in Path(cur).parts:
            parents.append(Path(cur))
if not parents:
    # Provider may have retained the small run package as ZIP rather than unpacked files.
    archives=[]
    for root in [WORK,INPUT]:
        if root.is_dir():archives.extend(root.rglob('PRIVATE_REVIEWER_EXPERIMENTS.zip'))
    for arc in sorted(archives,key=lambda p:(len(str(p)),str(p))):
        try:
            with zipfile.ZipFile(arc) as z:
                if 'TASK_LEDGER.json' not in z.namelist():continue
                old=json.loads(z.read('TASK_LEDGER.json'))
                numbers={int(r['task']):r for r in old}
                if not all(k in numbers for k in [3,4,6]):continue
                dest=RECOVERY/'package_results'/RUN_ID;dest.mkdir(parents=True,exist_ok=True)
                for m in z.infolist():
                    if m.is_dir() or m.filename.endswith(('.npy','.pcap')) or 'scratch' in Path(m.filename).parts:continue
                    if Path(m.filename).is_absolute() or '..' in Path(m.filename).parts:raise ValueError('Unsafe ZIP member')
                    if m.file_size>128*1024**2:continue
                    q=dest/m.filename;q.parent.mkdir(parents=True,exist_ok=True)
                    with z.open(m) as f,open(q,'wb') as g:shutil.copyfileobj(f,g)
                parents.append(dest)
                for q in dest.rglob('*.py'):
                    register(q.read_text(errors='replace'),str(q),600)
                break
        except Exception as e:print('Package recovery error:',arc,e,flush=True)

print('Recovered source candidates:',{k:len(v) for k,v in sources.items()},flush=True)
print('Previous result directories:',[str(p) for p in parents],flush=True)
if not parents:
    raise RuntimeError(
        'No previous task ledger/results are visible, even inside the saved experiment ZIP. '
        'The completed-result data must be attached; code cannot recreate absent data without repeating experiments.'
    )
parent=min(parents,key=lambda p:(len(str(p)),str(p)))

# Pick the most recent supplied definition in current session; record its recovery provenance.
# This is a NOW-observed source identity, not a fabricated pre-execution code binding.
choices={}
for kind in ['experiments','continuation']:
    if not sources[kind]:
        raise RuntimeError(
            f'The {kind} program is absent from session history and mounted notebooks/scripts. '
            'No source will be guessed or reconstructed from numerical outputs. '
            'Keep this runtime open; the existing results are untouched.'
        )
    rank,where,text=max(sources[kind],key=lambda x:(x[0],x[1]))
    choices[kind]={'where':where,'sha256':hashlib.sha256(text.encode()).hexdigest(),'text':text}
    print('SOURCE:',kind,'from',where,'SHA256',choices[kind]['sha256'],flush=True)

# Make a recovery COPY, never write a source binding into the accepted result folder.
bound=RECOVERY/'bound_results'/RUN_ID;bound.mkdir(parents=True)
for name in ['TASK_LEDGER.json','PREEXECUTION_PROTOCOL.json','START_ENVIRONMENT.json']:
    q=parent/name
    if q.is_file():shutil.copyfile(q,bound/name)
for number in [3,4,6]:
    src=parent/f'{number:02d}'
    if not src.is_dir():raise RuntimeError('Preserved completed task directory absent: '+str(src))
    for q in src.rglob('*'):
        if not q.is_file() or q.suffix in ('.npy','.pcap') or 'scratch' in q.relative_to(src).parts:continue
        target=bound/f'{number:02d}'/q.relative_to(src)
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(q,target)
source=bound/'executed_runner.py';source.write_text(choices['experiments']['text'],encoding='utf-8')
identity={'sha256':sha(source),'binding_created_now':True,
          'source_recovered_from':choices['experiments']['where'],
          'scope':'recovered supplied code for continuation; NOT proof of originally executed code identity or prior scoring chronology'}
(bound/'CODE_IDENTITY.json').write_text(json.dumps(identity,indent=2))
continuation=RECOVERY/'recovered_continuation.py'
continuation.write_text(choices['continuation']['text'],encoding='utf-8')
(RECOVERY/'RECOVERY_PROVENANCE.json').write_text(json.dumps({
    'original_results':str(parent),'recovery_results_copy':str(bound),
    'experiments_source':{k:v for k,v in choices['experiments'].items() if k!='text'},
    'continuation_source':{k:v for k,v in choices['continuation'].items() if k!='text'},
    'previous_results_modified':False,'completed_tasks_to_preserve':[3,4,6],
    'recovered_binding_is_not_original_preexecution_identity':True},indent=2))

# Execute the recovered continuation's definitions, but replace its parent lookup with this
# explicit recovered copy. Leave its task logic, pinned dependencies and resolver repair intact.
tree=ast.parse(choices['continuation']['text'])
# The supplied continuation ends with try:main() ... finally:package. Remove that call wrapper
# while loading its definitions, then run its existing main() ourselves.
kept=[]
for node in tree.body:
    if isinstance(node,ast.Try):
        calls=[x for x in ast.walk(node) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=='main']
        if calls:continue
    kept.append(node)
ns={'__name__':'recovered_continuation_definitions','__file__':str(continuation)}
exec(compile(ast.Module(body=kept,type_ignores=[]),str(continuation),'exec'),ns)
ns['get_parent']=lambda:bound
print('\nRECOVERY COMPLETE. Tasks 3,4,6 will NOT rerun. Resuming 1,2,5,7.\n',flush=True)
if DO_RUN:
    try:ns['main']()
    except Exception as e:
        import traceback
        (ns['OUT']/'continuation_failure.txt').write_text(traceback.format_exc())
        print('CONTINUATION FAILURE:',type(e).__name__,e,flush=True)
    finally:
        out=ns['OUT'];package=out/'PRIVATE_CONTINUATION_RECOVERED.zip'
        with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
            for q in out.rglob('*'):
                if q.is_file() and q!=package and q.suffix not in ('.pcap','.npy') and 'scratch' not in q.relative_to(out).parts:
                    z.write(q,str(q.relative_to(out)))
            z.write(RECOVERY/'RECOVERY_PROVENANCE.json','RECOVERY_PROVENANCE.json')
        with zipfile.ZipFile(package) as z:
            bad=z.testzip()
            if bad:raise RuntimeError('Package CRC failed: '+bad)
        print('\nRESULT PACKAGE:',package,'\nSHA256:',sha(package),flush=True)
