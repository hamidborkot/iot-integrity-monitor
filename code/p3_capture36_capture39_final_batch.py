# Final declared raw-PCAP batch: captures 36 and 39.
# Reuses the completed 33/36 runner, exact five-seed source bank,
# frozen settings, byte budgets, label-row limit and eligibility rules.
# Only capture IDs/output labels change. No model training occurs.
from pathlib import Path
from datetime import datetime, timezone
import ast, builtins, hashlib, json, symtable, traceback

W=Path('/kaggle/working')
B5=Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')
CAPTURES=[36,39]
OUT=W/('P3_CONTINUATION_36_39_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
REPORT={'status':'STARTED','captures_to_run':CAPTURES,'model_fits':0,'source_runner_reused':False,
        'scientific_settings_changed':False,'output_directory':str(OUT)}

def digest(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()
def save_json(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def receipt_of(path):
    try:return json.loads(path.read_text())
    except (OSError,ValueError):return None

def locate_validated_runner():
    candidates=[]
    # Prefer the original successful run in the active working directory.
    for root in W.glob('P3_RAW_CAPTURE33_CAPTURE36_*'):
        rp=root/'receipt.json';r=receipt_of(rp) if rp.is_file() else None
        code=root/'executed_runner.py'
        if not code.is_file():code=root/'standalone_capture33_capture36_runner.py'
        if r and r.get('status')=='P3_TWO_CAPTURE_BATCH_COMPLETE' and set(r.get('completed_captures',[]))=={33,36} and code.is_file():
            candidates.append((code.read_text(encoding='utf-8'),str(code),r))
    # Batch5 may contain a nested checkpoint ZIP with the same verified run.
    if B5.is_dir() and not candidates:
        for current,dirs,files in __import__('os').walk(B5,followlinks=False):
            dirs[:]=[d for d in dirs if d not in {'.git','__pycache__'}]
            for name in files:
                if not name.lower().endswith('.zip'):continue
                zpath=Path(current)/name
                try:
                    with __import__('zipfile').ZipFile(zpath) as z:
                        names=set(z.namelist())
                        code_names=[n for n in names if n.endswith('/executed_runner.py') or n.endswith('/standalone_capture33_capture36_runner.py')]
                        receipt_names=[n for n in names if n.endswith('/receipt.json')]
                        for rn in receipt_names:
                            r=json.loads(z.read(rn))
                            if r.get('status')!='P3_TWO_CAPTURE_BATCH_COMPLETE' or set(r.get('completed_captures',[]))!={33,36}:continue
                            parent=rn.rsplit('/',1)[0]
                            for cn in code_names:
                                if cn.rsplit('/',1)[0]==parent:
                                    candidates.append((z.read(cn).decode('utf-8'),f'{zpath}::{cn}',r))
                except (OSError,ValueError,__import__('zipfile').BadZipFile):continue
    for source,origin,r in candidates:
        try:tree=ast.parse(source)
        except SyntaxError:continue
        # Require the actual complete raw-PCAP runner, not a wrapper.
        names={n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        if {'main','packets','run_zeek','metadata_class_floor'}.issubset(names) and 'P3_TWO_CAPTURE_BATCH_COMPLETE' in source:
            return source,origin,r
    raise RuntimeError('Validated 33/36 source runner was not found in working outputs or batch5; no replacement runner was guessed.')

class Retarget(ast.NodeTransformer):
    def __init__(self):self.capture=0;self.output_label=0;self.next_list=0;self.remaining_list=0
    def visit_Assign(self,node):
        self.generic_visit(node)
        for t in node.targets:
            if isinstance(t,ast.Name) and t.id=='CAPTURES':
                if ast.literal_eval(node.value)!=[33,36]:raise RuntimeError('Runner capture roster differs from validated 33/36 run')
                node.value=ast.List(elts=[ast.Constant(x) for x in CAPTURES],ctx=ast.Load());self.capture+=1
            if isinstance(t,ast.Subscript) and isinstance(t.value,ast.Name) and t.value.id=='R' and isinstance(t.slice,ast.Constant):
                if t.slice.value=='next_planned_capture_batch':node.value=ast.List(elts=[],ctx=ast.Load());self.next_list+=1
                elif t.slice.value=='remaining_after_that_batch':node.value=ast.List(elts=[],ctx=ast.Load());self.remaining_list+=1
        return node
    def visit_Constant(self,node):
        if isinstance(node.value,str) and node.value=='P3_RAW_CAPTURE33_CAPTURE36_':
            node.value='P3_RAW_CAPTURE36_CAPTURE39_';self.output_label+=1
        return node

try:
    source,origin,old_receipt=locate_validated_runner()
    (OUT/'validated_capture33_capture36_runner.py').write_text(source,encoding='utf-8')
    tree=ast.parse(source);patch=Retarget();tree=patch.visit(tree);ast.fix_missing_locations(tree)
    counts={'capture_roster':patch.capture,'output_label':patch.output_label,'next_capture_list':patch.next_list,'remaining_capture_list':patch.remaining_list}
    if any(v!=1 for v in counts.values()):raise RuntimeError('Unexpected runner structure; no experiment started: '+json.dumps(counts))
    # Freeze a machine-readable amendment before opening targets.
    amendment={'parent_runner_sha256':digest(source),'parent_receipt':old_receipt,
        'new_capture_roster':CAPTURES,'changes_only':['capture identifiers','output directory label','empty next/remaining capture lists'],
        'unchanged':['source model bank','model seeds','features','byte-prefix budgets','published-label scan limit',
                     'cohort size','pacing delays','packet eligibility','monitor definitions','statistical unit'],
        'model_training':False,'target_outcome_based_selection':False,'independent_confirmation_claim':False}
    save_json(OUT/'protocol_amendment.json',amendment)
    standalone=ast.unparse(tree)+'\n';path=OUT/'standalone_capture36_capture39_runner.py'
    compile(standalone,str(path),'exec');path.write_text(standalone,encoding='utf-8')
    st=symtable.symtable(standalone,str(path),'exec');defined={s.get_name() for s in st.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    allowed=defined|set(dir(builtins))|{'__name__','__file__'};missing=[]
    def check(scope):
        for sym in scope.get_symbols():
            if sym.is_referenced() and sym.is_global() and sym.get_name() not in allowed:missing.append((scope.get_name(),sym.get_name()))
        for child in scope.get_children():check(child)
    check(st)
    if missing:raise RuntimeError('Undefined names detected before execution: '+repr(missing))
    REPORT.update({'status':'RUNNING_FINAL_DECLARED_P3_BATCH','source_runner_origin':origin,
                   'source_runner_sha256':digest(source),'standalone_runner_sha256':digest(standalone),
                   'structural_change_counts':counts,'models_retrained':False,
                   'byte_prefix_MiB':{'36':512,'39':512},'published_label_row_limit':4000000,
                   'undefined_global_names':missing})
    save_json(OUT/'continuation_receipt.json',REPORT)
    print('Running only the remaining declared captures 36 and 39.',flush=True)
    print('No model fitting or outcome-driven selection. Each case retains its fixed intake/eligibility rule.',flush=True)
    ns={'__name__':'__main__','__file__':str(path)}
    exec(compile(tree,str(path),'exec'),ns)
    r=ns.get('R',{});ledger=ns.get('case_ledger',[])
    REPORT['experiment_receipt']=r;REPORT['capture_ledger']=ledger
    REPORT['both_capture_ids_accounted_for']=set(x.get('capture') for x in ledger)==set(CAPTURES)
    REPORT['packet_cohorts_completed']=set(r.get('completed_captures',[]))==set(CAPTURES)
    REPORT['status']='FINAL_P3_BATCH_COMPLETE_WITH_EXPLICIT_CASE_OUTCOMES' if REPORT['both_capture_ids_accounted_for'] else 'FINAL_P3_BATCH_INCOMPLETE'
except Exception as error:
    REPORT['status']='STOPPED_WITH_EXACT_REASON';REPORT['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc(),encoding='utf-8');print('\nCONTINUATION ISSUE:',error,flush=True)
finally:
    save_json(OUT/'continuation_receipt.json',REPORT)
    print('\nFINAL P3 CONTINUATION RECEIPT\n'+json.dumps(REPORT,indent=2),flush=True)
