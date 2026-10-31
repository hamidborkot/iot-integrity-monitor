# P3 continuation: reuse the completed Capture-7/9 runner for Captures 33/36.
# Executes the full runner in a fresh namespace; does not call leftover functions.
# Saves the original and parameterized standalone sources before any replay.
from pathlib import Path
from datetime import datetime, timezone
import ast
import builtins
import hashlib
import json
import symtable
import traceback

W=Path('/kaggle/working')
CONTROL=W/('P3_CONTINUATION_33_36_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
CONTROL.mkdir(parents=True,exist_ok=False)
NEXT_CAPTURES=[33,36]
NEXT_PLANNED=[39,43]
AFTER_NEXT=[]
REPORT={'status':'STARTED','captures_to_run':NEXT_CAPTURES,'model_fits':0,
        'validated_runner_reused':False,'experiment_started':False,
        'scientific_parameters_changed':['capture identifiers only; predeclared byte budgets already in runner'],
        'resource_change':'discard only closed temporary intake index/logs after cohort is saved',
        'output_directory':str(CONTROL)}

def save_json(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def source_digest(s):return hashlib.sha256(s.encode()).hexdigest()

def describes_working_runner(source):
    try:tree=ast.parse(source)
    except SyntaxError:return False
    assignments={}
    for node in tree.body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):
                    try:assignments[target.id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError):pass
    functions={node.name for node in ast.walk(tree) if isinstance(node,ast.FunctionDef)}
    required={'model_bank','ensure_zeek','packets','ip_packet','record_key','logs','make_checkpoint','atc'}
    return (assignments.get('CAPTURES')==[7,9] and assignments.get('LABEL_ROW_LIMIT')==4_000_000
            and assignments.get('PREFIX_MIB',{}).get(33)==128
            and assignments.get('PREFIX_MIB',{}).get(36)==512
            and required.issubset(functions)
            and 'P3_TWO_CAPTURE_BATCH_COMPLETE' in source
            and 'P3_RAW_CAPTURE7_CAPTURE9_' in source)

def find_source():
    cache=W/'P3_VALIDATED_RUNNER_SOURCE'/'capture7_capture9_original.py'
    if cache.is_file():
        text=cache.read_text(encoding='utf-8')
        if describes_working_runner(text):return text,str(cache)
    candidates=[]
    for path in [W/'p3_raw_capture7_capture9_final_v2.py',W/'p3_raw_capture7_capture9_complete.py']:
        if path.is_file():candidates.append((path.read_text(encoding='utf-8'),str(path)))
    try:
        history=get_ipython().history_manager.input_hist_raw
        candidates.extend((s,f'current notebook cell {i}') for i,s in reversed(list(enumerate(history))) if isinstance(s,str))
    except (NameError,AttributeError):pass
    for text,origin in candidates:
        if describes_working_runner(text):
            cache.parent.mkdir(exist_ok=True);cache.write_text(text,encoding='utf-8')
            return text,origin
    raise RuntimeError('The complete runner source is not in this session or its saved file. Do not rerun completed captures. Attach the Python runner used for captures 7/9; this cell has not launched a replay.')

class Parameterize(ast.NodeTransformer):
    def __init__(self):self.capture_edits=0;self.prefix_edits=0;self.next_edits=0;self.after_edits=0;self.cleanup_edits=0;self.source_snapshot_edits=0
    def visit_Assign(self,node):
        self.generic_visit(node)
        for target in node.targets:
            if isinstance(target,ast.Name) and target.id=='CAPTURES':
                if ast.literal_eval(node.value)!=[7,9]:raise RuntimeError('Unexpected original capture list')
                node.value=ast.List(elts=[ast.Constant(x) for x in NEXT_CAPTURES],ctx=ast.Load());self.capture_edits+=1
            if isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name) and target.value.id=='R' and isinstance(target.slice,ast.Constant):
                if target.slice.value=='next_planned_capture_batch':
                    node.value=ast.List(elts=[ast.Constant(x) for x in NEXT_PLANNED],ctx=ast.Load());self.next_edits+=1
                elif target.slice.value=='remaining_after_that_batch':
                    node.value=ast.List(elts=[ast.Constant(x) for x in AFTER_NEXT],ctx=ast.Load());self.after_edits+=1
        return node
    def visit_Constant(self,node):
        if isinstance(node.value,str) and node.value=='P3_RAW_CAPTURE7_CAPTURE9_':
            node.value='P3_RAW_CAPTURE33_CAPTURE36_';self.prefix_edits+=1
        return node
    def visit_Expr(self,node):
        self.generic_visit(node)
        call=node.value
        if isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute):
            if isinstance(call.func.value,ast.Name) and call.func.value.id=='OUT' and call.func.attr=='mkdir':
                self.source_snapshot_edits+=1
                snapshot=ast.parse("if '__file__' in globals() and Path(__file__).is_file():\n    shutil.copyfile(Path(__file__), OUT/'executed_runner.py')").body
                return [node]+snapshot
            if (call.func.attr=='to_csv' and isinstance(call.func.value,ast.Name) and call.func.value.id=='clean'
                and call.args and isinstance(call.args[0],ast.BinOp)
                and isinstance(call.args[0].right,ast.Constant) and call.args[0].right.value=='clean_cohort.csv.gz'):
                self.cleanup_edits+=1
                # This index and initial extraction are temporary, no longer read
                # after the verified cohort is written. Raw input is untouched.
                cleanup=ast.parse("intake_index = scratch/'clean.sqlite'\nif intake_index.is_file():\n    intake_index.unlink()\nif intake.is_dir() and intake.parent.resolve()==scratch.resolve():\n    shutil.rmtree(intake)\nC['temporary_intake_index_removed_after_cohort_saved'] = True").body
                return [node]+cleanup
        return node

try:
    if not W.is_dir():raise RuntimeError('Run inside the same Kaggle notebook that completed captures 7/9')
    prior=[]
    for path in W.glob('P3_RAW_CAPTURE7_CAPTURE9_*'):
        rp=path/'receipt.json'
        if rp.is_file():
            r=json.loads(rp.read_text())
            if r.get('status')=='P3_TWO_CAPTURE_BATCH_COMPLETE' and r.get('completed_captures')==[7,9]:prior.append(path)
    if not prior:raise RuntimeError('The reported completed Capture-7/9 batch receipt was not found')
    original,origin=find_source()
    (CONTROL/'original_validated_capture7_capture9_source.py').write_text(original,encoding='utf-8')
    patch=Parameterize();tree=patch.visit(ast.parse(original));ast.fix_missing_locations(tree)
    counts={'capture_edits':patch.capture_edits,'prefix_edits':patch.prefix_edits,'next_edits':patch.next_edits,
            'after_edits':patch.after_edits,'cleanup_edits':patch.cleanup_edits,'source_snapshot_edits':patch.source_snapshot_edits}
    if any(value!=1 for value in counts.values()):raise RuntimeError('Unexpected runner structure; no experiment started. '+json.dumps(counts))
    standalone=ast.unparse(tree)+'\n'
    standalone_path=CONTROL/'standalone_capture33_capture36_runner.py'
    compile(standalone,str(standalone_path),'exec')
    # Check global references before handing control to the full experiment.
    st=symtable.symtable(standalone,str(standalone_path),'exec')
    defined={x.get_name() for x in st.get_symbols() if x.is_assigned() or x.is_imported() or x.is_namespace()}
    allowed=defined|set(dir(builtins))|{'__name__','__file__'};missing=[]
    def check_scope(scope):
        for symbol in scope.get_symbols():
            if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in allowed:missing.append((scope.get_name(),symbol.get_name()))
        for child in scope.get_children():check_scope(child)
    check_scope(st)
    if missing:raise RuntimeError('Undefined global names found before execution: '+repr(missing))
    standalone_path.write_text(standalone,encoding='utf-8')
    REPORT.update({'status':'READY_TO_RUN','validated_runner_reused':True,'source_origin':origin,
        'original_source_sha256':source_digest(original),'standalone_source_sha256':source_digest(standalone),
        'prior_completed_batch':str(max(prior,key=lambda p:p.name)),'structural_checks':counts,
        'predeclared_prefix_MiB':{'33':128,'36':512},'label_row_budget':4_000_000,
        'models_or_thresholds_changed':False,'eligibility_changed':False})
    save_json(CONTROL/'receipt.json',REPORT)
    print('Running captures 33 and 36 with the unchanged frozen bank and declared intake policy.',flush=True)
    print('The closed temporary intake index is removed only after the cohort is saved, reducing disk use.',flush=True)
    namespace={'__name__':'__main__','__file__':str(standalone_path)}
    REPORT['experiment_started']=True
    exec(compile(standalone,str(standalone_path),'exec'),namespace)
    actual=namespace.get('R',{})
    REPORT['experiment_receipt']=actual
    REPORT['status']='CONTINUATION_COMPLETE' if actual.get('status')=='P3_TWO_CAPTURE_BATCH_COMPLETE' else 'CONTINUATION_RETURNED_WITH_EXPLICIT_GAPS'
except Exception as error:
    REPORT['status']='STOPPED_WITH_SAVED_REASON';REPORT['reason']=str(error)
    (CONTROL/'error.txt').write_text(traceback.format_exc(),encoding='utf-8')
    print('\nCONTINUATION ISSUE:',error,flush=True)
finally:
    save_json(CONTROL/'receipt.json',REPORT)
    print('\nCONTINUATION RECEIPT\n'+json.dumps(REPORT,indent=2),flush=True)
