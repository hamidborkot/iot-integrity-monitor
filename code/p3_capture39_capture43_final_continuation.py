# Final declared P3 capture batch: 39 and 43, reusing the validated 33/36 source.
# Keeps models, thresholds, budgets, cohort sampling and action eligibility unchanged.
# Adds only an exact necessary primary-label-count check before expensive extraction.
from pathlib import Path
from datetime import datetime, timezone
import ast
import builtins
import hashlib
import json
import symtable
import traceback

W=Path('/kaggle/working')
OUT=W/('P3_CONTINUATION_39_43_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
EXPECTED_SOURCE_SHA='02f047f0a2dd2ffcd89b390d8a0efed40a491d445c210a76de0e1d7f39794d0f'
REPORT={'status':'STARTED','captures_to_run':[39,43],'experiment_started':False,'model_fits':0,
        'models_thresholds_and_sampling_rules_changed':False,'output_directory':str(OUT)}

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def digest(text):return hashlib.sha256(text.encode()).hexdigest()

def get_source():
    matches=[]
    for d in W.glob('P3_RAW_CAPTURE33_CAPTURE36_*'):
        rp=d/'receipt.json';sp=d/'executed_runner.py'
        if rp.is_file() and sp.is_file():
            r=json.loads(rp.read_text())
            if r.get('status')=='P3_TWO_CAPTURE_BATCH_COMPLETE' and r.get('completed_captures')==[33,36]:matches.append((sp,r))
    for d in W.glob('P3_CONTINUATION_33_36_*'):
        rp=d/'receipt.json';sp=d/'standalone_capture33_capture36_runner.py'
        if rp.is_file() and sp.is_file():
            r=json.loads(rp.read_text())
            if r.get('status')=='CONTINUATION_COMPLETE':matches.append((sp,r))
    for sp,r in sorted(matches,key=lambda x:str(x[0]),reverse=True):
        text=sp.read_text(encoding='utf-8')
        if digest(text)==EXPECTED_SOURCE_SHA:return sp,text
    raise RuntimeError('The exact validated Capture-33/36 source was not found. No replay started. Preserve or attach its executed_runner.py or standalone source.')

FLOOR_HELPER=r"""
def metadata_class_floor(scenario):
    paths=[p for p in RAW.rglob('conn.log.labeled') if scenario in p.parts]
    if len(paths)!=1:
        return {'passed':False,'safe_to_skip_for_class_shortage':False,'reason':'Original unique labelled log not found','matching_logs':len(paths)}
    counts={'benign':0,'malicious':0};scanned=0;exhausted=True
    for row in logs(paths[0],True):
        scanned+=1
        if scanned>LABEL_ROW_LIMIT:exhausted=False;break
        label=row['label'].lower()
        if label in counts:counts[label]+=1
        if counts['benign']>=N and counts['malicious']>=N:
            return {'passed':True,'safe_to_skip_for_class_shortage':False,'primary_label_counts_at_early_stop':counts,
                    'published_rows_scanned':scanned,'reason':'Necessary floor reached; prefix linkage and supported-protocol checks still required'}
    return {'passed':False,'safe_to_skip_for_class_shortage':True,'primary_label_counts_in_declared_scan':counts,
            'published_rows_scanned':min(scanned,LABEL_ROW_LIMIT),'full_log_exhausted':exhausted,
            'reason':'A primary class has fewer than N records in the permitted published-row scan; stable-linked subset cannot contain N of that class'}
"""
FLOOR_CHECK=r"""
metadata_floor = metadata_class_floor(scenario)
js(folder/'metadata_primary_class_floor.json', metadata_floor)
print('PRIMARY-LABEL PREFLIGHT:', scenario, metadata_floor, flush=True)
C['metadata_class_floor_checked'] = True
if not metadata_floor['passed'] and metadata_floor['safe_to_skip_for_class_shortage']:
    C['status'] = 'INSUFFICIENT_UNDER_DECLARED_INTAKE_POLICY'
    C['reason'] = metadata_floor['reason']
    C['raw_PCAP_replays_avoided_by_necessary_class_floor'] = True
    case_ledger.append(C)
    continue
"""

class Patch(ast.NodeTransformer):
    def __init__(self):self.capture_edits=0;self.prefix_edits=0;self.next_edits=0;self.after_edits=0;self.floor_edits=0
    def visit_Assign(self,node):
        self.generic_visit(node)
        for target in node.targets:
            if isinstance(target,ast.Name) and target.id=='CAPTURES':
                if ast.literal_eval(node.value)!=[33,36]:raise RuntimeError('Unexpected validated source capture list')
                node.value=ast.List(elts=[ast.Constant(39),ast.Constant(43)],ctx=ast.Load());self.capture_edits+=1
            if isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name) and target.value.id=='R' and isinstance(target.slice,ast.Constant):
                if target.slice.value=='next_planned_capture_batch':node.value=ast.List(elts=[],ctx=ast.Load());self.next_edits+=1
                elif target.slice.value=='remaining_after_that_batch':node.value=ast.List(elts=[],ctx=ast.Load());self.after_edits+=1
        return node
    def visit_Constant(self,node):
        if isinstance(node.value,str) and node.value=='P3_RAW_CAPTURE33_CAPTURE36_':node.value='P3_RAW_CAPTURE39_CAPTURE43_';self.prefix_edits+=1
        return node
    def visit_For(self,node):
        self.generic_visit(node)
        if isinstance(node.target,ast.Name) and node.target.id=='capture' and isinstance(node.iter,ast.Name) and node.iter.id=='CAPTURES':
            tries=[n for n in node.body if isinstance(n,ast.Try)]
            if len(tries)!=1:raise RuntimeError('Expected one capture-level guarded experiment')
            tries[0].body=ast.parse(FLOOR_CHECK).body+tries[0].body;self.floor_edits+=1
        return node

try:
    sp,source=get_source();(OUT/'validated_capture33_capture36_source.py').write_text(source,encoding='utf-8')
    patch=Patch();tree=patch.visit(ast.parse(source))
    # Helpers are defined before the runner's top-level experiment starts.
    helper=ast.parse(FLOOR_HELPER).body[0]
    insertion=next((i for i,n in enumerate(tree.body) if isinstance(n,ast.Try)),None)
    if insertion is None:raise RuntimeError('Experiment entry block not found')
    tree.body.insert(insertion,helper);ast.fix_missing_locations(tree)
    counts={n:getattr(patch,n) for n in ['capture_edits','prefix_edits','next_edits','after_edits','floor_edits']}
    if any(v!=1 for v in counts.values()):raise RuntimeError('Unexpected source structure; no experiment started. '+json.dumps(counts))
    text=ast.unparse(tree)+'\n';compiled=compile(text,'capture39_capture43_runner','exec')
    st=symtable.symtable(text,'capture39_capture43_runner','exec')
    defined={s.get_name() for s in st.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    allowed=defined|set(dir(builtins))|{'__name__','__file__'};missing=[]
    def check(scope):
        for symbol in scope.get_symbols():
            if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in allowed:missing.append((scope.get_name(),symbol.get_name()))
        for child in scope.get_children():check(child)
    check(st)
    if missing:raise RuntimeError('Undefined globals found before execution: '+repr(missing))
    runner=OUT/'standalone_capture39_capture43_runner.py';runner.write_text(text,encoding='utf-8')
    REPORT.update({'status':'READY_TO_RUN','validated_source':str(sp),'validated_source_sha256':digest(source),
                   'standalone_source_sha256':digest(text),'structural_checks':counts,
                   'prefix_budgets_MiB':{'39':512,'43':128},'published_row_limit':4_000_000,
                   'new_precheck':'Necessary primary-class floor only; does not relax or replace original stable linkage/cohort rules'})
    js(OUT/'receipt.json',REPORT)
    print('Running final declared capture batch: 39 and 43.',flush=True)
    print('The preflight can skip an impossible class-count intake before costly PCAP processing; such a case remains an explicit budget-limited gap.',flush=True)
    namespace={'__name__':'__main__','__file__':str(runner)};REPORT['experiment_started']=True
    exec(compiled,namespace)
    actual=namespace.get('R',{});ledger=namespace.get('case_ledger',[])
    REPORT['experiment_receipt']=actual;REPORT['capture_execution_ledger']=ledger
    REPORT['both_capture_ids_accounted_for']=set(c.get('capture') for c in ledger)=={39,43}
    REPORT['both_packet_cohorts_evaluated']=set(actual.get('completed_captures',[]))=={39,43}
    REPORT['status']='FINAL_CAPTURE_BATCH_RETURNED_WITH_EXPLICIT_OUTCOMES' if REPORT['both_capture_ids_accounted_for'] else 'FINAL_CAPTURE_BATCH_INCOMPLETE'
except Exception as error:
    REPORT['status']='STOPPED_WITH_SAVED_REASON';REPORT['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc(),encoding='utf-8');print('\nCONTINUATION ISSUE:',error,flush=True)
finally:
    js(OUT/'receipt.json',REPORT);print('\nCONTINUATION RECEIPT\n'+json.dumps(REPORT,indent=2),flush=True)
