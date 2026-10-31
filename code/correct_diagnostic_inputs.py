# Targeted correction for the diagnostic that just stopped.
# No model fitting, new extraction settings, or target-panel changes.
from pathlib import Path
from datetime import datetime,timezone
import ast,gzip,hashlib,io,json,traceback,zipfile

W=Path('/kaggle/working')
CONTROL=W/('DIAGNOSTIC_INPUT_FIX_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
CONTROL.mkdir(parents=True,exist_ok=False)
FAILED=W/'MECHANISM_DIAGNOSIS_20261018T020902321820Z'
REPORT={'status':'STARTED','model_fits':0,'scientific_settings_changed':False,
        'target_panels_changed':False,'control_directory':str(CONTROL)}

def digest(s):return hashlib.sha256(s.encode('utf-8')).hexdigest()
def save_report():
    (CONTROL/'repair_receipt.json').write_text(json.dumps(REPORT,indent=2,default=str),encoding='utf-8')

def usable(text):
    try:t=ast.parse(text)
    except SyntaxError:return False
    names={n.name for n in t.body if isinstance(n,ast.FunctionDef)}
    return {'audit_inputs','restore','target_capture','explain_units','verify_parent_outcomes','summarize_explanations'}.issubset(names) and 'RAW_ONLY_REMEASUREMENT_20261017T130813279947Z' in text

def find_source():
    paths=[FAILED/'executed_diagnostic.py']
    paths+=sorted(W.glob('mechanism_diagnostic_source_*.py'),reverse=True)
    paths+=sorted(W.glob('MECHANISM_DIAGNOSIS_*/executed_diagnostic.py'),reverse=True)
    for p in paths:
        if not p.is_file():continue
        text=p.read_text(encoding='utf-8')
        if usable(text):return text,str(p)
    archive=FAILED/'PRIVATE_raw_only_checkpoint.zip'
    if archive.is_file():
        with zipfile.ZipFile(archive) as z:
            for name in z.namelist():
                if Path(name).name=='executed_diagnostic.py':
                    text=z.read(name).decode('utf-8')
                    if usable(text):return text,str(archive)+'!/'+name
    raise RuntimeError('The just-executed diagnostic source is no longer in this session. No replacement experiment was launched. Use this repair in the same session as the reported failure.')

RESTORE_SOURCE = "\ndef restore(relative):\n    local = OUT / 'verified_inputs' / relative\n    if local.is_file():\n        return local\n    aliases = [relative]\n    if relative.endswith('.csv.gz'):\n        aliases.append(relative[:-3])\n    elif relative.endswith('.csv'):\n        aliases.append(relative + '.gz')\n    hits = [a for a in index_backup()\n            if any(a['logical'].replace('\\\\', '/').endswith('/' + v) for v in aliases)\n            and a['bytes'] <= 64 * 1024**2]\n    if not hits:\n        raise Stop('Required diagnostic input not found (compressed and unpacked names checked): ' + relative)\n    csv_input = relative.endswith(('.csv', '.csv.gz'))\n    variants = {}\n    for a in hits:\n        raw = read_asset(a)\n        source_hash = hashlib.sha256(raw).hexdigest()\n        if csv_input:\n            data = raw\n            if data[:2] == b'\\x1f\\x8b':\n                with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:\n                    data = f.read(64 * 1024**2 + 1)\n                if len(data) > 64 * 1024**2:\n                    raise Stop('Expanded diagnostic CSV exceeds bound: ' + relative)\n            table = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)\n            canonical = table.to_csv(index=False, lineterminator='\\n').encode('utf-8')\n            digest = hashlib.sha256(canonical).hexdigest()\n            payload = canonical\n        else:\n            digest = source_hash\n            payload = raw\n        variants.setdefault(digest, []).append((a, payload, source_hash))\n    if len(variants) != 1:\n        raise Stop('Different contents found for ' + relative + '; no input selected using results')\n    digest, copies = next(iter(variants.items()))\n    a, payload, source_hash = min(copies, key=lambda v: (len(v[0]['chain']), len(v[0]['path']), v[0]['path']))\n    local.parent.mkdir(parents=True, exist_ok=True)\n    if csv_input and relative.endswith('.gz'):\n        with local.open('wb') as f:\n            with gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0) as g:\n                g.write(payload)\n    else:\n        local.write_bytes(payload)\n    ASSET_LOG.append({'relative': relative, 'origin': a,\n        'original_bytes_sha256': source_hash,\n        'comparison_sha256': digest,\n        'comparison_kind': 'ordered CSV text canonicalization' if csv_input else 'exact bytes',\n        'local_sha256': sha(local), 'restored_bytes': local.stat().st_size})\n    js(OUT / 'input_binding.json', ASSET_LOG)\n    return local\n"

class CorrectInputs(ast.NodeTransformer):
    def __init__(self):
        self.restore_replacements=0
        self.required_panel_removals=0
        self.source_check_removals=0
        self.scope_records=0
    def visit_FunctionDef(self,node):
        if node.name=='restore':
            self.restore_replacements+=1
            return ast.parse(RESTORE_SOURCE).body[0]
        if node.name!='audit_inputs':return node
        updated=[]
        for item in node.body:
            if isinstance(item,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='required' for t in item.targets):
                if not isinstance(item.value,ast.List):raise RuntimeError('Unexpected required-input declaration')
                kept=[]
                for value in item.value.elts:
                    if isinstance(value,ast.Constant) and value.value=='fresh_source_panel.csv.gz':
                        self.required_panel_removals+=1
                    else:kept.append(value)
                item.value.elts=kept
            if isinstance(item,ast.If):
                calls=[n for n in ast.walk(item.test) if isinstance(n,ast.Call)]
                source_call=any(isinstance(n.func,ast.Name) and n.func.id=='restore' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='fresh_source_panel.csv.gz' for n in calls)
                hash_call=any(isinstance(n.func,ast.Name) and n.func.id=='sha' for n in calls)
                if source_call and hash_call:
                    self.source_check_removals+=1
                    continue
            updated.append(item)
        if not updated or not isinstance(updated[-1],ast.Return):raise RuntimeError('Unexpected audit return structure')
        scope=ast.parse("""
R['source_training_panel_required_for_diagnostic'] = False
R['source_training_panel_hash_verified_in_this_diagnostic'] = False
js(OUT/'diagnostic_input_scope.json', {
    'no_model_training_or_recalibration': True,
    'source_training_rows_required': False,
    'source_training_panel_hash_verified_now': False,
    'saved_model_byte_hashes_still_required': True,
    'source_reference_rates': 'reused unchanged from the saved model_binding.json',
    'raw_prefix_panel_and_parent_outcome_checks': 'unchanged'
})
""").body
        node.body=updated[:-1]+scope+[updated[-1]]
        self.scope_records+=1
        return node

try:
    source,origin=find_source()
    (CONTROL/'original_diagnostic.py').write_text(source,encoding='utf-8')
    patch=CorrectInputs();tree=patch.visit(ast.parse(source));ast.fix_missing_locations(tree)
    counts={k:getattr(patch,k) for k in ['restore_replacements','required_panel_removals','source_check_removals','scope_records']}
    if any(v!=1 for v in counts.values()):raise RuntimeError('Unexpected source structure; experiment not started: '+json.dumps(counts))
    text=ast.unparse(tree)+'\n';path=CONTROL/'corrected_full_diagnostic.py'
    compile(text,str(path),'exec');path.write_text(text,encoding='utf-8')
    # Ensure scientific functions have not been changed by this input-only repair.
    before={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
    after={n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,ast.FunctionDef)}
    preserved=['replay','target_capture','bounds','explain_units','verify_prefix','verify_panel','verify_parent_outcomes','summarize_explanations','main']
    if not all(n in before and n in after and before[n]==after[n] for n in preserved):raise RuntimeError('Unexpected scientific-code change; no execution')
    REPORT.update({'status':'INPUT_REPAIR_VALIDATED','original_source':origin,'original_source_sha256':digest(source),
                   'corrected_source_sha256':digest(text),'edits':counts,'scientific_functions_preserved':preserved,
                   'source_panel_verification_claimed':False,'complete_corrected_script':str(path)})
    save_report()
    entry = ("from pathlib import Path\nfrom datetime import datetime,timezone\nimport runpy\nSOURCE=" + repr(text)
             + "\np=Path('/kaggle/working')/('corrected_diagnostic_source_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.py')\np.write_text(SOURCE,encoding='utf-8')\nrunpy.run_path(str(p),run_name='__main__')\n")
    notebook = {'nbformat':4,'nbformat_minor':5,
        'metadata':{'kernelspec':{'name':'python3','display_name':'Python 3','language':'python'}},
        'cells':[{'cell_type':'code','metadata':{},'execution_count':None,'outputs':[],
                  'source':entry.splitlines(keepends=True)}]}
    complete_notebook=CONTROL/'corrected_full_diagnostic.ipynb'
    complete_notebook.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    try:
        from IPython.display import display,FileLink
        print('Complete corrected program saved BEFORE execution. Preserve these files:',flush=True)
        display(FileLink(str(path)))
        display(FileLink(str(complete_notebook)))
    except ImportError:pass
    print('Input correction validated. The old training panel is no longer required.',flush=True)
    print('Saved model hashes, raw-prefix identity, panel identity and parent-result checks are unchanged.',flush=True)
    print('CSV inputs accept genuine gzip or unpacked CSV, decoded by content.',flush=True)
    print('Running the corrected full diagnostic; no retraining.',flush=True)
    ns={'__name__':'__main__','__file__':str(path)}
    exec(compile(text,str(path),'exec'),ns)
    result=ns.get('R',{})
    REPORT['diagnostic_receipt']=result
    REPORT['status']='DIAGNOSTIC_COMPLETE' if result.get('status')=='BOUNDED_MECHANISM_DIAGNOSIS_COMPLETE' else 'DIAGNOSTIC_RETURNED_WITH_EXACT_REASON'
except Exception as error:
    REPORT.update({'status':'REPAIR_STOPPED_WITH_EXACT_REASON','reason':str(error)})
    (CONTROL/'error.txt').write_text(traceback.format_exc(),encoding='utf-8')
    print('\nISSUE:',error,flush=True)
finally:
    save_report()
    print('\nINPUT-REPAIR RECEIPT\n'+json.dumps(REPORT,indent=2,default=str),flush=True)
