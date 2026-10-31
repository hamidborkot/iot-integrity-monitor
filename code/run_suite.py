"""Run extracted development experiments in an isolated verified working copy.
Never infer confirmation, provenance approval, packet validity, or study completion.
"""
import argparse, ast, csv, hashlib, json, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent
MANIFEST=json.loads((HERE/'manifest.json').read_text())

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()

class Configure(ast.NodeTransformer):
    def __init__(self,base):self.base=str(base)
    def visit_Constant(self,node):
        if node.value=='/kaggle/working/fresh_all_datasets_v1':
            return ast.copy_location(ast.Constant(value=self.base),node)
        return node
    def visit_Assign(self,node):
        names={t.id for t in node.targets if isinstance(t,ast.Name)}
        if names.intersection({'CREATE_PRIVATE_ARCHIVE','INSTALL_MISSING_MENELAUS'}):
            node.value=ast.Constant(value=False)
        return self.generic_visit(node)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',required=True)
    ap.add_argument('--worktree')
    ap.add_argument('--tasks',nargs='+',choices=list(MANIFEST))
    ap.add_argument('--allow-training',action='store_true')
    ap.add_argument('--allow-attacks',action='store_true')
    args=ap.parse_args()
    source=Path(args.base).resolve()
    if not source.is_dir():raise FileNotFoundError(source)
    for name,spec in MANIFEST.items():
        if sha(HERE/spec['file'])!=spec['sha256']:
            raise RuntimeError(f'Experiment source changed: {name}')
    if not args.tasks:
        for name,spec in MANIFEST.items():
            folder=source/spec['output_folder']
            statuses=list(folder.glob('*status.csv')) if folder.is_dir() else []
            print(json.dumps({'task':name,'folder_present':folder.is_dir(),
                'status_files':[str(p) for p in statuses],
                'may_fit_models':spec['may_fit_auxiliary_models'],
                'optimizes_attacks':spec['optimizes_attacks'],
                'completion_inferred':False}))
        return
    for task in args.tasks:
        spec=MANIFEST[task]
        if spec['may_fit_auxiliary_models'] and not args.allow_training:
            raise RuntimeError(f'{task} may fit models. Add --allow-training explicitly.')
        if spec['optimizes_attacks'] and not args.allow_attacks:
            raise RuntimeError(f'{task} optimizes attacks. Add --allow-attacks explicitly.')
    if args.worktree:
        root=Path(args.worktree).resolve()
        marker=root/'worktree_receipt.json'
        if not marker.is_file():raise RuntimeError('Not a registered suite worktree.')
        if json.loads(marker.read_text())['source']!=str(source):
            raise RuntimeError('Worktree source mismatch.')
    else:
        root=Path('/kaggle/working')/('experiment_suite_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        files=[p for p in source.rglob('*') if p.is_file()]
        if any(p.is_symlink() for p in source.rglob('*')):
            raise RuntimeError('Source tree contains symlinks; isolated copying blocked.')
        total=sum(p.stat().st_size for p in files)
        if total+1024**3>shutil.disk_usage('/kaggle/working').free:
            raise RuntimeError('Insufficient space for isolated working copy.')
        root.mkdir(exist_ok=False)
        copied=root/'development'
        copied.mkdir()
        with (root/'copy_verification.csv').open('w',newline='') as f:
            w=csv.writer(f);w.writerow(['relative_path','bytes','sha256'])
            for p in files:
                q=copied/p.relative_to(source);q.parent.mkdir(parents=True,exist_ok=True)
                h=sha(p);shutil.copy2(p,q)
                if sha(q)!=h:raise RuntimeError(f'Copy mismatch: {q}')
                w.writerow([str(p.relative_to(source)),p.stat().st_size,h])
        marker=root/'worktree_receipt.json'
        marker.write_text(json.dumps({'source':str(source),'files':len(files),
            'bytes':total,'original_tree_overwritten':False},indent=2))
    base=root/'development'
    logs=root/'logs';logs.mkdir(exist_ok=True)
    history=root/'superseded_outputs';history.mkdir(exist_ok=True)
    receipts=[]
    for task in args.tasks:
        spec=MANIFEST[task]
        folder=base/spec['output_folder']
        if folder.exists():
            archived=history/(task+'_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
            folder.rename(archived)
        source_code=(HERE/spec['file']).read_text()
        tree=Configure(base).visit(ast.parse(source_code));ast.fix_missing_locations(tree)
        script=logs/f'{task}_configured.py'
        script.write_text(ast.unparse(tree)+'\n')
        log=logs/f'{task}.log'
        print(f'RUNNING {task}; log={log}',flush=True)
        with log.open('w') as f:
            completed=subprocess.run([sys.executable,str(script)],stdout=f,stderr=subprocess.STDOUT)
        task_statuses=[]
        for status in folder.glob('*status.csv') if folder.is_dir() else []:
            try:
                with status.open(newline='') as f:task_statuses.extend(list(csv.DictReader(f)))
            except Exception as error:task_statuses.append({'read_error':str(error)})
        failed_rows=[r for r in task_statuses if any(
            word in str(r.get('status','')).upper() for word in ['FAIL','BLOCK','NOT_IMPLEMENTED','RECOVERY_REQUIRED']
        ) or 'read_error' in r]
        receipt={'task':task,'process_returncode':completed.returncode,
            'status_rows':task_statuses,'recorded_failure_rows':len(failed_rows),
            'log':str(log),'experiment_output':str(folder),
            'scientific_completion_inferred':False,'confirmation_performed':False}
        receipts.append(receipt)
        (root/'execution_receipts.json').write_text(json.dumps(receipts,indent=2))
        print(json.dumps(receipt,indent=2),flush=True)
        if completed.returncode or failed_rows:
            raise RuntimeError(f'{task} failed; dependent tasks were not run. Inspect {log}')
    print('WORKTREE:',root)
    print('DEVELOPMENT COMPUTATIONS ONLY. FINAL STUDY COMPLETION NOT CLAIMED.')

if __name__=='__main__':main()
