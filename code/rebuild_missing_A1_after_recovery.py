"""Recreate ONLY missing post-recovery A1 artifacts. No training or attacks.
Private recovered source/dependency snapshot, split audit, local Git tag and A2 draft.
Does NOT reconstruct the lost old commit or certify source/execution completeness.
"""
import hashlib
import itertools
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

ROOT=Path('/kaggle/working')
BASE=ROOT/'fresh_all_datasets_v1'
RECOVERY=ROOT/'runtime_recovery_verification_v1'
OUT=ROOT/'group_A1_development_source_freeze_v1'
REPO=OUT/'private_source_snapshot'
TAG='v1-development-recovery-freeze'
OLD_COMMIT_REPORTED='5c2a604f53027f4a05bafb23a076daee16ca9283'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
EXPECTED={
 'CICIoT2023':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88',
 'CICIoMT2024':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473',
 'CSE':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3',
 'NSL':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29',
 'TONIoT':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf'}
SOURCE_SCRIPT_NAMES={
 'all_datasets_rebuild_and_run.py','verify_real_witnesses_and_estimator_blindness.py',
 'real_record_mixture_and_order_stress.py','run_md3_and_identifiability_experiments.py',
 'run_aline_and_homogeneous_gde.py','neural_primary_attack_replication.py',
 'repair_neural_postprocessing.py','independent_bank_replication_and_statistics.py',
 'saved_attack_consistency_and_retention.py','protocol_freeze_and_provenance_workbench.py'}


def sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as handle:
        for block in iter(lambda:handle.read(8*1024*1024),b''): digest.update(block)
    return digest.hexdigest()


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def git(*args,check=True):
    result=subprocess.run(['git','-C',str(REPO),*args],capture_output=True,text=True)
    if check and result.returncode: raise RuntimeError(result.stderr)
    return result


def strip_notebook(path):
    notebook=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(notebook.get('cells'),list): raise ValueError('Not notebook JSON.')
    for cell in notebook['cells']:
        cell['metadata']={};cell.pop('attachments',None)
        if cell.get('cell_type')=='code':
            cell['outputs']=[];cell['execution_count']=None
    notebook['metadata']={key:value for key,value in notebook.get('metadata',{}).items()
                          if key in ['kernelspec','language_info']}
    return json.dumps(notebook,indent=2,ensure_ascii=False).encode()


def sources():
    manifest=[];candidates=set()
    for path in ROOT.rglob('*'):
        if path.is_file() and not path.is_symlink() and OUT not in path.parents:
            if path.suffix.lower() in ['.py','.ipynb'] or path.name=='IoTJ_Integrity_Monitoring_Research_Plan.md':
                candidates.add(path)
    input_root=Path('/kaggle/input')
    if input_root.exists():
        for path in input_root.rglob('*'):
            if path.is_file() and not path.is_symlink() and (
                path.name in SOURCE_SCRIPT_NAMES or path.name=='IoTJ_Integrity_Monitoring_Research_Plan.md'):
                candidates.add(path)
    current=globals().get('__file__')
    if current and Path(current).is_file(): candidates.add(Path(current))
    seen=set()
    for path in sorted(candidates,key=str):
        original_hash=sha(path)
        key=(path.name,original_hash)
        if key in seen: continue
        seen.add(key)
        target=REPO/'source'/f'{original_hash[:12]}_{path.name}'
        target.parent.mkdir(parents=True,exist_ok=True)
        try:
            if path.suffix.lower()=='.ipynb': target.write_bytes(strip_notebook(path))
            else: shutil.copy2(path,target)
            manifest.append({'original_path':str(path),'original_sha256':original_hash,
                'snapshot_path':str(target.relative_to(REPO)),'snapshot_sha256':sha(target),
                'scope':'Recovered/source candidate; execution lineage requires review'})
        except Exception as error:
            manifest.append({'original_path':str(path),'scope':'COPY_FAILED','detail':str(error)})
    try:
        from IPython import get_ipython
        shell=get_ipython()
        history=list(shell.history_manager.input_hist_raw) if shell else []
    except Exception: history=[]
    cells=[{'cell_type':'code','id':hashlib.sha256(f'{i}:{text}'.encode()).hexdigest()[:12],
            'metadata':{},'source':text.splitlines(keepends=True),'execution_count':None,'outputs':[]}
           for i,text in enumerate(history) if text and text.strip()]
    if cells:
        path=REPO/'source'/'NEW_RUNTIME_executed_inputs.ipynb'
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{},'cells':cells},indent=2))
        manifest.append({'original_path':'Current runtime input history','snapshot_path':str(path.relative_to(REPO)),
                         'snapshot_sha256':sha(path),'scope':'NEW runtime only; NOT the disconnected runtime history'})
    save_csv(manifest,REPO/'metadata'/'source_snapshot_manifest.csv')
    return manifest


def audit():
    allocation_rows=[];pair_rows=[];bundle_rows=[];used_rows=[]
    allowed={frozenset(['normal_profile_fit_df','known_reference_df']),
             frozenset(['normal_profile_calibration_df','known_profile_calibration_df'])}
    keys=['train_df','primary_calibration_df','view_threshold_df','normal_profile_fit_df',
          'normal_profile_calibration_df','known_reference_df','known_profile_calibration_df','source_test_df']
    for dataset in DATASETS:
        path=BASE/dataset/f'{dataset}_bundle.joblib'
        if sha(path)!=EXPECTED[dataset]: raise AssertionError(f'{dataset}: changed frozen bundle.')
        bundle=joblib.load(path)
        frames={key:bundle[key] for key in keys if key in bundle}
        frames.update({f'evaluation:{name}':frame for name,frame in bundle['evaluation_domains'].items()})
        ids={};patterns={};files={}
        for role,frame in frames.items():
            if frame['_row_id'].duplicated().any(): raise AssertionError(f'{dataset}/{role}: repeated record IDs.')
            row_ids=frame['_row_id'].astype(str)
            ids[role]=set(row_ids)
            file_names=row_ids.str.rsplit(':',n=1).str[0]
            files[role]=set(file_names)
            numeric=frame[bundle['primary_features']].apply(pd.to_numeric,errors='raise').astype('float64')
            numeric['__label__']=frame.label.to_numpy(dtype=int)
            patterns[role]=set(pd.util.hash_pandas_object(numeric,index=False).to_numpy().tolist())
            allocation_rows.append({'dataset':dataset,'allocation':role,'records':len(frame),
                'attack_fraction':float(frame.label.mean()),'source_files':len(files[role]),
                'pattern_duplicates':len(frame)-len(patterns[role])})
            used_rows.extend({'dataset':dataset,'allocation':role,'row_id':row_id,'source_file':file_name}
                             for row_id,file_name in zip(row_ids,file_names))
        for left,right in itertools.combinations(frames,2):
            overlap=len(ids[left]&ids[right]);permitted=frozenset([left,right]) in allowed
            pair_rows.append({'dataset':dataset,'left':left,'right':right,'exact_record_overlap':overlap,
                'permitted_shared_profile_records':permitted,'unexpected_exact_overlap':0 if permitted else overlap,
                'shared_predictor_label_patterns':len(patterns[left]&patterns[right]),
                'shared_source_files':len(files[left]&files[right]),
                'pattern_overlap_is_proven_record_duplication':False,'source_group_independence_verified':False})
        bundle_rows.append({'dataset':dataset,'bundle_sha256':sha(path),
                            'train_rows':len(bundle['train_df']),'source_test_rows':len(bundle['source_test_df']),
                            'features':len(bundle['primary_features'])})
        print(dataset,'RECOVERED SPLIT / PATTERN AUDIT COMPUTED',flush=True)
    save_csv(allocation_rows,REPO/'audit'/'allocation_summary.csv')
    save_csv(pair_rows,REPO/'audit'/'cross_allocation_audit.csv')
    save_csv(bundle_rows,REPO/'metadata'/'frozen_bundle_hashes.csv')
    save_csv(used_rows,OUT/'PRIVATE_fresh_bundle_record_exposure_registry.csv')
    return allocation_rows,pair_rows


def main():
    recovery_path=RECOVERY/'recovery_receipt.json'
    if not recovery_path.exists(): raise FileNotFoundError('Run verified recovery first.')
    if not json.loads(recovery_path.read_text()).get('five_bundle_recovery_verified'):
        raise RuntimeError('Five-bundle recovery has not passed.')
    if shutil.which('git') is None: raise RuntimeError('git is not installed.')
    OUT.mkdir(parents=True,exist_ok=True);REPO.mkdir(parents=True,exist_ok=True)
    receipt_path=OUT/'A1_freeze_receipt.json'
    if receipt_path.exists() and (REPO/'.git').exists() and git('rev-parse','--verify',f'refs/tags/{TAG}',check=False).returncode==0:
        receipt=json.loads(receipt_path.read_text())
        print('Existing recovered snapshot preserved; no tag overwrite.\n'+json.dumps(receipt,indent=2))
        return receipt
    source_manifest=sources()
    allocation_rows,pair_rows=audit()
    primary_family=[{'dataset':dataset,'attack':attack}
                    for dataset in ['CICIoT2023','CICIoMT2024']
                    for attack in ['approved_primitive_whitebox','approved_primitive_transfer','approved_primitive_sparse_channel']]
    draft={'status':'DRAFT_NOT_APPROVED_FOR_CONFIRMATION','primary_family':primary_family,
           'metric':'Differential absolute accuracy-estimation error','fixed_baseline':'DoC',
           'candidate_method':'Final source-reviewed drift-gated monitor; implementation not yet approved',
           'statistics':'Approved independent source-pair/model-seed units, clustered bootstrap, frozen six-test Holm family',
           'model_seeds_proposed':[3101,3102,3103],'pool_seed_proposed':3001,
           'warning':'New seeds alone are not new independent data',
           'approved_provenance_schema_sha256':None,'approved_attack_implementation_sha256':None,
           'approved_source_group_data_design':None,'untouched_boundary_data':None,
           'TONIoT_role':'Already inspected development data; not blind confirmation',
           'prerequisites':['B source-verified provenance','C permitted primitive transformations and re-extraction',
                            'D final baseline/label-budget conformance','E final adaptive protocol',
                            'Approved independent-data and claim/hypothesis design'],
           'confirmation_executed':False}
    (REPO/'protocol').mkdir(parents=True,exist_ok=True)
    (REPO/'protocol'/'protocol-confirmatory.DRAFT.yaml').write_text(
        '# DRAFT: NOT APPROVED FOR EXECUTION\n'+json.dumps(draft,indent=2))
    (REPO/'environment').mkdir(parents=True,exist_ok=True)
    packages=subprocess.run([sys.executable,'-m','pip','freeze'],capture_output=True,text=True,check=True)
    (REPO/'environment'/'RECOVERY_RUNTIME_requirements.txt').write_text(packages.stdout)
    (REPO/'environment'/'runtime.json').write_text(json.dumps({
        'python':sys.version,'platform':platform.platform(),'created_utc':datetime.now(timezone.utc).isoformat(),
        'scope':'Current recovery runtime; original environment requires archived evidence comparison'},indent=2))
    (REPO/'README.md').write_text(
        '# PRIVATE post-recovery snapshot\n\n'
        'This is a NEW local snapshot, not reconstruction of the lost earlier commit.\n'
        'Includes recovered source candidates, NEW runtime history, split audits, hashes and a protocol draft.\n'
        'No raw feature data or models are committed. No remote is configured and nothing is pushed.\n'
        'Source/execution completeness, original environment matching, physical provenance and confirmation remain unverified.\n')
    (REPO/'.gitignore').write_text('*.joblib\n*.pkl\n*.npz\n*.pcap*\n*.zip\n__pycache__/\n')
    git('init');git('config','user.name','Private Recovery Snapshot');git('config','user.email','snapshot@localhost')
    if git('remote').stdout.strip(): raise RuntimeError('Unexpected remote; no network operation permitted.')
    git('add','source','metadata','audit','environment','protocol','README.md','.gitignore')
    git('commit','-m','Private post-recovery development snapshot; confirmation pending')
    git('tag','-a',TAG,'-m','Recovered artifacts and audits; not the lost original commit or a confirmed study')
    commit=git('rev-parse','HEAD').stdout.strip()
    receipt={'A1_status':'POST_RECOVERY_LOCAL_SNAPSHOT_AND_SPLIT_AUDIT_CREATED',
        'local_repository':str(REPO),'local_tag':TAG,'git_commit':commit,
        'earlier_reported_commit_not_reconstructed':OLD_COMMIT_REPORTED,
        'remote_push_performed':False,'data_changed':False,'models_retrained':False,
        'source_snapshots':sum(bool(row.get('snapshot_path')) for row in source_manifest),
        'source_coverage_status':'Recovered candidates and NEW runtime history; full original executed-source coverage unverified',
        'unexpected_exact_record_overlap_count':sum(row['unexpected_exact_overlap'] for row in pair_rows),
        'source_group_independence_status':'NOT_ESTABLISHED_BY_RECORD_IDS',
        'exposure_registry_scope':'Current fresh bundles only, not all legacy exposures',
        'A2_confirmation_status':'NOT_RUN; final B-E and independent-data design pending',
        'final_confirmatory_protocol_frozen':False,'public_release_approved':False,
        'next_group':'B — recreate missing source evidence; preserve restored C/D/E/G development results'}
    receipt_path.write_text(json.dumps(receipt,indent=2))
    archive_base=ROOT/f'PRIVATE_A1_RECOVERY_SOURCE_{commit[:12]}'
    archive=Path(shutil.make_archive(str(archive_base),'zip',root_dir=OUT))
    archive_receipt={'archive':str(archive),'sha256':sha(archive),'private_only':True,
                     'scope':'A1 source/audit/registry only; experiment models are in the original full backup'}
    (ROOT/(archive.name+'.sha256')).write_text(f"{archive_receipt['sha256']}  {archive.name}\n")
    print('\nGROUP A1 RECOVERY RECEIPT\n'+json.dumps(receipt,indent=2),flush=True)
    print('\nA1 PRIVATE SOURCE ARCHIVE\n'+json.dumps(archive_receipt,indent=2),flush=True)
    print('\nALLOCATION SUMMARY\n'+pd.DataFrame(allocation_rows).to_string(index=False),flush=True)
    print('\nNEXT: GROUP B; do not rerun completed training or start A2.',flush=True)
    return receipt

if __name__=='__main__':
    A1_RECOVERY_STATUS=main()
