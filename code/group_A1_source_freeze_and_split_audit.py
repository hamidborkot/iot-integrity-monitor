"""Group A1: actual LOCAL source-code freeze, exposure/split audit, protocol draft.
Creates a local Git commit and v1-development-freeze tag. Never pushes to GitHub.
Does not retrain, alter datasets, approve schemas, or claim confirmation complete.
Group A2 requires finalized B-E implementations and an approved independent-data design.
"""
import hashlib
import itertools
import json
import os
import platform
import shutil
import subprocess
import sys
import traceback
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

ROOT=Path('/kaggle/working')
BASE=ROOT/'fresh_all_datasets_v1'
OUT=ROOT/'group_A1_development_source_freeze_v1'
REPO=OUT/'private_source_snapshot'
TAG='v1-development-freeze'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
SOURCE_NAMES={
 'all_datasets_rebuild_and_run.py','verify_real_witnesses_and_estimator_blindness.py',
 'real_record_mixture_and_order_stress.py','protocol_freeze_and_provenance_workbench.py',
 'run_md3_and_identifiability_experiments.py','run_aline_and_homogeneous_gde.py',
 'neural_primary_attack_replication.py','repair_neural_postprocessing.py',
 'independent_bank_replication_and_statistics.py','saved_attack_consistency_and_retention.py'}


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.tmp')
    frame.to_csv(temporary,index=False);temporary.replace(path)


def sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as handle:
        for block in iter(lambda:handle.read(8*1024*1024),b''): digest.update(block)
    return digest.hexdigest()


def git(*args,check=True):
    result=subprocess.run(['git','-C',str(REPO),*args],text=True,capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f'Local git command failed: {args}\n{result.stderr}')
    return result


def notebook_without_outputs(path):
    notebook=json.loads(path.read_text(encoding='utf-8'))
    if 'cells' not in notebook: raise ValueError('Not a notebook JSON document.')
    for cell in notebook['cells']:
        if cell.get('cell_type')=='code':
            cell['outputs']=[];cell['execution_count']=None
        cell['metadata']={}
        cell.pop('attachments',None)
    notebook['metadata']={key:value for key,value in notebook.get('metadata',{}).items()
                          if key in ['kernelspec','language_info']}
    return json.dumps(notebook,indent=2,ensure_ascii=False).encode('utf-8')


def snapshot_execution_history():
    try:
        from IPython import get_ipython
        shell=get_ipython()
        raw=list(shell.history_manager.input_hist_raw) if shell is not None else []
    except Exception:
        raw=[]
    cells=[]
    for index,source in enumerate(raw):
        if not source or not source.strip(): continue
        cells.append({'cell_type':'code','id':hashlib.sha256(f'{index}:{source}'.encode()).hexdigest()[:12],
                      'metadata':{},'execution_count':None,'outputs':[],'source':source.splitlines(keepends=True)})
    if not cells: return None
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':{
        'kernelspec':{'name':'python3','language':'python','display_name':'Python 3'}},'cells':cells}
    path=REPO/'source'/'current_session_executed_inputs.ipynb'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(notebook,indent=2,ensure_ascii=False))
    return {'source_origin':'IPython current-session input history','snapshot_file':str(path.relative_to(REPO)),
            'source_sha256':sha(path),'notebook_outputs_removed':True,'code_cells':len(cells)}


def collect_source():
    sources=[]
    history=snapshot_execution_history()
    if history: sources.append(history)
    candidates=[]
    for path in ROOT.rglob('*'):
        if not path.is_file() or OUT in path.parents or path.is_symlink(): continue
        if path.suffix.lower() in ['.py','.ipynb'] or path.name=='IoTJ_Integrity_Monitoring_Research_Plan.md':
            candidates.append(path)
    input_root=Path('/kaggle/input')
    if input_root.exists():
        for path in input_root.rglob('*'):
            if path.is_file() and not path.is_symlink() and (
                path.name in SOURCE_NAMES or path.name=='IoTJ_Integrity_Monitoring_Research_Plan.md'):
                candidates.append(path)
    seen=set()
    for path in sorted(candidates,key=str):
        original_hash=sha(path)
        key=(path.name,original_hash)
        if key in seen: continue
        seen.add(key)
        destination=REPO/'source'/'discovered_files'/f'{original_hash[:12]}_{path.name}'
        destination.parent.mkdir(parents=True,exist_ok=True)
        try:
            if path.suffix.lower()=='.ipynb':
                destination.write_bytes(notebook_without_outputs(path))
            else:
                shutil.copy2(path,destination)
            sources.append({'source_origin':str(path),'snapshot_file':str(destination.relative_to(REPO)),
                            'source_sha256':original_hash,'snapshot_sha256':sha(destination),
                            'notebook_outputs_removed':path.suffix.lower()=='.ipynb',
                            'execution_verified':'Current history is execution evidence; discovered files are source candidates'})
        except Exception as error:
            sources.append({'source_origin':str(path),'snapshot_file':'','source_sha256':original_hash,
                            'status':'COPY_FAILED','detail':str(error)})
    if not any(row.get('snapshot_file') for row in sources):
        raise RuntimeError('No source could be captured. Export the notebook source before freezing.')
    save_csv(sources,REPO/'metadata'/'source_snapshot_manifest.csv')
    return sources


def frames_for_audit(bundle):
    fields=['train_df','primary_calibration_df','view_threshold_df',
            'normal_profile_fit_df','normal_profile_calibration_df',
            'known_reference_df','known_profile_calibration_df','source_test_df']
    result={field:bundle[field] for field in fields if field in bundle}
    result.update({f'evaluation:{name}':frame for name,frame in bundle.get('evaluation_domains',{}).items()})
    return result


def split_audit():
    summaries=[];overlaps=[];exposures=[];bundle_manifest=[]
    permitted={frozenset(['normal_profile_fit_df','known_reference_df']),
               frozenset(['normal_profile_calibration_df','known_profile_calibration_df'])}
    for dataset in DATASETS:
        path=BASE/dataset/f'{dataset}_bundle.joblib'
        if not path.exists(): raise FileNotFoundError(path)
        bundle=joblib.load(path)
        features=list(bundle['primary_features'])
        frames=frames_for_audit(bundle)
        ids={};patterns={};files={}
        for role,frame in frames.items():
            if '_row_id' not in frame or 'label' not in frame:
                raise ValueError(f'{dataset}/{role}: record identifiers/labels are absent.')
            if frame['_row_id'].duplicated().any():
                raise AssertionError(f'{dataset}/{role}: record ID duplicated within an allocation.')
            id_values=frame['_row_id'].astype(str)
            ids[role]=set(id_values)
            file_values=id_values.str.rsplit(':',n=1).str[0]
            files[role]=set(file_values)
            numeric=frame[features].apply(pd.to_numeric,errors='raise').astype('float64')
            numeric['__binary_label__']=frame.label.to_numpy(dtype=int)
            pattern_hashes=pd.util.hash_pandas_object(numeric,index=False).to_numpy(dtype='uint64')
            patterns[role]=set(pattern_hashes.tolist())
            summaries.append({'dataset':dataset,'allocation':role,'records':len(frame),
                'attack_fraction':float(frame.label.mean()),'source_files':len(files[role]),
                'distinct_predictor_label_patterns':len(patterns[role]),
                'pattern_duplicates_within_allocation':len(frame)-len(patterns[role])})
            exposures.extend({'dataset':dataset,'allocation':role,'row_id':row_id,'source_file':file}
                             for row_id,file in zip(id_values,file_values))
        for left,right in itertools.combinations(frames,2):
            exact=ids[left]&ids[right]
            allowed=frozenset([left,right]) in permitted
            overlaps.append({'dataset':dataset,'left':left,'right':right,
                'exact_record_id_overlap':len(exact),'allowed_shared_profile_records':allowed,
                'shared_source_files':len(files[left]&files[right]),
                'shared_predictor_label_patterns':len(patterns[left]&patterns[right]),
                'unexpected_exact_overlap':len(exact) if not allowed else 0,
                'pattern_match_interpretation':'Candidate duplicate pattern; NOT proof of identical source traffic',
                'source_group_independence_verified':False})
        bundle_manifest.append({'dataset':dataset,'relative_bundle_path':str(path.relative_to(ROOT)),
                                'bundle_sha256':sha(path),'primary_features':len(features),
                                'train_rows':len(bundle['train_df']),
                                'source_test_rows':len(bundle['source_test_df'])})
        print(dataset,'RECORD / PATTERN / SOURCE-GROUP AUDIT COMPUTED',flush=True)
    save_csv(summaries,REPO/'audit'/'allocation_summary.csv')
    save_csv(overlaps,REPO/'audit'/'cross_allocation_overlap_audit.csv')
    # Private exclusion list for future confirmation design; not public release data.
    save_csv(exposures,OUT/'PRIVATE_previously_used_record_ids.csv')
    save_csv(bundle_manifest,REPO/'metadata'/'development_bundle_fingerprints.csv')
    return summaries,overlaps


def write_protocol_draft():
    primary_family=[{'dataset':dataset,'attack_family':attack,
                     'hypothesis':'Mean differential absolute error of the frozen DoC baseline exceeds that of the reviewed monitor'}
                    for dataset in ['CICIoMT2024','CICIoT2023']
                    for attack in ['approved_primitive_whitebox','approved_primitive_transfer','approved_primitive_sparse_channel']]
    draft={'status':'DRAFT_NOT_APPROVED_FOR_CONFIRMATORY_EXECUTION',
           'original_plan':'IoTJ_Integrity_Monitoring_Research_Plan.md',
           'development_source_tag':TAG,'source_tag_location':'LOCAL ONLY; no GitHub push',
           'primary_metric':'abs((estimated_attack_accuracy-actual_attack_accuracy)-(estimated_clean_accuracy-actual_clean_accuracy))',
           'fixed_comparison_baseline':'DoC','primary_test_family':primary_family,
           'multiple_testing':'Holm over these six tests ONLY after the final protocol is approved',
           'proposed_new_model_seeds':[3101,3102,3103],'proposed_new_pool_seed':3001,
           'seed_warning':'Fresh seeds alone do not establish independent data or confirmation',
           'independent_unit':'Approved source-domain-pair x independently trained model seed; source/target dependence must be audited',
           'approved_provenance_schema_sha256':None,'approved_attack_implementation_sha256':None,
           'final_model_and_monitor_configuration':None,'approved_confirmation_data_design':None,
           'untouched_boundary_dataset':None,'TONIoT_status':'Already used in development; not a blind dataset',
           'execution_blockers':['Finish Group B source-verified provenance',
                                 'Finish Group C primitive transformation/re-extraction validation',
                                 'Finish Group D baseline and label-budget conformance',
                                 'Finish Group E final adaptive evaluation protocol',
                                 'Approve independent data/source-group design and final hypothesis scope'],
           'A2_complete':False,'private_only':True}
    path=REPO/'protocol'/'protocol-confirmatory.DRAFT.yaml';path.parent.mkdir(parents=True,exist_ok=True)
    # JSON is valid YAML 1.2; no additional YAML library is needed.
    path.write_text('# DRAFT — NOT AN APPROVED CONFIRMATORY PROTOCOL\n'+json.dumps(draft,indent=2))
    return draft


def main():
    if not BASE.exists():
        raise FileNotFoundError('Restore your private backup into /kaggle/working first; fresh_all_datasets_v1 is absent.')
    if shutil.which('git') is None:
        raise RuntimeError('git is not installed in this environment.')
    OUT.mkdir(parents=True,exist_ok=True);REPO.mkdir(parents=True,exist_ok=True)
    if (REPO/'.git').exists() and git('rev-parse','--verify',f'refs/tags/{TAG}',check=False).returncode==0:
        print('Existing local development-freeze tag found; it will NOT be overwritten.')
        receipt=json.loads((OUT/'A1_freeze_receipt.json').read_text())
        print(json.dumps(receipt,indent=2));return receipt
    sources=collect_source()
    summaries,overlaps=split_audit()
    draft=write_protocol_draft()
    freeze=subprocess.run([sys.executable,'-m','pip','freeze'],capture_output=True,text=True,check=True)
    (REPO/'environment').mkdir(exist_ok=True)
    (REPO/'environment'/'requirements-development-freeze.txt').write_text(freeze.stdout)
    (REPO/'environment'/'runtime.json').write_text(json.dumps({
        'python':sys.version,'platform':platform.platform(),'created_utc':datetime.now(timezone.utc).isoformat()},indent=2))
    (REPO/'README.md').write_text(
        '# PRIVATE development source snapshot\n\n'
        'Source, code-history, dependency, and audit snapshots only. Models and processed data are not in this Git repository.\n'
        'No provenance approvals, confirmation results, traffic-validity claims, or public-redistribution approval are implied.\n'
        'This directory has no remote and this script does not push. A2 remains pending B-E and independent-data validation.\n')
    (REPO/'.gitignore').write_text('*.joblib\n*.pkl\n*.npz\n*.zip\n*.pcap*\n__pycache__/\n')
    git('init')
    git('config','user.name','Private Research Snapshot')
    git('config','user.email','snapshot@localhost')
    if git('remote').stdout.strip():
        raise RuntimeError('Unexpected Git remote configured; no automatic network operation will run.')
    git('add','source','audit','metadata','protocol','environment','README.md','.gitignore')
    git('commit','-m','Freeze private development source, dependencies and real-data audit; confirmation pending')
    git('tag','-a',TAG,'-m','Development evidence only; provenance-valid confirmation not complete')
    commit=git('rev-parse','HEAD').stdout.strip()
    tagged_commit=git('rev-list','-n','1',TAG).stdout.strip()
    if commit!=tagged_commit: raise AssertionError('Local tag/commit mismatch.')
    unexpected=sum(row['unexpected_exact_overlap'] for row in overlaps)
    receipt={'A1_status':'LOCAL_SOURCE_FREEZE_AND_SPLIT_AUDIT_COMPUTED',
        'local_repository':str(REPO),'local_tag':TAG,'git_commit':commit,
        'remote_push_performed':False,'source_snapshots':sum(bool(row.get('snapshot_file')) for row in sources),
        'source_snapshot_coverage':'Executed session history plus discovered source candidates; clean end-to-end replay remains to be audited',
        'unexpected_exact_record_overlap_count':unexpected,
        'record_disjointness_status':'NO_UNEXPECTED_ID_OVERLAP' if unexpected==0 else 'REVIEW_REQUIRED_UNEXPECTED_OVERLAP',
        'source_group_independence_status':'NOT_ESTABLISHED_BY_ROW_IDS',
        'A2_confirmation_status':'NOT_RUN; B-E and independent-data design required',
        'final_confirmatory_protocol_frozen':False,'public_release_approved':False}
    (OUT/'A1_freeze_receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\nGROUP A1 RECEIPT\n'+json.dumps(receipt,indent=2),flush=True)
    print('\nALLOCATION SUMMARY\n'+pd.DataFrame(summaries).to_string(index=False),flush=True)
    print('\nUNEXPECTED EXACT OVERLAPS\n'+pd.DataFrame([r for r in overlaps if r['unexpected_exact_overlap']]).to_string(index=False),flush=True)
    print('\nNEXT: GROUP B — verify feature/extractor provenance; do not run A2 yet.',flush=True)
    return receipt

if __name__=='__main__':
    A1_STATUS=main()
