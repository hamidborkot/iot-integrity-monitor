import hashlib, json, shutil, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

INPUT = Path('/kaggle/working/CLOSING_FINISH_20261015T113658611821Z')
WORKER = r'''
import hashlib, itertools, json
from pathlib import Path
import numpy as np
import pandas as pd

GROUPS = ['dataset','family','view_seed','model_seed','seed','condition','epsilon',
          'scope','profile_version','attack','attack_family','candidate_kind','panel',
          'domain','target','scenario','held_capture','bank_id','bank_seed',
          'search_seed','lambda','ordering','configuration','tie_policy']

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''): h.update(b)
    return h.hexdigest()

def boolean(s):
    v=s.astype('string').str.strip().str.lower()
    out=v.map({'true':True,'false':False,'1':True,'0':False,'1.0':True,'0.0':False})
    if out.isna().any(): raise ValueError('Missing or unrecognized accepted/collapse value')
    return out.astype(bool)

def number(s):
    x=pd.to_numeric(s,errors='raise').astype(float)
    if np.isinf(x).any(): raise ValueError('Infinite numeric metric')
    return x

def finite_mean(s):
    a=np.asarray(s,dtype=float)
    return float(np.mean(a[np.isfinite(a)])) if np.isfinite(a).any() else np.nan

def grouped(df, keys):
    if not keys: return [((),df)]
    return df.groupby(keys,dropna=False,sort=True)

def tags_for(keys, values):
    if not keys: return {}
    if len(keys)==1 and not isinstance(values,tuple): values=(values,)
    return dict(zip(keys,values))

def process(root, output):
    root=Path(root); output=Path(output); output.mkdir(exist_ok=True)
    manifest=pd.read_csv(root/'historical_table_manifest.csv',keep_default_na=False)
    required={'sha256','saved_copy','logical_name'}
    if not required.issubset(manifest): raise ValueError('Historical manifest schema mismatch')
    manifest=manifest.loc[manifest.saved_copy.ne('') & manifest.sha256.ne('')]
    summaries=[]; pairings=[]; window_summaries=[]; audit=[]; schemas=[]
    for row in manifest.drop_duplicates('sha256').sort_values('sha256').itertuples(index=False):
        sha=row.sha256
        item={'source_sha256':sha,'logical_name':row.logical_name,'status':'','error':''}
        try:
            p=(root/row.saved_copy).resolve()
            p.relative_to(root.resolve())
            if digest(p)!=sha: raise ValueError('Preserved CSV checksum mismatch')
            frame=pd.read_csv(p,low_memory=False)
            if frame.columns.duplicated().any(): raise ValueError('Duplicate column names')
            original=len(frame)
            frame=frame.drop_duplicates().reset_index(drop=True)
            item.update(input_rows=original,exact_duplicate_rows_removed=original-len(frame))
            schemas.append({'source_sha256':sha,'logical_name':row.logical_name,'columns':json.dumps(list(frame.columns))})
            keys=[c for c in GROUPS if c in frame]
            base={'source_sha256':sha,'logical_name':row.logical_name,
                  'evidence_scope':'HISTORICAL_TABLE_DESCRIPTIVE_NOT_ACCEPTED_OR_CONFIRMATORY'}
            if {'estimator','estimated_accuracy','actual_accuracy'}.issubset(frame):
                frame['estimated_accuracy']=number(frame.estimated_accuracy)
                frame['actual_accuracy']=number(frame.actual_accuracy)
                actual=frame.actual_accuracy.dropna()
                if not actual.between(0,1).all(): raise ValueError('actual_accuracy is not a proportion')
                # Do not clip estimator outputs; out-of-range estimates remain visible.
                frame['_signed']=frame.estimated_accuracy-frame.actual_accuracy
                frame['_absolute']=frame['_signed'].abs()
                if 'absolute_error' in frame:
                    stored=number(frame.absolute_error)
                    mask=stored.notna() & frame['_absolute'].notna()
                    if not np.allclose(stored[mask],frame.loc[mask,'_absolute'],rtol=0,atol=1e-9):
                        raise ValueError('Stored absolute_error disagrees with estimate-minus-truth')
                if 'differential_error' in frame:
                    frame['differential_error']=number(frame.differential_error)
                    if frame.differential_error.dropna().lt(-1e-12).any():
                        raise ValueError('Negative differential absolute error')
                accepted='accepted' if 'accepted' in frame else None
                if accepted: frame[accepted]=boolean(frame[accepted])
                witness='witness_sha256' if 'witness_sha256' in frame else None
                if witness:
                    if frame[witness].isna().any(): raise ValueError('Missing witness identity')
                    identity=keys+[witness,'estimator']
                    if frame.duplicated(identity,keep=False).any():
                        raise ValueError('Nonidentical repeated estimator/witness keys; no silent pooling')
                for values,g in grouped(frame,keys+['estimator']):
                    tags=tags_for(keys+['estimator'],values)
                    valid=g['_absolute'].notna()
                    result={**base,**tags,'reported_rows':len(g),'valid_estimates':int(valid.sum()),
                            'missing_estimate_or_truth_fraction':float(1-valid.mean()),
                            'accuracy_MAE':finite_mean(g['_absolute']),
                            'signed_overestimation':finite_mean(g['_signed']),
                            'actual_accuracy':finite_mean(g.actual_accuracy),
                            'estimated_accuracy':finite_mean(g.estimated_accuracy),
                            'out_of_range_estimates':int((g.estimated_accuracy.notna() & ~g.estimated_accuracy.between(0,1)).sum())}
                    if 'differential_error' in g:
                        result['saved_differential_MAE']=finite_mean(g.differential_error)
                        result['saved_differential_valid_rows']=int(g.differential_error.notna().sum())
                    if accepted:
                        result['accepted_coverage']=float(g.accepted.mean())
                        result['accepted_rows']=int(g.accepted.sum())
                        result['accepted_accuracy_MAE']=finite_mean(g.loc[g.accepted,'_absolute'])
                        result['accepted_valid_estimates']=int((g.accepted & valid).sum())
                    if 'true_damage' in g:
                        result['saved_mean_true_damage']=finite_mean(number(g.true_damage))
                    summaries.append(result)
                if witness:
                    for values,g in grouped(frame,keys):
                        tags=tags_for(keys,values)
                        for left,right in itertools.combinations(sorted(g.estimator.dropna().astype(str).unique()),2):
                            a=g.loc[g.estimator.astype(str).eq(left)].set_index(witness)
                            b=g.loc[g.estimator.astype(str).eq(right)].set_index(witness)
                            common=a.index.intersection(b.index)
                            if len(common)==0: continue
                            a=a.loc[common]; b=b.loc[common]
                            if not np.allclose(a.actual_accuracy,b.actual_accuracy,atol=1e-12,rtol=0,equal_nan=True):
                                raise ValueError('Paired estimators disagree on ground truth')
                            if accepted and not np.array_equal(a.accepted,b.accepted):
                                raise ValueError('Estimator-specific acceptance differs; cannot claim matched coverage')
                            for metric in ['_absolute']+(['differential_error'] if 'differential_error' in g else []):
                                av=a[metric].to_numpy(float); bv=b[metric].to_numpy(float)
                                valid=np.isfinite(av)&np.isfinite(bv)
                                delta=av[valid]-bv[valid]
                                pairings.append({**base,**tags,'left':left,'right':right,
                                    'metric':'accuracy_absolute_error' if metric=='_absolute' else 'saved_differential_error',
                                    'common_witnesses':len(common),'valid_pairs':int(valid.sum()),
                                    'left_unmatched':len(g.loc[g.estimator.astype(str).eq(left)])-len(common),
                                    'right_unmatched':len(g.loc[g.estimator.astype(str).eq(right)])-len(common),
                                    'left_mean_error':finite_mean(av[valid]),'right_mean_error':finite_mean(bv[valid]),
                                    'left_minus_right':finite_mean(delta),
                                    'interpretation':'Negative favors left; descriptive only; no independence claim'})
                item['status']='ESTIMATOR_ANALYZED'
            elif {'witness_sha256','accuracy','accepted'}.issubset(frame):
                frame['accuracy']=number(frame.accuracy)
                if not frame.accuracy.dropna().between(0,1).all(): raise ValueError('accuracy is not a proportion')
                frame['accepted']=boolean(frame.accepted)
                if frame.duplicated(keys+['witness_sha256'],keep=False).any():
                    raise ValueError('Nonidentical repeated window identities')
                if 'accepted_collapse' in frame: frame['accepted_collapse']=boolean(frame.accepted_collapse)
                for values,g in grouped(frame,keys):
                    r={**base,**tags_for(keys,values),'windows':len(g),
                       'accepted_windows':int(g.accepted.sum()),'accepted_coverage':float(g.accepted.mean()),
                       'mean_primary_accuracy':finite_mean(g.accuracy),
                       'accepted_primary_risk':finite_mean(1-g.loc[g.accepted,'accuracy'])}
                    if 'true_damage' in g: r['saved_mean_true_damage']=finite_mean(number(g.true_damage))
                    if 'accepted_collapse' in g:
                        r['saved_accepted_collapse_count']=int(g.accepted_collapse.sum())
                        r['saved_accepted_collapse_fraction_all_windows']=float(g.accepted_collapse.mean())
                    window_summaries.append(r)
                item['status']='WINDOW_ANALYZED'
            else:
                item['status']='UNSUPPORTED_SCHEMA_PRESERVED_NOT_GUESSED'
            item['rows_after_exact_dedup']=len(frame)
        except Exception as e:
            # Remove all partial results from a table that fails validation.
            summaries=[x for x in summaries if x['source_sha256']!=sha]
            pairings=[x for x in pairings if x['source_sha256']!=sha]
            window_summaries=[x for x in window_summaries if x['source_sha256']!=sha]
            item['status']='VALIDATION_FAILED'; item['error']=type(e).__name__+': '+str(e)
        audit.append(item)
    tables={'estimator_summary':summaries,'matched_estimator_comparisons':pairings,
            'window_coverage_summary':window_summaries,'table_analysis_audit':audit,'table_schemas':schemas}
    for name,rows in tables.items():
        pd.DataFrame(rows).to_csv(output/(name+'.csv'),index=False,float_format='%.15g')
    return {name:len(rows) for name,rows in tables.items()}
'''

def main():
    started=time.monotonic()
    if not (INPUT/'historical_table_manifest.csv').is_file():
        raise FileNotFoundError('The recovered historical-table package is not mounted at INPUT. Restore that package; do not rerun training.')
    out=Path('/kaggle/working')/('CLOSING_REUSE_ANALYSIS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(); inputs=out/'inputs'; inputs.mkdir()
    shutil.copy2(INPUT/'historical_table_manifest.csv',inputs/'historical_table_manifest.csv')
    manifest=pd.read_csv(INPUT/'historical_table_manifest.csv',keep_default_na=False)
    used=manifest.loc[manifest.saved_copy.ne('') & manifest.sha256.ne('')].drop_duplicates('sha256')
    for row in used.itertuples(index=False):
        src=(INPUT/row.saved_copy).resolve(); src.relative_to(INPUT.resolve())
        dst=inputs/row.saved_copy; dst.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(src,dst)
    ns={}; exec(WORKER,ns)
    print('[1/3] Computing saved-table errors, coverage and matched comparisons.',flush=True)
    counts=ns['process'](inputs,out/'analysis')
    print('[2/3] Reproducing all output tables in a clean Python process.',flush=True)
    child=out/'reproduce_saved_table_analysis.py'
    child.write_text(WORKER+"\nif __name__ == '__main__':\n    import sys\n    process(sys.argv[1],sys.argv[2])\n")
    p=subprocess.run([sys.executable,str(child),str(inputs),str(out/'clean_reproduction')],capture_output=True,text=True,timeout=300)
    (out/'clean_process_stdout.txt').write_text(p.stdout)
    (out/'clean_process_stderr.txt').write_text(p.stderr)
    comparisons=[]
    for a in sorted((out/'analysis').glob('*.csv')):
        b=out/'clean_reproduction'/a.name
        comparisons.append({'table':a.name,'exactly_reproduced':b.is_file() and ns['digest'](a)==ns['digest'](b)})
    pd.DataFrame(comparisons).to_csv(out/'reproduction_checks.csv',index=False)
    audit=pd.read_csv(out/'analysis/table_analysis_audit.csv',keep_default_na=False)
    statuses=audit.status.value_counts().to_dict()
    reproduced=p.returncode==0 and bool(comparisons) and all(r['exactly_reproduced'] for r in comparisons)
    receipt={'status':'DESCRIPTIVE_REUSE_ANALYSIS_RECORDED','output_directory':str(out),
        'unique_input_tables':len(used),'output_row_counts':counts,'table_status_counts':statuses,
        'clean_process_exact_reproduction':reproduced,'clean_process_returncode':p.returncode,
        'elapsed_seconds':round(time.monotonic()-started,2),
        'new_models_trained':False,'new_predictions_computed':False,'new_target_outcomes_read':False,
        'method_or_threshold_changes':False,'p_values_or_independent_seed_intervals_computed':False,
        'historical_tables_declared_accepted':False,'packet_validity_established':False,
        'E4_E7_executed':False,'full_E8_E10_completed':False,
        'source_branch_blocker':'Exact current source configuration/allocations/cache must be recovered before that branch resumes',
        'scope':'Per-input-table descriptive analysis; no cross-version pooling and no new confirmation'}
    if not reproduced: receipt['status']='REPRODUCTION_FAILED'
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2))
    (out/'README.txt').write_text(
        'Use source_sha256 to keep every historical input separate. Negative left_minus_right favors the left estimator.\n'
        'Paired comparisons require matching witness hashes and identical truth/acceptance. No p-values are produced.\n'
        'saved_differential_MAE is summarized from the existing field; its original clean/attack pairing is not independently reconstructed.\n'
        'Unsupported schemas and validation failures are explicit in table_analysis_audit.csv.\n'
        'These are candidate historical summaries, not accepted manuscript tables until provenance/supersession is reconciled.\n')
    records=[{'file':str(q.relative_to(out)),'sha256':ns['digest'](q),'bytes':q.stat().st_size}
             for q in sorted(out.rglob('*')) if q.is_file()]
    pd.DataFrame(records).to_csv(out/'file_manifest.csv',index=False)
    archive=shutil.make_archive(str(out)+'_PACK','zip',root_dir=out)
    print('[3/3] Analysis package written.',flush=True)
    print('\n=== TABLE ANALYSIS STATUS ===')
    print(audit.groupby('status',dropna=False).size().rename('tables').to_string())
    print('\n=== REUSE ANALYSIS RECEIPT ===')
    print(json.dumps(receipt,indent=2))
    print('\nEvidence pack:',archive)
    print('Keep this package and the previous recovery package before resetting the runtime.')
    return str(out)

REUSE_ANALYSIS_DIRECTORY=main()
