import json,shutil,subprocess,sys,time
from pathlib import Path
from datetime import datetime,timezone
import pandas as pd

PRIOR=Path('/kaggle/working/CLOSING_REUSE_ANALYSIS_20261015T114153050466Z')
WORKER = r'''
import hashlib,itertools,json
from pathlib import Path
import numpy as np
import pandas as pd

KEY_ORDER=['group','scenario','condition','attack','seed','window']
BASE_NUMERIC=['clean_accuracy','attack_accuracy','true_damage','clean_estimate','attack_estimate']

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()

def boolean(s):
    v=s.astype('string').str.strip().str.lower().map({'true':True,'false':False,'1':True,'0':False,'1.0':True,'0.0':False})
    if v.isna().any():raise ValueError('Unrecognized or missing boolean')
    return v.astype(bool)

def avg(s):
    a=np.asarray(s,float);a=a[np.isfinite(a)]
    return float(a.mean()) if len(a) else np.nan

def analyze(frame,source_sha):
    f=frame.drop_duplicates().copy()
    method='configuration' if 'configuration' in f else 'estimator' if 'estimator' in f else None
    if not method:raise ValueError('No explicit configuration/estimator column')
    keys=[k for k in KEY_ORDER if k in f]
    if not {'scenario','seed','window'}.issubset(keys):raise ValueError('Missing explicit scenario/seed/window identity')
    if not ('attack' in keys or 'condition' in keys):raise ValueError('Missing attack/condition identity')
    if f[keys+[method]].isna().any().any():raise ValueError('Missing pair identity or method')
    if f.duplicated(keys+[method],keep=False).any():raise ValueError('Nonidentical repeated pair/method keys')
    for c in BASE_NUMERIC+['differential_abs_error']:
        f[c]=pd.to_numeric(f[c],errors='raise').astype(float)
        if np.isinf(f[c]).any():raise ValueError('Infinite value: '+c)
    for c in ['clean_accuracy','attack_accuracy']:
        if f[c].isna().any() or not f[c].between(0,1).all():raise ValueError('Invalid ground-truth accuracy: '+c)
    damage=f.clean_accuracy-f.attack_accuracy
    if not np.allclose(damage,f.true_damage,rtol=0,atol=1e-10):raise ValueError('Saved true damage mismatch')
    clean_available=f.clean_estimate.notna()
    attack_available=f.attack_estimate.notna()
    available=clean_available&attack_available
    if {'clean_abstained','attack_abstained','paired_estimate_retained'}.issubset(f):
        for c in ['clean_abstained','attack_abstained','paired_estimate_retained']:f[c]=boolean(f[c])
        if not np.array_equal(f.paired_estimate_retained,~f.clean_abstained&~f.attack_abstained):
            raise ValueError('Abstention and paired-retention flags disagree')
        if not np.array_equal(~f.clean_abstained,clean_available) or not np.array_equal(~f.attack_abstained,attack_available):
            raise ValueError('Declared acceptance and finite estimates disagree')
    elif 'paired_estimate_available' in f:
        if not np.array_equal(boolean(f.paired_estimate_available),available):
            raise ValueError('Saved paired availability disagrees with finite estimates')
    calculated=(f.clean_estimate-f.attack_estimate-damage).abs().where(available)
    if not np.allclose(calculated,f.differential_abs_error,rtol=0,atol=1e-10,equal_nan=True):
        raise ValueError('Saved differential error mismatch')
    f['_method']=f[method].astype(str)
    f['_paired_available']=available
    f['_attack_available']=attack_available
    f['_attack_absolute_error']=(f.attack_estimate-f.attack_accuracy).abs().where(attack_available)
    f['_attack_overestimation']=(f.attack_estimate-f.attack_accuracy).where(attack_available)
    f['_damage_underestimation']=(damage-(f.clean_estimate-f.attack_estimate)).where(available)
    f['_source_sha256']=source_sha
    units=[];comparisons=[]
    unitkeys=[k for k in keys if k!='window']
    for values,g in f.groupby(unitkeys+['_method'],dropna=False,sort=True):
        if not isinstance(values,tuple):values=(values,)
        tags=dict(zip(unitkeys+['_method'],values));tags['method']=tags.pop('_method')
        result={'source_sha256':source_sha,**tags,'windows':len(g),
            'paired_available_windows':int(g._paired_available.sum()),
            'paired_availability':float(g._paired_available.mean()),
            'attack_available_windows':int(g._attack_available.sum()),
            'attack_availability':float(g._attack_available.mean()),
            'mean_true_damage':avg(g.true_damage),
            'differential_MAE_on_available_pairs':avg(g.differential_abs_error),
            'attack_accuracy_MAE_on_available_estimates':avg(g._attack_absolute_error),
            'attack_signed_overestimation':avg(g._attack_overestimation),
            'damage_underestimation_on_available_pairs':avg(g._damage_underestimation)}
        if 'clean_abstained' in g:
            result.update(clean_abstention=float(g.clean_abstained.mean()),
                attack_abstention=float(g.attack_abstained.mean()),
                clean_abstain_attack_accept=float((g.clean_abstained&~g.attack_abstained).mean()),
                clean_accept_attack_abstain=float((~g.clean_abstained&g.attack_abstained).mean()))
        units.append(result)
    for values,g in f.groupby(unitkeys,dropna=False,sort=True):
        if not isinstance(values,tuple):values=(values,)
        tags=dict(zip(unitkeys,values))
        for left,right in itertools.combinations(sorted(g._method.unique()),2):
            a=g.loc[g._method.eq(left)].set_index('window')
            b=g.loc[g._method.eq(right)].set_index('window')
            common=a.index.intersection(b.index)
            a=a.loc[common];b=b.loc[common]
            for c in ['clean_accuracy','attack_accuracy','true_damage']:
                if not np.allclose(a[c],b[c],rtol=0,atol=1e-10,equal_nan=True):
                    raise ValueError('Compared methods do not share ground truth: '+c)
            mask=a._paired_available.to_numpy()&b._paired_available.to_numpy()
            av=a.differential_abs_error.to_numpy()[mask];bv=b.differential_abs_error.to_numpy()[mask]
            comparisons.append({'source_sha256':source_sha,**tags,'left':left,'right':right,
                'common_windows':len(common),'finite_common_pairs':int(mask.sum()),
                'finite_common_pair_fraction':float(mask.mean()) if len(mask) else np.nan,
                'left_error':avg(av),'right_error':avg(bv),'left_minus_right':avg(av-bv),
                'interpretation':'Negative favors left; conditional on both estimates available; descriptive only'})
    return f,units,comparisons

def run(inputs,output):
    inputs=Path(inputs);output=Path(output);output.mkdir(exist_ok=True)
    entries=json.loads((inputs/'trace_manifest.json').read_text())
    units=[];comparisons=[];audit=[]
    for row in entries:
        state={'source_sha256':row['sha256'],'logical_name':row['logical_name'],'status':'','error':''}
        try:
            p=inputs/row['copy']
            if sha(p)!=row['sha256']:raise ValueError('Saved CSV checksum mismatch')
            f,u,c=analyze(pd.read_csv(p,low_memory=False),row['sha256'])
            units.extend(u);comparisons.extend(c)
            f.to_csv(output/(row['sha256']+'_recomputed_windows.csv'),index=False,float_format='%.15g')
            state.update(status='PAIRED_TRACE_ANALYZED',rows=len(f),unit_rows=len(u),comparison_rows=len(c))
        except Exception as e:
            state.update(status='VALIDATION_FAILED',error=type(e).__name__+': '+str(e))
        audit.append(state)
    pd.DataFrame(units).to_csv(output/'trace_units_by_seed.csv',index=False,float_format='%.15g')
    pd.DataFrame(comparisons).to_csv(output/'trace_matched_comparisons_by_seed.csv',index=False,float_format='%.15g')
    pd.DataFrame(audit).to_csv(output/'trace_validation_audit.csv',index=False)
    # Seed means are descriptive; captures remain separate.
    if units:
        df=pd.DataFrame(units)
        groups=[k for k in ['source_sha256','group','scenario','condition','attack','method'] if k in df]
        aggs={'n_seeds':('seed','nunique'),'mean_paired_availability':('paired_availability','mean'),
            'mean_attack_availability':('attack_availability','mean'),
            'mean_differential_MAE':('differential_MAE_on_available_pairs','mean'),
            'seeds_with_finite_differential_error':('differential_MAE_on_available_pairs','count'),
            'mean_attack_accuracy_MAE':('attack_accuracy_MAE_on_available_estimates','mean'),
            'mean_true_damage':('mean_true_damage','mean')}
        df.groupby(groups,as_index=False,dropna=False).agg(**aggs).to_csv(output/'trace_capture_summary.csv',index=False,float_format='%.15g')
    return {'tables_attempted':len(entries),'tables_validated':sum(r['status']=='PAIRED_TRACE_ANALYZED' for r in audit),
            'validation_failures':sum(r['status']=='VALIDATION_FAILED' for r in audit),
            'unit_rows':len(units),'matched_comparison_rows':len(comparisons)}
'''

def main():
    started=time.monotonic()
    auditpath=PRIOR/'analysis/table_analysis_audit.csv'
    if not auditpath.is_file():raise FileNotFoundError('Restore the previous reuse-analysis package at PRIOR before running.')
    out=Path('/kaggle/working')/('CLOSING_TRACE_PAIR_CLOSURE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir();inputs=out/'inputs';inputs.mkdir()
    audit=pd.read_csv(auditpath,keep_default_na=False)
    manifest=pd.read_csv(PRIOR/'inputs/historical_table_manifest.csv',keep_default_na=False)
    unsupported=set(audit.loc[audit.status.eq('UNSUPPORTED_SCHEMA_PRESERVED_NOT_GUESSED'),'source_sha256'])
    selected=manifest.loc[manifest.sha256.isin(unsupported)&manifest.saved_copy.ne('')].drop_duplicates('sha256')
    ns={};exec(WORKER,ns)
    trace=[];schemas=[]
    for row in selected.sort_values('sha256').itertuples(index=False):
        p=(PRIOR/'inputs'/row.saved_copy).resolve();p.relative_to((PRIOR/'inputs').resolve())
        if ns['sha'](p)!=row.sha256:raise ValueError('Input checksum mismatch: '+row.logical_name)
        header=list(pd.read_csv(p,nrows=0).columns)
        origins=manifest.loc[manifest.sha256.eq(row.sha256),'artifact'].tolist()
        supported=set(ns['BASE_NUMERIC']+['differential_abs_error']).issubset(header)
        schemas.append({'source_sha256':row.sha256,'logical_name':row.logical_name,
            'columns':json.dumps(header),'original_locations':json.dumps(origins),
            'next_disposition':'TRACE_ADAPTER_APPLIED' if supported else 'EXPLICIT_SCHEMA_ADAPTER_STILL_REQUIRED'})
        if supported:
            dest=inputs/(row.sha256+'.csv');shutil.copy2(p,dest)
            trace.append({'sha256':row.sha256,'copy':dest.name,'logical_name':row.logical_name})
    (inputs/'trace_manifest.json').write_text(json.dumps(trace,indent=2))
    pd.DataFrame(schemas).to_csv(out/'previously_unsupported_schema_report.csv',index=False)
    print('[1/3] Recomputing legacy paired trace errors and availability.',flush=True)
    counts=ns['run'](inputs,out/'analysis')
    print('[2/3] Checking independent-process reproduction.',flush=True)
    child=out/'reproduce_trace_tables.py'
    child.write_text(WORKER+"\nif __name__ == '__main__':\n    import sys\n    run(sys.argv[1],sys.argv[2])\n")
    proc=subprocess.run([sys.executable,str(child),str(inputs),str(out/'clean_reproduction')],capture_output=True,text=True,timeout=180)
    (out/'clean_process_stdout.txt').write_text(proc.stdout)
    (out/'clean_process_stderr.txt').write_text(proc.stderr)
    checks=[]
    for p in sorted((out/'analysis').glob('*.csv')):
        q=out/'clean_reproduction'/p.name
        checks.append({'table':p.name,'exact_match':q.is_file() and ns['sha'](p)==ns['sha'](q)})
    pd.DataFrame(checks).to_csv(out/'reproduction_checks.csv',index=False)
    reproduced=proc.returncode==0 and bool(checks) and all(r['exact_match'] for r in checks)
    receipt={'stage':'Legacy trace paired-error and availability closure',
        'status':'TRACE_PAIR_ANALYSIS_RECORDED' if reproduced and not counts['validation_failures'] and counts['tables_validated'] else 'PARTIAL_OR_BLOCKED',
        'output_directory':str(out),**counts,'clean_process_exact_reproduction':reproduced,
        'previously_unsupported_tables':len(selected),
        'remaining_schema_adapters':len(selected)-counts['tables_validated'],
        'elapsed_seconds':round(time.monotonic()-started,2),
        'models_trained':False,'new_targets_scored':False,'new_packet_transforms':False,
        'new_damage_thresholds':False,'independent_seed_inference':False,'E4_E7_new_confirmation_executed':False,
        'historical_scope':'Existing post-exposure/descriptive trace evidence; not new source-feasible-method confirmation',
        'current_source_configuration_restored':False,
        'all_experiments_complete':False}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2))
    archive=shutil.make_archive(str(out)+'_PACK','zip',root_dir=out)
    print('[3/3] Trace package complete.',flush=True)
    print('\n=== TRACE CAPTURE SUMMARY (up to 40 rows; full CSV saved) ===')
    if (out/'analysis/trace_capture_summary.csv').is_file():
        summary=pd.read_csv(out/'analysis/trace_capture_summary.csv')
        print(summary.drop(columns=['source_sha256'],errors='ignore').head(40).round(5).to_string(index=False))
    else:print('No compatible trace tables validated; inspect the schema report.')
    print('\n=== STILL-UNSUPPORTED SCHEMAS ===')
    for r in schemas:
        if r['next_disposition']=='EXPLICIT_SCHEMA_ADAPTER_STILL_REQUIRED':
            print(r['logical_name']+' | '+r['columns'])
    print('\n=== TRACE VALIDATION AUDIT ===')
    if trace:print(pd.read_csv(out/'analysis/trace_validation_audit.csv').to_string(index=False))
    else:print('No compatible trace tables found.')
    print('\n=== TRACE RECEIPT ===\n'+json.dumps(receipt,indent=2))
    print('\nEvidence pack:',archive)
    return str(out)

TRACE_PAIR_CLOSURE_DIRECTORY=main()
