import csv,hashlib,json,time
from pathlib import Path
from datetime import datetime,timezone
import pandas as pd

RUN=Path('/kaggle/working/CLOSING_E2E3_DRIVER_v2_48579ceb7266')
EXPECTED_CONFIG='48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea'
MAX_SMALL=1024**2
MAX_FILES=5000

def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()

def main():
    if not RUN.is_dir():raise FileNotFoundError(RUN)
    out=Path('/kaggle/working')/('CLOSING_E2E3_STOP_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(exist_ok=False)
    inventory=[];summaries=[];flags=[];errors=[];config=None
    allpaths=sorted(p for p in RUN.rglob('*') if p.is_file() and not p.is_symlink())
    if len(allpaths)>MAX_FILES:raise RuntimeError('Unexpected file count; bounded review required')
    for p in allpaths:
        size=p.stat().st_size
        rec={'path':str(p),'relative_path':str(p.relative_to(RUN)),'bytes':size,'suffix':p.suffix.lower()}
        inventory.append(rec)
        try:
            if p.name=='configuration.json':
                if size>MAX_SMALL:raise ValueError('Configuration exceeds bounded read')
                config=json.loads(p.read_text())
                (out/'configuration_snapshot.json').write_text(json.dumps(config,indent=2,default=str))
            if p.suffix.lower()=='.json' and size<=MAX_SMALL:
                obj=json.loads(p.read_text())
                if isinstance(obj,dict):
                    keys=['stage','status','configuration_sha256','jobs_expected','jobs_verified',
                          'source_jobs_complete','provisional_schema_for_E4','new_target_records_read',
                          'new_targets_read','independent_method_confirmation','next_step']
                    row={'path':str(p),**{k:obj[k] for k in keys if k in obj}}
                    if len(row)>1:flags.append(row)
            if p.suffix.lower()=='.csv':
                header=pd.read_csv(p,nrows=0).columns.tolist()
                if {'schema','min_primary_fold_mean_bacc','source_feasible'}.issubset(header):
                    df=pd.read_csv(p)
                    if len(df)>10:raise ValueError('Unexpected schema-summary size')
                    for row in df.to_dict('records'):summaries.append({'evidence_path':str(p),**row})
        except Exception as e:errors.append({'path':str(p),'error':f'{type(e).__name__}: {e}'})
    known_config_flags=[r for r in flags if r.get('configuration_sha256')==EXPECTED_CONFIG]
    failure_receipts=[r for r in known_config_flags if r.get('status')=='SOURCE_FEASIBILITY_FAILED']
    completed=[r for r in known_config_flags if r.get('jobs_verified')==18 or r.get('source_jobs_complete')==18]
    if not isinstance(config,dict):errors.append({'path':str(RUN/'configuration.json'),'error':'Configuration object unavailable'})
    passed_schemas=[]
    for r in summaries:
        value=str(r.get('source_feasible')).strip().lower()
        if value in ['true','1']:passed_schemas.append(str(r.get('schema')))
    decision={'status':'STOP_PRIMARY_MONITOR_BRANCH_RECORDED' if failure_receipts and completed and not passed_schemas else 'MANUAL_REVIEW_REQUIRED',
              'run_directory':str(RUN),'expected_configuration_sha256':EXPECTED_CONFIG,
              'matching_failure_receipts':len(failure_receipts),'matching_completion_receipts':len(completed),
              'schemas_marked_feasible':sorted(set(passed_schemas)),
              'E4_authorized':False,'E5_to_E7_authorized':False,'new_targets_may_be_scored':False,
              'interpretation':'Execution completed; declared source feasibility failed. No threshold/schema/target substitution.',
              'not_established':['Universal impossibility of monitoring','Novel failure law','Reason for expanded-schema recall loss'],
              'next_action':'Preserve accepted evidence; inspect saved source predictions for diagnostics and continue reusable evidence closure'}
    pd.DataFrame(inventory).to_csv(out/'run_inventory.csv',index=False)
    pd.DataFrame(flags).to_csv(out/'receipt_scope_flags.csv',index=False)
    pd.DataFrame(summaries).to_csv(out/'schema_summary_evidence.csv',index=False)
    pd.DataFrame(errors,columns=['path','error']).to_csv(out/'errors.csv',index=False)
    manifest={'audit_directory':str(out),'source_run':str(RUN),'expected_configuration_sha256':EXPECTED_CONFIG,
              'configuration_file_sha256':digest(RUN/'configuration.json') if (RUN/'configuration.json').is_file() else None,
              'decision':decision,'errors':errors,'files':[r for r in inventory]}
    (out/'audit_manifest.json').write_text(json.dumps(manifest,indent=2,default=str))
    (out/'branch_decision.json').write_text(json.dumps(decision,indent=2))
    print('\n=== BRANCH DECISION ===\n'+json.dumps(decision,indent=2))
    print('\n=== SOURCE CONFIGURATION ===\n'+json.dumps(config,indent=2,default=str))
    print('\n=== MATCHING COMPLETION / FEASIBILITY RECEIPTS ===')
    for r in known_config_flags:print(json.dumps(r,default=str))
    print('\n=== SCHEMA SUMMARY EVIDENCE ===\n'+pd.DataFrame(summaries).to_string(index=False))
    print('\n=== SAVED ARTIFACT LOCATIONS (first 30) ===')
    interesting=[r for r in inventory if Path(r['path']).suffix.lower() in ['.npz','.joblib','.parquet']]
    print(pd.DataFrame(interesting).head(30).to_string(index=False))
    print('\n=== ERRORS ===\n'+pd.DataFrame(errors,columns=['path','error']).to_string(index=False))
    print('\nAUDIT DIRECTORY:',out)
    return str(out)

E2E3_STOP_AUDIT_DIRECTORY=main()
