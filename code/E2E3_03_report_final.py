import hashlib,itertools,json
from pathlib import Path
import pandas as pd
import numpy as np

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def canonical(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()
ctx=json.loads(Path('/kaggle/working/CLOSING_CURRENT_SOURCE_DRIVER.json').read_text());out=Path(ctx['run_directory'])
cfg=json.loads(Path(ctx['configuration_path']).read_text())
if canonical(cfg)!=ctx['configuration_sha256']:raise ValueError('Configuration changed')
metrics=[];dependence=[];missing=[]
for schema,held,seed in itertools.product(cfg['schemas'],cfg['sources'],cfg['seeds']):
 job=out/'folds'/schema/held/f'seed_{seed}';receipt=job/'receipt.json'
 if not receipt.exists():missing.append((schema,held,seed));continue
 r=json.loads(receipt.read_text())
 if r.get('status')!='SOURCE_FOLD_COMPLETE' or r.get('configuration_sha256')!=ctx['configuration_sha256']:raise ValueError('Unaccepted checkpoint')
 for name,digest in r['artifact_hashes'].items():
  if sha(job/name)!=digest:raise ValueError('Artifact hash mismatch: '+str(job/name))
 metrics.append(pd.read_csv(job/'metrics.csv'));dependence.append(pd.read_csv(job/'dependence.csv'))
if missing:raise RuntimeError(f'{len(missing)} source jobs remain. Rerun Cell 2 unchanged; no feasibility decision issued.')
m=pd.concat(metrics,ignore_index=True);d=pd.concat(dependence,ignore_index=True)
m.to_csv(out/'all_fold_metrics.csv',index=False);d.to_csv(out/'all_view_dependence.csv',index=False)
main=m[m.scope.eq('held_source_validation')].copy()
f=main.groupby(['schema','held_capture','model'],as_index=False).agg(
balanced_accuracy=('balanced_accuracy','mean'),malicious_recall=('malicious_recall','mean'),
benign_FPR=('benign_FPR','mean'),AUROC=('AUROC','mean'),seed_bacc_SD=('balanced_accuracy','std'))
f.to_csv(out/'source_fold_seed_means.csv',index=False)
view_rows=[];schema_rows=[]
for schema in cfg['schemas']:
 primary=f[f.schema.eq(schema)&f.model.eq('PRIMARY')]
 if len(primary)!=len(cfg['sources']):raise ValueError('Missing primary fold')
 eligible=[]
 for view in cfg['views'][schema]:
  x=f[f.schema.eq(schema)&f.model.eq(view)]
  mean=float(x.balanced_accuracy.mean());minimum=float(x.balanced_accuracy.min())
  passed=bool(len(x)==len(cfg['sources']) and mean>=cfg['eligibility']['view_mean_fold_bacc'] and minimum>cfg['eligibility']['view_each_fold_mean_bacc_strictly_above'])
  view_rows.append({'schema':schema,'view':view,'mean_fold_bacc':mean,'min_fold_bacc':minimum,'eligible':passed})
  if passed:eligible.append(view)
 min_primary=float(primary.balanced_accuracy.min())
 schema_rows.append({'schema':schema,'min_primary_fold_mean_bacc':min_primary,'mean_primary_fold_bacc':float(primary.balanced_accuracy.mean()),
'eligible_views':'|'.join(eligible),'eligible_view_count':len(eligible),
'source_feasible':bool(min_primary>=cfg['eligibility']['primary_min_fold_mean_bacc'] and len(eligible)>=cfg['eligibility']['minimum_views'])})
s=pd.DataFrame(schema_rows);v=pd.DataFrame(view_rows)
s.to_csv(out/'schema_feasibility.csv',index=False);v.to_csv(out/'view_eligibility.csv',index=False)
choices=s[s.source_feasible].copy();choices['feature_count']=choices.schema.map(lambda k:len(cfg['schemas'][k]))
choices=choices.sort_values(['min_primary_fold_mean_bacc','feature_count'],ascending=[False,True],kind='stable')
selected=None if choices.empty else str(choices.iloc[0].schema)
receipt={'stage':'E2/E3 source-only feasibility','status':'SOURCE_FEASIBILITY_PASSED' if selected else 'SOURCE_FEASIBILITY_FAILED',
'run_directory':str(out),'configuration_sha256':ctx['configuration_sha256'],'source_jobs_complete':18,
'provisional_schema_for_E4':selected,'new_target_records_read':False,'independent_method_confirmation':False,
'warning':'Source feasibility is not monitoring effectiveness or a target guarantee; source panels are class-capped',
'next_step':'Review the per-fold primary/view/shortcut results before E4 calibration' if selected else 'Stop primary-monitor branch; do not add features/targets automatically'}
(out/'feasibility_receipt.json').write_text(json.dumps(receipt,indent=2))
print('=== E2/E3 FEASIBILITY RECEIPT ===\n'+json.dumps(receipt,indent=2))
print('\n=== PRIMARY SOURCE FOLDS ===\n'+f[f.model.eq('PRIMARY')].round(6).to_string(index=False))
print('\n=== VIEW ELIGIBILITY ===\n'+v.round(6).to_string(index=False))
print('\n=== SCHEMA FEASIBILITY ===\n'+s.round(6).to_string(index=False))
print('\n=== SHORTCUT CONTROLS (seed 8101; primary validation population) ===\n'+main[main.model.str.startswith('shortcut_')][['held_capture','seed','model','balanced_accuracy','malicious_recall','benign_FPR','AUROC']].round(6).to_string(index=False))
print('\n=== VIEW DEPENDENCE (mean descriptive diagnostics across source jobs) ===\n'+d.groupby(['schema','left','right'])[['disagreement','joint_error','error_correlation']].mean().round(6).to_string())
print('\nE4 has not run. No monitor/rejection parameters or held-out target outcomes have been selected here.')
