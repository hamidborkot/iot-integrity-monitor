import gc,hashlib,json,time
from pathlib import Path
from datetime import datetime,timezone
from itertools import combinations
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder,FunctionTransformer
from sklearn.impute import SimpleImputer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix,roc_auc_score
from threadpoolctl import threadpool_limits

PANELS=Path('/kaggle/working/CLOSING_E1A_SOURCE_PANEL_20261015T061834828709Z')
OUT=Path('/kaggle/working/CLOSING_E2E3_SOURCE_FOLDS_v1')
SOURCES=[f'CTU-IoT-Malware-Capture-{n}-1' for n in [1,3,8]]
SEEDS=[8101,8102,8103]
CORE=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
EXTRA=['id.resp_p','service','conn_state','history']
SCHEMAS={'core9':CORE,'expanded13':CORE+EXTRA}
CATEGORICAL={'proto','service','conn_state','history'}
VIEWS={'originator':['orig_pkts','orig_bytes','orig_ip_bytes'],
       'responder':['resp_pkts','resp_bytes','resp_ip_bytes'],
       'timing':['duration'],'context':['proto','missed_bytes']}
ROLES=['train','competence_reference','profile_fit','cutoff_calibration','source_validation']
VERSION='source-fold-closure-v1'


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
    return h.hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def group_id(scenario,record_key):
    fields=json.loads(record_key)
    if len(fields)!=6:raise ValueError('Unexpected recorded flow-key schema')
    payload=json.dumps([scenario]+fields[1:],separators=(',',':'))
    return hashlib.sha256(payload.encode()).hexdigest()


def allocation(group):
    bucket=int(hashlib.sha256(('closing-source-role-v1|'+group).encode()).hexdigest()[:16],16)%100
    return ROLES[0] if bucket<60 else ROLES[1+(bucket-60)//10]


def model_pipeline(columns,seed):
    nums=[c for c in columns if c not in CATEGORICAL]
    cats=[c for c in columns if c in CATEGORICAL]
    transforms=[]
    if nums:
        transforms.append(('numeric',Pipeline([
            ('impute',SimpleImputer(strategy='median',keep_empty_features=True)),
            ('log1p',FunctionTransformer(np.log1p,feature_names_out='one-to-one'))]),nums))
    if cats:
        transforms.append(('categorical',OneHotEncoder(handle_unknown='ignore',
                          sparse_output=False,max_categories=64,dtype=np.float64),cats))
    return Pipeline([('features',ColumnTransformer(transforms,remainder='drop',sparse_threshold=0)),
                     ('classifier',HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,
                        early_stopping=False,random_state=seed))])


def metric(y,decision,probability):
    tn,fp,fn,tp=confusion_matrix(y,decision,labels=[0,1]).ravel()
    recall=float(tp/(tp+fn)) if tp+fn else None
    fpr=float(fp/(fp+tn)) if fp+tn else None
    return {'rows':len(y),'benign':int(tn+fp),'malicious':int(tp+fn),
        'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp),
        'accuracy':float(np.mean(y==decision)),
        'balanced_accuracy':(recall+1-fpr)/2 if recall is not None and fpr is not None else None,
        'malicious_recall':recall,'benign_FPR':fpr,
        'AUROC':float(roc_auc_score(y,probability)) if len(np.unique(y))==2 else None}


def summarize_jobs(config_hash):
    rows=[];done=[]
    for p in sorted((OUT/'jobs').glob('*/completion.json')):
        rec=json.loads(p.read_text())
        if rec.get('configuration_sha256')!=config_hash:raise ValueError('Mixed configurations in job tree')
        if rec.get('status')!='SOURCE_FOLD_TECHNICALLY_COMPLETE':continue
        metrics=Path(rec['metrics_file'])
        if not metrics.is_file() or sha(metrics)!=rec['metrics_sha256']:raise ValueError('Completed metrics missing/changed: '+str(p))
        rows.extend(pd.read_csv(metrics).to_dict('records'));done.append(rec['job_id'])
    if rows:pd.DataFrame(rows).to_csv(OUT/'completed_fold_metrics.csv',index=False)
    return rows,done


def main():
    started=time.monotonic()
    receipt=json.loads((PANELS/'receipt.json').read_text())
    if receipt['status']!='SOURCE_PANEL_READY_FOR_ALLOCATION':raise RuntimeError('All source panels must pass E1-A')
    panel_contract=json.loads((PANELS/'source_panel_contract.json').read_text())
    fingerprints=[]
    for p in panel_contract['panels']:
        if sha(p['path'])!=p['sha256']:raise ValueError('Source panel changed: '+p['scenario'])
        fingerprints.append({'scenario':p['scenario'],'path':p['path'],'sha256':p['sha256']})
    config={'version':VERSION,'sources':SOURCES,'panel_fingerprints':fingerprints,
        'schemas':SCHEMAS,'views_core':VIEWS,'views_expanded_context':['proto','missed_bytes']+EXTRA,
        'seeds':SEEDS,'grouping':'Source capture plus directed five-tuple, excluding timestamp',
        'role_buckets':dict(zip(ROLES,[60,10,10,10,10])),
        'role_salt':'closing-source-role-v1','categorical_max_categories':64,
        'unknown_categories':'All-zero encoding; unknown rates reported',
        'classifier':{'family':'HistGradientBoostingClassifier','max_iter':150,'learning_rate':.08,'early_stopping':False},
        'fixed_decision_threshold':.5,'calibration_diagnostic_FPR':.05,
        'source_primary_goal_min_fold_bacc':.80,'source_view_goal_mean_fold_bacc':.70,
        'source_view_goal_each_fold_above':.50,'minimum_eligible_views':2,
        'scope':'SOURCE/DESIGN ONLY; no held-out research targets; no confirmatory p-values'}
    ch=canonical_hash(config)
    OUT.mkdir(exist_ok=True);(OUT/'jobs').mkdir(exist_ok=True)
    config_path=OUT/'configuration.json'
    if config_path.exists():
        existing=json.loads(config_path.read_text())
        if existing.get('configuration_sha256')!=ch:raise RuntimeError('Configuration changed; use a new versioned output root')
    else:config_path.write_text(json.dumps({'configuration_sha256':ch,'settings':config},indent=2))
    data_path=OUT/'source_allocations.parquet';allocation_receipt=OUT/'allocation_receipt.json'
    if allocation_receipt.exists():
        ar=json.loads(allocation_receipt.read_text())
        if ar['configuration_sha256']!=ch or not data_path.is_file() or sha(data_path)!=ar['allocations_sha256']:
            raise ValueError('Saved allocation contract/file mismatch')
        df=pd.read_parquet(data_path)
    else:
        if data_path.exists():raise RuntimeError('Unaccepted partial allocation exists; inspect it rather than silently reuse')
        frames=[pd.read_parquet(p['path']) for p in fingerprints]
        df=pd.concat(frames,ignore_index=True)
        if set(df.source_scenario)!=set(SOURCES) or df.record_id.duplicated().any():raise ValueError('Source roster/record IDs invalid')
        if not df.y.isin([0,1]).all():raise ValueError('Binary source labels required')
        df['allocation_group']=[group_id(s,k) for s,k in zip(df.source_scenario,df.record_key)]
        role_map={g:allocation(g) for g in df.allocation_group.unique()}
        df['role']=df.allocation_group.map(role_map)
        for c in CORE+EXTRA:
            if c in CATEGORICAL:df[c]=df[c].astype(str)
            else:
                df[c]=pd.to_numeric(df[c],errors='raise')
                if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise ValueError('Invalid numeric predictor: '+c)
        if df.groupby('allocation_group').role.nunique().max()!=1:raise ValueError('Group split across allocations')
        df.to_parquet(data_path,index=False)
        df.groupby(['source_scenario','role','y']).size().rename('records').reset_index().to_csv(OUT/'allocation_counts.csv',index=False)
        df[['record_id','source_scenario','allocation_group','role']].to_csv(OUT/'record_role_manifest.csv',index=False)
        patterns=pd.util.hash_pandas_object(df[CORE+EXTRA],index=False).to_numpy(np.uint64)
        comparisons=[]
        for left,right in combinations(ROLES,2):
            a=df.role.eq(left).to_numpy();b=df.role.eq(right).to_numpy()
            comparisons.append({'left':left,'right':right,
                'shared_record_ids':len(set(df.loc[a,'record_id'])&set(df.loc[b,'record_id'])),
                'shared_five_tuple_groups':len(set(df.loc[a,'allocation_group'])&set(df.loc[b,'allocation_group'])),
                'shared_feature_patterns_diagnostic':len(set(patterns[a])&set(patterns[b]))})
        pd.DataFrame(comparisons).to_csv(OUT/'allocation_overlap_audit.csv',index=False)
        if any(r['shared_record_ids'] or r['shared_five_tuple_groups'] for r in comparisons):raise ValueError('Allocation overlap detected')
        ar={'configuration_sha256':ch,'allocations_sha256':sha(data_path),
            'record_disjointness_verified':True,'directed_five_tuple_groups_disjoint':True,
            'feature_patterns_may_repeat':True,'physical_device_independence_certified':False,
            'historical_model_training_disjointness_proved':False,'new_target_records_read':False}
        allocation_receipt.write_text(json.dumps(ar,indent=2))
    rows,done=summarize_jobs(ch)
    jobs=[(held,seed,schema) for held in SOURCES for seed in SEEDS for schema in SCHEMAS]
    pending=[job for job in jobs if f'{job[0]}__seed{job[1]}__{job[2]}' not in done]
    if not pending:
        print('ALL 18 SOURCE-FOLD JOBS TECHNICALLY COMPLETE. No efficacy/novelty claim is inferred.')
        print(pd.DataFrame(rows).query("population == 'held_source' and model == 'PRIMARY'").to_string(index=False))
        return str(OUT)
    held,seed,schema=pending[0];job_id=f'{held}__seed{seed}__{schema}'
    jobdir=OUT/'jobs'/job_id;jobdir.mkdir(exist_ok=True)
    train_pos=np.flatnonzero((df.source_scenario.ne(held)&df.role.eq('train')).to_numpy())
    reference_pos=np.flatnonzero((df.source_scenario.ne(held)&df.role.eq('competence_reference')).to_numpy())
    validation_pos=np.flatnonzero((df.source_scenario.ne(held)&df.role.eq('source_validation')).to_numpy())
    held_pos=np.flatnonzero(df.source_scenario.eq(held).to_numpy())
    train=df.iloc[train_pos];reference=df.iloc[reference_pos]
    if len(train)<256 or set(train.y.unique())!={0,1}:raise RuntimeError('Insufficient two-class training allocation; do not alter buckets after results')
    if len(reference)<128 or set(reference.y.unique())!={0,1}:raise RuntimeError('Insufficient two-class competence allocation; inspect group structure before proceeding')
    views={k:list(v) for k,v in VIEWS.items()}
    if schema=='expanded13':views['context']+=EXTRA
    model_columns={'PRIMARY':SCHEMAS[schema],**views,
                   'PROTOCOL_ONLY':['proto'],'PORT_ONLY':['id.resp_p'],'PROTOCOL_PORT':['proto','id.resp_p']}
    metrics_rows=[];unknown_rows=[];predictions={'held_source_position':held_pos,'reference_position':reference_pos,
        'source_validation_position':validation_pos,'held_source_labels':df.iloc[held_pos].y.to_numpy(int),
        'reference_labels':reference.y.to_numpy(int),'source_validation_labels':df.iloc[validation_pos].y.to_numpy(int)}
    held_decisions={}
    print('RUNNING ONE SOURCE-FOLD JOB:',job_id,flush=True)
    with threadpool_limits(limits=2):
        for name,columns in model_columns.items():
            model_path=jobdir/(name+'.joblib');meta_path=jobdir/(name+'_model_receipt.json')
            if meta_path.exists():
                mr=json.loads(meta_path.read_text())
                if mr.get('configuration_sha256')!=ch or mr.get('columns')!=columns or sha(model_path)!=mr['model_sha256']:
                    raise ValueError('Model checkpoint mismatch: '+name)
                model=joblib.load(model_path);fit_seconds=mr['fit_seconds'];reused=True
            else:
                model=model_pipeline(columns,seed);t=time.perf_counter();model.fit(train[columns],train.y)
                fit_seconds=time.perf_counter()-t;reused=False
                temp=model_path.with_suffix('.joblib.partial');joblib.dump(model,temp);temp.replace(model_path)
                mr={'configuration_sha256':ch,'columns':columns,'model_sha256':sha(model_path),'fit_seconds':fit_seconds,
                    'held_source':held,'seed':seed,'schema':schema,'model':name,'training_records':len(train)}
                meta_path.write_text(json.dumps(mr,indent=2))
            if not np.array_equal(model.classes_,[0,1]):raise ValueError('Model class order invalid')
            reference_p=model.predict_proba(reference[columns])[:,1]
            benign_p=np.sort(reference_p[reference.y.to_numpy()==0]);budget=int(np.floor(.05*len(benign_p)))
            threshold=float(benign_p[max(0,len(benign_p)-budget-1)])
            for population,pos in [('reference',reference_pos),('source_validation',validation_pos),('held_source',held_pos)]:
                if not len(pos):continue
                frame=df.iloc[pos];p=np.asarray(model.predict_proba(frame[columns])[:,1],float);y=frame.y.to_numpy(int)
                if not np.isfinite(p).all() or ((p<0)|(p>1)).any():raise ValueError('Invalid prediction probabilities')
                predictions[name+'_'+population+'_probability']=p
                if population=='held_source':held_decisions[name]=(p>=.5).astype(int)
                for rule,cut,decision in [('fixed_0.5',.5,p>=.5),('source_FPR5_strict',threshold,p>threshold)]:
                    metrics_rows.append({'job_id':job_id,'held_source':held,'seed':seed,'schema':schema,'model':name,
                        'population':population,'decision_rule':rule,'threshold':cut,'fit_seconds':fit_seconds,**metric(y,decision.astype(int),p)})
                for c in columns:
                    if c in CATEGORICAL:
                        unknown_rows.append({'job_id':job_id,'model':name,'population':population,'feature':c,
                                             'unknown_fraction':float((~frame[c].isin(set(train[c]))).mean())})
            print(name,': checkpoint reused' if reused else ': fitted',f'({fit_seconds:.2f}s)',flush=True)
            del model;gc.collect()
    joint=[];y=df.iloc[held_pos].y.to_numpy(int)
    for left,right in combinations(['PRIMARY']+list(views),2):
        a=held_decisions[left]!=y;b=held_decisions[right]!=y
        corr=float(np.corrcoef(a.astype(float),b.astype(float))[0,1]) if a.std()>0 and b.std()>0 else None
        joint.append({'left':left,'right':right,'disagreement':float(np.mean(held_decisions[left]!=held_decisions[right])),
                      'joint_error':float(np.mean(a&b)),'error_correlation':corr})
    table=pd.DataFrame(metrics_rows);mp=jobdir/'metrics.csv';table.to_csv(mp,index=False)
    pd.DataFrame(unknown_rows).to_csv(jobdir/'unknown_categories.csv',index=False)
    pd.DataFrame(joint).to_csv(jobdir/'joint_errors.csv',index=False)
    pp=jobdir/'predictions.npz';temp=jobdir/'predictions.partial.npz';np.savez_compressed(temp,**predictions);temp.replace(pp)
    completion={'status':'SOURCE_FOLD_TECHNICALLY_COMPLETE','configuration_sha256':ch,'job_id':job_id,
        'metrics_file':str(mp),'metrics_sha256':sha(mp),'predictions_file':str(pp),'predictions_sha256':sha(pp),
        'model_count':len(model_columns),'train_records':len(train),'reference_records':len(reference),
        'held_source_records':len(held_pos),'held_source_used_for_training':False,
        'elapsed_seconds':round(time.monotonic()-started,2),'new_research_targets_read':False,
        'source_model_selection_completed':False,'scientific_success_declared':False}
    (jobdir/'completion.json').write_text(json.dumps(completion,indent=2))
    rows,done=summarize_jobs(ch)
    progress={'output_directory':str(OUT),'configuration_sha256':ch,'completed_jobs':len(done),
        'expected_jobs':len(jobs),'remaining_jobs':len(jobs)-len(done),'last_completed_job':job_id,
        'phase':'SOURCE/DESIGN E2/E3','no_heldout_research_target_predictions':True,
        'next_step':'Run this same cell for the next declared job; do not alter settings'}
    (OUT/'progress.json').write_text(json.dumps(progress,indent=2))
    print('\n=== E1-B ALLOCATION COUNTS ===\n'+pd.read_csv(OUT/'allocation_counts.csv').to_string(index=False))
    print('\n=== E2/E3 PROGRESS ===\n'+json.dumps(progress,indent=2))
    print('\n=== LAST JOB HELD-SOURCE METRICS ===\n'+table[table.population.eq('held_source')].round(6).to_string(index=False))
    print('\n=== LAST JOB JOINT ERRORS ===\n'+pd.DataFrame(joint).round(6).to_string(index=False))
    print('\n=== LAST JOB UNKNOWN CATEGORIES ===\n'+pd.DataFrame(unknown_rows).query("population == 'held_source'").round(6).to_string(index=False))
    return str(OUT)

E2E3_OUTPUT_DIRECTORY=main()
