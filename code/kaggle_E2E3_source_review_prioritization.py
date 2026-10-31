import json,hashlib,math,time
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
import pandas as pd

RUN=Path('/kaggle/working/CLOSING_E2E3_DRIVER_v2_48579ceb7266')
DIAG=Path('/kaggle/working/CLOSING_SOURCE_DIAGNOSTICS_20261015T094802565839Z')
EXPECTED_CONFIG='48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea'
MODELS=['PRIMARY','originator','responder','timing','context']
BUDGETS=[0.05,0.10]
WINDOW=128
MIN_MALICIOUS_PER_WINDOW=20

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()

def rank_metric(y,d,score):
    positive=(np.asarray(y)==1)
    score=np.asarray(score,float)
    good=positive & (np.asarray(d)==0)
    return good,positive

def recall_at_budget(score,eligible,numerator,n,rate):
    eligible=np.asarray(eligible,bool); numerator=np.asarray(numerator,bool)
    ids=np.flatnonzero(eligible)
    k=max(1,int(math.floor(rate*n)))
    k=min(k,len(ids))
    if k==0:return {'reviewed':0,'recovered':0,'recall':np.nan,'precision':np.nan,'budget_shortfall':n}
    order=ids[np.argsort(-np.asarray(score)[ids],kind='stable')[:k]]
    recovered=int(numerator[order].sum())
    total=int(numerator[eligible].sum())
    return {'reviewed':k,'recovered':recovered,
            'recall':recovered/total if total else np.nan,
            'precision':recovered/k,'budget_shortfall':n-k}

def paired_random_baseline(eligible,numerator,n,rate,repeats,seed):
    eligible=np.asarray(eligible,bool); numerator=np.asarray(numerator,bool)
    ids=np.flatnonzero(eligible);k=min(max(1,int(math.floor(rate*n))),len(ids))
    if not len(ids) or not k:return np.nan,np.nan,np.nan
    total=int(numerator[eligible].sum())
    rng=np.random.default_rng(seed);rec=[]
    for _ in range(repeats):
        chosen=rng.choice(ids,size=k,replace=False)
        got=int(numerator[chosen].sum())
        rec.append(got/total if total else np.nan)
    return float(np.nanmean(rec)),float(np.nanquantile(rec,.025)),float(np.nanquantile(rec,.975))

def main():
    start=time.monotonic()
    pointer=Path('/kaggle/working/CLOSING_CURRENT_SOURCE_DIAGNOSTIC.json')
    if not pointer.is_file():raise FileNotFoundError(pointer)
    diagdir=Path(json.loads(pointer.read_text())['directory'])
    source_receipt=json.loads((diagdir/'receipt.json').read_text())
    if source_receipt['status']!='SOURCE_DIAGNOSTIC_INPUTS_READY':raise RuntimeError('Source prediction cache is not validated')
    driver_config=json.loads((RUN/'configuration.json').read_text())
    if driver_config.get('prior_driver_equivalence_claimed') is not False:raise ValueError('Unexpected driver-equivalence declaration')
    if driver_config.get('source_allocation_path') and sha(driver_config['source_allocation_path'])!=driver_config['source_allocation_sha256']:
        raise ValueError('Source allocation hash mismatch')
    allocation_path=Path(driver_config['allocation_path'])
    if sha(allocation_path)!=driver_config['allocation_sha256']:raise ValueError('Allocation hash mismatch')
    allocation=pd.read_parquet(allocation_path);allocation['record_id']=allocation.record_id.astype(str)
    if allocation.record_id.duplicated().any():raise ValueError('Duplicate accepted allocation IDs')
    cache_path=diagdir/'source_validation_cache.npz'
    cache_hash=sha(cache_path)
    data_rows=[];signal_rows=[];window_rows=[];summary_rows=[];errors=[]
    run_dir=Path('/kaggle/working')/('CLOSING_REVIEW_BUDGET_WINDOWS_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    run_dir.mkdir(exist_ok=False)
    expected_keys=[]
    for schema in driver_config['schemas']:
        for capture in driver_config['sources']:
            for seed in driver_config['seeds']:
                key=f"{schema.replace('_','').lower()}__{capture.replace('-','').lower()}__{seed}"
                expected_keys.append(key)
    with np.load(cache_path,allow_pickle=False) as saved:
        if set(saved.files)!={x+s for x in expected_keys for s in ['__record_id','__y']+[f'__p_{m}' for m in MODELS]}:
            raise ValueError('Prediction-cache key set differs from expected schemas/models')
        for schema in driver_config['schemas']:
            for capture in driver_config['sources']:
                for seed in driver_config['seeds']:
                    key=f"{schema.replace('_','').lower()}__{capture.replace('-','').lower()}__{seed}"
                    ids=saved[key+'__record_id'].astype(str);y=saved[key+'__y'].astype(int)
                    if len(set(ids))!=len(ids):raise ValueError('Duplicate prediction record IDs: '+key)
                    pred={m:np.asarray(saved[key+'__p_'+m],float) for m in MODELS}
                    if any(a.shape!=(len(y),) or not np.isfinite(a).all() or ((a<0)|(a>1)).any() for a in pred.values()):
                        raise ValueError('Invalid cached probability vector: '+key)
                    meta=allocation[['record_id','source_scenario','role','y','proto']].copy()
                    paired=pd.DataFrame({'record_id':ids,'cache_y':y}).merge(meta,on='record_id',how='left',validate='one_to_one')
                    if paired.source_scenario.isna().any() or not np.array_equal(paired.cache_y.to_numpy(),paired.y.to_numpy(int)):
                        raise ValueError('Prediction/accepted-allocation alignment failure: '+key)
                    if not paired.source_scenario.eq(capture).all() or not paired.role.eq('source_validation').all():
                        raise ValueError('Cache includes records outside this held-capture validation allocation: '+key)
                    orderdf=allocation.set_index('record_id').loc[ids]
                    if not np.array_equal(orderdf.record_id.astype(str).to_numpy(),ids):raise ValueError('Record ordering mismatch')
                    timestamp_column=driver_config.get('timestamp_column')
                    time_source='no_timestamp_in_prediction_cache'
                    if timestamp_column and timestamp_column in orderdf.columns:
                        ts=pd.to_numeric(orderdf[timestamp_column],errors='coerce').to_numpy(float)
                        if np.isfinite(ts).all() and len(np.unique(ts))>1:
                            order=np.lexsort((ids,ts));time_source='timestamp_order'
                        else:order=np.arange(len(ids));time_source='timestamp_missing_or_constant'
                    else:order=np.arange(len(ids))
                    indices=[order[i:i+WINDOW] for i in range(0,len(order)-WINDOW+1,WINDOW)]
                    dropped=len(order)-sum(map(len,indices))
                    primary=(pred['PRIMARY']>=.5).astype(int)
                    wrong=(primary!=y)
                    false_negative=(primary==0)&(y==1)
                    false_positive=(primary==1)&(y==0)
                    other={m:(pred[m]>=.5).astype(int) for m in MODELS[1:]}
                    viewstack=np.vstack([other[m] for m in MODELS[1:]])
                    viewdis=np.std(viewstack.astype(float),axis=0)
                    confidence=np.maximum(pred['PRIMARY'],1-pred['PRIMARY'])
                    margin=-confidence
                    # Entropy is label-free, higher means more uncertainty.
                    clipped=np.clip(pred['PRIMARY'],1e-12,1-1e-12)
                    entropy=-(clipped*np.log(clipped)+(1-clipped)*np.log(1-clipped))
                    scores={'primary_low_confidence':-confidence,
                            'primary_entropy':entropy,
                            'view_disagreement':viewdis,
                            'primary_view_disagreement':np.mean(viewstack!=primary[None,:],axis=0),
                            'primary_margin_uncertainty':margin,
                            'random':np.random.default_rng(100000+seed).random(len(y))}
                    for window_id,ix in enumerate(indices):
                        nmal=int((y[ix]==1).sum());nben=int((y[ix]==0).sum())
                        assessable=nmal>=MIN_MALICIOUS_PER_WINDOW
                        window_fn=int(false_negative[ix].sum());window_fp=int(false_positive[ix].sum())
                        window_rows.append({'schema':schema,'held_capture':capture,'seed':seed,'window':window_id,
                            'time_order':time_source,'records':len(ix),'malicious':nmal,'benign':nben,
                            'assessable_for_recall':assessable,'false_negatives':window_fn,'false_positives':window_fp,
                            'malicious_recall':float(1-window_fn/nmal) if nmal else np.nan,
                            'benign_fpr':float(window_fp/nben) if nben else np.nan,
                            'primary_accuracy':float(np.mean(primary[ix]==y[ix]))})
                        status={'no_malicious_records':nmal==0,'damaging_fn_at_least_5pp': bool(nmal>0 and window_fn/nmal>=.05),
                                'false_alarm_fpr_at_least_5pp':bool(nben>0 and window_fp/nben>=.05)}
                        for endpoint,flag,eligible in [
                            ('missed_attack_recall',status['damaging_fn_at_least_5pp'],assessable),
                            ('benign_false_alarm',status['false_alarm_fpr_at_least_5pp'],nben>=MIN_MALICIOUS_PER_WINDOW)]:
                            signal_rows.append({'schema':schema,'held_capture':capture,'seed':seed,'window':window_id,
                                'endpoint':endpoint,'positive_event':flag,'eligible':bool(eligible),
                                **{name:float(np.mean(score[ix])) for name,score in scores.items()}})
                        data_rows.append({'schema':schema,'held_capture':capture,'seed':seed,'window':window_id,
                            'time_order':time_source,'primary_errors':int(wrong[ix].sum()),'false_negatives':window_fn,
                            'false_positives':window_fp,'malicious':nmal,'benign':nben})
                    summary_rows.append({'schema':schema,'held_capture':capture,'seed':seed,'rows':len(y),
                        'windows':len(indices),'dropped_incomplete_records':dropped,'time_order':time_source,
                        'false_negatives_total':int(false_negative.sum()),'false_positives_total':int(false_positive.sum()),
                        'primary_accuracy':float(np.mean(primary==y)),
                        'primary_recall':float(primary[y==1].mean()) if (y==1).any() else np.nan,
                        'primary_benign_fpr':float(primary[y==0].mean()) if (y==0).any() else np.nan,
                        'primary_prediction_positive_rate':float(primary.mean()),
                        'view_majority_error':float(np.mean(np.sum(viewstack,axis=0)>=3) if False else np.nan)})
                    print(f'WINDOWS BUILT {schema} {capture} seed={seed}: {len(indices)}; time={time_source}; dropped={dropped}',flush=True)
    win=pd.DataFrame(window_rows);sig=pd.DataFrame(signal_rows)
    win.to_csv(run_dir/'window_security_outcomes.csv',index=False)
    sig.to_csv(run_dir/'window_review_signals.csv',index=False)
    pd.DataFrame(summary_rows).to_csv(run_dir/'fold_security_summary.csv',index=False)
    pd.DataFrame(data_rows).to_csv(run_dir/'fold_window_counts.csv',index=False)
    ranking=[];aucrows=[];randomrows=[]
    for keys,g in sig.groupby(['schema','held_capture','seed','endpoint']):
        schema,capture,seed,endpoint=keys
        eligible=g.eligible.to_numpy(bool); positive=g.positive_event.to_numpy(bool); n=len(g)
        if not eligible.any():
            continue
        target_count=int((positive&eligible).sum())
        for score_name in [c for c in g.columns if c not in ['schema','held_capture','seed','window','endpoint','positive_event','eligible']]:
            s=g[score_name].to_numpy(float)
            # For benign-FPR events, prioritize high predicted benign risk:
            # primary predicted-malicious probability is the score.
            # For FN events, prioritize high uncertainty/disagreement.
            if endpoint=='benign_false_alarm':
                if score_name=='primary_low_confidence': s=-s
                elif score_name=='primary_entropy': s=-s
                elif score_name=='primary_margin_uncertainty': s=-s
                elif score_name=='primary_view_disagreement': s=-s
                elif score_name=='view_disagreement': s=-s
                # All these reversed uncertainty scores are only simple alarm-risk
                # baselines; probability-positive ranking is added separately below.
            if endpoint=='benign_false_alarm' and score_name=='primary_low_confidence':
                # use the actual positive-probability rank: high p(primary=attack)
                continue
            for budget in BUDGETS:
                result=recall_at_budget(s,eligible,positive,n,budget)
                randmean,randlo,randhi=paired_random_baseline(eligible,positive,n,budget,2000,314159+seed)
                ranking.append({'schema':schema,'held_capture':capture,'seed':seed,'endpoint':endpoint,
                    'signal':score_name,'review_budget':budget,'eligible_windows':int(eligible.sum()),
                    'positive_windows':target_count,**result,'random_recall_mean':randmean,
                    'random_recall_q025':randlo,'random_recall_q975':randhi})
            if eligible.sum()>=5 and len(set(positive[eligible]))==2:
                aucrows.append({'schema':schema,'held_capture':capture,'seed':seed,'endpoint':endpoint,
                    'signal':score_name,'auroc':float(roc_auc_score(positive[eligible],s[eligible])),
                    'eligible_windows':int(eligible.sum()),'positive_windows':target_count})
        if endpoint=='benign_false_alarm':
            ppos=np.array([
                float(np.mean([])) if False else 0.0
                for _ in range(n)
            ])
            # use source cached primary probabilities to calculate per-window primary positive rate
            cache=np.load(DIAG/'source_validation_cache.npz',allow_pickle=False)
            key=f"{schema.replace('_','').lower()}__{capture.replace('-','').lower()}__{seed}"
            pp=cache[key+'__p_PRIMARY'].astype(float);recid=cache[key+'__record_id'].astype(str)
            orderdf=allocation.set_index('record_id').loc[recid]
            if 'timestamp_column' in driver_config and driver_config['timestamp_column'] in orderdf.columns:
                ts=pd.to_numeric(orderdf[driver_config['timestamp_column']],errors='coerce').to_numpy(float)
                order=np.lexsort((recid,ts)) if np.isfinite(ts).all() and len(np.unique(ts))>1 else np.arange(len(pp))
            else: order=np.arange(len(pp))
            win_pp=[float(pp[order[i:i+WINDOW]].mean()) for i in range(0,len(order)-WINDOW+1,WINDOW)]
            good=g.eligible.to_numpy(bool); yevent=g.positive_event.to_numpy(bool)
            for budget in BUDGETS:
                res=recall_at_budget(win_pp,good,yevent,len(g),budget)
                randomrows.append({'schema':schema,'held_capture':capture,'seed':seed,'endpoint':endpoint,
                    'signal':'primary_attack_rate','review_budget':budget,'eligible_windows':int(good.sum()),
                    'positive_windows':int((yevent&good).sum()),**res})
            if good.sum()>=5 and len(set(yevent[good]))==2:
                aucrows.append({'schema':schema,'held_capture':capture,'seed':seed,'endpoint':endpoint,
                    'signal':'primary_attack_rate','auroc':float(roc_auc_score(yevent[good],np.asarray(win_pp)[good])),
                    'eligible_windows':int(good.sum()),'positive_windows':int((yevent&good).sum())})
    rank=pd.DataFrame(ranking);auc=pd.DataFrame(aucrows);prank=pd.DataFrame(randomrows)
    rank.to_csv(run_dir/'review_budget_results.csv',index=False)
    auc.to_csv(run_dir/'review_signal_auroc.csv',index=False)
    prank.to_csv(run_dir/'primary_positive_rate_review_results.csv',index=False)
    receipt={'stage':'secondary source-only review-prioritization diagnostic',
        'status':'COMPLETED_SOURCE_ONLY_DIAGNOSTIC','output_directory':str(run_dir),
        'configuration_sha256':CFG_SHA,'source_validation_cache_sha256':cache_hash,
        'source_capture_count':3,'schema_count':2,'model_seed_count':3,'windows':len(win),
        'review_budgets':BUDGETS,'minimum_malicious_per_assessable_window':MIN_MALICIOUS_PER_WINDOW,
        'target_records_read':False,'target_labels_used_for_ranking':False,'new_models_trained':False,
        'heldout_confirmation':False,'E4_to_E7_authorized':False,
        'notes':['Windows are sequential blocks only if source timestamps exist and vary; otherwise order is record-ID order.',
                 'These are source-validation diagnostics; not independent held-out performance.',
                 'Benign false-alarm endpoint uses 128-record windows and minimum benign support.',
                 'AUROC is descriptive by capture/seed; do not pool windows as independent deployments.'],
        'elapsed_seconds':round(time.monotonic()-start,2)}
    (run_dir/'receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\n=== WINDOW REVIEW DIAGNOSTIC RECEIPT ===\n'+json.dumps(receipt,indent=2))
    if len(rank):
        print('\n=== PER-CAPTURE/SEED RECALL AT REVIEW BUDGET ===\n'+rank.groupby(['schema','held_capture','endpoint','signal','review_budget']).agg(mean_recall=('recall','mean'),mean_precision=('precision','mean'),eligible=('eligible_windows','mean'),positives=('positive_windows','mean')).round(4).to_string())
    if len(auc):print('\n=== PER-CAPTURE/SEED AUROC ===\n'+auc.groupby(['schema','held_capture','endpoint','signal']).auroc.mean().round(4).to_string())
    if len(prank):print('\n=== PRIMARY POSITIVE-RATE BASELINE ===\n'+prank.groupby(['schema','held_capture','review_budget']).agg(recall=('recall','mean'),precision=('precision','mean')).round(4).to_string())
    print('\n=== SECURITY OUTCOMES BY FOLD ===\n'+pd.DataFrame(summary_rows).to_string(index=False))
    print('\nOUTPUT_DIRECTORY:',run_dir)
    return str(run_dir)

SOURCE_WINDOW_REVIEW_DIRECTORY=main()
