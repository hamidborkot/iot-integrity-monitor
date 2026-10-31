# FINAL v2 — FIVE MODEL SEEDS, not five-fold evaluation: controlled source split build.
# Uses the source panel actually listed in batch5; no phantom five-fold artifacts.
# Builds true endpoint/protocol groups from original published logs.
# Two fixed policies share one fixed group-disjoint outer validation set.
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from decimal import Decimal, ROUND_HALF_EVEN
import gzip, hashlib, json, shutil, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from threadpoolctl import threadpool_limits

PRIMARY=Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')
RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
W=Path('/kaggle/working')
SEEDS=[8101,8102,8103,8104,8105]
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SOURCES={f'CTU-IoT-Malware-Capture-{k}-1' for k in [1,3,8]}
OUT=W/('CONTROLLED_FIVE_SEED_SOURCE_SPLIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(parents=True,exist_ok=False)
R={'status':'STARTED','model_seeds':SEEDS,'source_fold_count_claimed':False,
   'new_primary_model_fits':0,'new_calibrator_fits':0,'checkpoint_pairs_reused':0,
   'new_PCAP_replays':0,'legacy_models_modified':False,'target_cohorts_changed':False,
   'target_evaluation_completed_by_this_batch':False,'independent_confirmation':False,
   'six_remaining_packet_captures_completed':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def sha_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def read_csv(path):
    with open(path,'rb') as f:compressed=f.read(2)==b'\x1f\x8b'
    return pd.read_csv(path,compression='gzip' if compressed else None,dtype=str,keep_default_na=False)
def norm(df):
    df=df.copy()
    if not set(F+['ks','y','source_scenario']).issubset(df.columns):raise Stop('Preserved source panel schema differs')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower();y=pd.to_numeric(df.y,errors='raise')
    if not y.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid labels/protocols')
    df['y']=y.astype(int)
    if set(df.source_scenario)!=SOURCES or df.duplicated(['source_scenario','ks']).any():raise Stop('Source role/key contract differs')
    return df

def semantic_hash(df):
    return hashlib.sha256(pd.util.hash_pandas_object(df[['source_scenario','ks','y']+F],index=False).to_numpy().tobytes()).hexdigest()
def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def logit(p):
    p=np.clip(p,1e-6,1-1e-6);return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def metrics(y,p):
    y=np.asarray(y,int);p=np.asarray(p,float)
    if set(y)!={0,1} or not np.isfinite(p).all():raise Stop('Validation/calibration lacks both classes or finite predictions')
    d=p>=.5;bins=np.minimum((p*10).astype(int),9);ece=0.
    for k in range(10):
        mask=bins==k
        if mask.any():ece+=float(mask.mean())*abs(float(p[mask].mean()-y[mask].mean()))
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
            'AUROC':float(roc_auc_score(y,p)),'malicious_recall':float(d[y==1].mean()),
            'benign_FPR':float(d[y==0].mean()),'Brier':float(np.mean((p-y)**2)),'ECE_10_bins':ece}

def log_rows(path):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):
                fields=line.strip().split()[1:]
                if 'label' not in fields:raise Stop('Original log has no explicit primary label')
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Original log header missing')
                v=line.rstrip().split()
                if len(v)!=len(fields):raise Stop('Original log row width differs')
                yield dict(zip(fields,v))

def native_key(row):
    values=[us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()]
    return hashlib.sha256(json.dumps(values,separators=(',',':')).encode()).hexdigest()
def legacy_keys(row):
    values=[us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()]
    return [sep.join(map(str,values)) for sep in ['|','::',',']]
def source_group(scenario,row):
    endpoints=sorted([(row['id.orig_h'],int(row['id.orig_p'])),(row['id.resp_h'],int(row['id.resp_p']))])
    return hashlib.sha256(json.dumps([scenario,endpoints,row['proto'].lower()],separators=(',',':')).encode()).hexdigest()

try:
    if not PRIMARY.is_dir() or not RAW.is_dir():raise Stop('Both batch5 and the original IoT-23 mounts are required')
    if shutil.disk_usage(W).free<1024**3:raise Stop('At least 1 GiB free is required')
    # These filenames are observed in the supplied inventory. CSV/GZ aliases
    # are decoded by content, not assumed to have identical compressed bytes.
    candidates=[]
    for root in sorted(PRIMARY.glob('FRESH_RAW_CAPTURE48_*')):
        for parent in [root,root/'fresh_capture48_small_results']:
            for name in ['fresh_source_panel.csv','fresh_source_panel.csv.gz']:
                p=parent/name
                if p.is_file():
                    df=norm(read_csv(p));candidates.append((p,df,semantic_hash(df)))
    if not candidates:raise Stop('The preserved fresh_source_panel.csv or .csv.gz listed in batch5 was not found')
    signatures={x[2] for x in candidates}
    if len(signatures)!=1:raise Stop('Distinct source panels were found; no outcome-based choice made')
    source_path,source,source_signature=min(candidates,key=lambda x:(len(x[0].parts),str(x[0])))
    print('[1/3] Recovering real network-group metadata for the preserved source rows.',flush=True)
    source=source.reset_index(drop=True)
    metadata={};log_manifest=[]
    for scenario in sorted(SOURCES):
        matches=[p for p in RAW.rglob('conn.log.labeled') if scenario in p.parts]
        if len(matches)!=1:raise Stop('Expected one original labelled source log for '+scenario)
        path=matches[0];subset=source[source.source_scenario.eq(scenario)].set_index('ks');wanted=set(subset.index)
        hashed=all(len(k)==64 and all(c in '0123456789abcdef' for c in k.lower()) for k in wanted)
        for row in log_rows(path):
            try:
                possible=[native_key(row)] if hashed else legacy_keys(row)
                hits=[k for k in possible if k in wanted]
                if not hits:continue
                if len(hits)!=1:raise Stop('Ambiguous original-key serialization')
                k=hits[0];ref=subset.loc[k];label=row['label'].lower()
                if label not in ['benign','malicious'] or int(label=='malicious')!=int(ref.y):raise Stop('Published/source label disagreement')
                values=[0. if row[c] in ['-',''] else float(row[c]) for c in F[:-1]]
                if row['proto'].lower()!=ref.proto or not np.allclose(values,ref[F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9):raise Stop('Published/source stable-feature disagreement')
                g=source_group(scenario,row);identity=(scenario,k)
                if identity in metadata and metadata[identity]['source_group']!=g:raise Stop('Conflicting source group metadata')
                metadata[identity]={'source_group':g,'orig_h':row['id.orig_h'],'orig_p':row['id.orig_p'],
                                    'resp_h':row['id.resp_h'],'resp_p':row['id.resp_p']}
            except (ValueError,KeyError):continue
        found=sum((scenario,k) in metadata for k in wanted)
        log_manifest.append({'scenario':scenario,'published_log':str(path),'log_sha256':sha_file(path),'wanted_rows':len(wanted),'matched_rows':found})
        print(scenario,':',found,'/',len(wanted),'source rows linked',flush=True)
        if found!=len(wanted):raise Stop('Not every preserved source row has verified original metadata')
    source['source_group']=[metadata[(s,k)]['source_group'] for s,k in zip(source.source_scenario,source.ks)]
    for field in ['orig_h','orig_p','resp_h','resp_p']:source[field]=[metadata[(s,k)][field] for s,k in zip(source.source_scenario,source.ks)]
    groups=source.source_group.to_numpy();indices=np.arange(len(source));strata=(source.source_scenario+'|'+source.y.astype(str)).to_numpy()
    # One newly declared fixed outer split; not a claim to reproduce an
    # unavailable historical five-fold split.
    if len(set(groups))<10:raise Stop('Too few actual source groups for this control')
    development,validation=next(GroupShuffleSplit(n_splits=1,test_size=.2,random_state=94701).split(indices,source.y,groups))
    development=np.sort(development);validation=np.sort(validation)
    inner_fit,inner_cal=next(GroupShuffleSplit(n_splits=1,test_size=.25,random_state=94702).split(development,source.y.iloc[development],groups[development]))
    grouped={'model_fit':np.sort(development[inner_fit]),'calibration':np.sort(development[inner_cal]),'validation':validation}
    rng=np.random.default_rng(94703);rf=[];rc=[]
    for stratum in sorted(set(strata[development])):
        pool=rng.permutation(development[strata[development]==stratum]);nfit=int((strata[grouped['model_fit']]==stratum).sum())
        rf.extend(pool[:nfit]);rc.extend(pool[nfit:])
    row={'model_fit':np.sort(np.asarray(rf,int)),'calibration':np.sort(np.asarray(rc,int)),'validation':validation.copy()}
    roles={'GROUP_DISJOINT':grouped,'ROW_FIT_CAL_CONTROL':row};audit=[];allocation=[]
    for policy,rr in roles.items():
        if set(rr['model_fit'])&set(rr['calibration']) or set(np.concatenate(list(rr.values())))!=set(indices):raise Stop('Record allocation is not a partition')
        gg={name:set(groups[ii]) for name,ii in rr.items()}
        if gg['validation']&(gg['model_fit']|gg['calibration']):raise Stop('Outer validation group leakage')
        if policy=='GROUP_DISJOINT' and gg['model_fit']&gg['calibration']:raise Stop('Grouped fit/cal overlap')
        for role,ii in rr.items():
            if set(source.y.iloc[ii])!={0,1}:raise Stop('Fixed split has a single-class role; no alternate split silently tried')
            if not pd.Series(strata[ii]).value_counts().sort_index().equals(pd.Series(strata[grouped[role]]).value_counts().sort_index()):raise Stop('Class/capture budget mismatch')
            allocation.extend({'split_policy':policy,'role':role,'ks':source.iloc[i].ks,'source_scenario':source.iloc[i].source_scenario,'source_group':groups[i]} for i in ii)
        audit.append({'split_policy':policy,'fit_rows':len(rr['model_fit']),'calibration_rows':len(rr['calibration']),
            'validation_rows':len(rr['validation']),'fit_cal_shared_groups':len(gg['model_fit']&gg['calibration']),
            'validation_shared_groups':len(gg['validation']&(gg['model_fit']|gg['calibration'])),
            'outer_validation_identical':np.array_equal(rr['validation'],validation),'class_capture_budgets_matched':True})
    protocol={'model_seeds':SEEDS,'five_fold_evaluation':False,'one_fixed_outer_validation_set':True,
        'historical_outer_validation_reproduced':False,'legacy_three_seed_bank_unchanged':True,
        'group':'source scenario + unordered endpoint/port pair + protocol; no timestamp; recovered from original logs',
        'outer_split_seed':94701,'inner_group_split_seed':94702,'row_control_split_seed':94703,
        'outer_group_fraction':.2,'inner_calibration_group_fraction':.25,
        'fit_cal_class_capture_budgets_matched':True,'target_data_used_for_fitting':False,
        'HGB':{'max_iter':150,'learning_rate':.08,'early_stopping':False},
        'LR':{'C':1.,'solver':'lbfgs','max_iter':5000,'StandardScaler':'fit on primary training rows only'},
        'calibrator':{'type':'logistic regression on clipped logit of raw primary probability','C':1.,'max_iter':2000},
        'probability_clip':1e-6,'record_decision':'raw primary probability >= 0.5; calibration does not change decisions',
        'source_panel':str(source_path),'source_ordered_semantic_sha256':source_signature,
        'scope':'New controlled source-split sensitivity bank; source-group holdout is not unseen-capture confirmation'}
    js(OUT/'pre_outcome_protocol.json',protocol);js(OUT/'source_metadata_binding.json',log_manifest)
    source.to_csv(OUT/'source_panel_with_network_groups.csv.gz',index=False,compression='gzip')
    pd.DataFrame(allocation).to_csv(OUT/'fixed_source_memberships.csv.gz',index=False,compression='gzip')
    pd.DataFrame(audit).to_csv(OUT/'matched_allocation_audit.csv',index=False)
    print('\nFIXED SPLIT AUDIT\n'+pd.DataFrame(audit).to_string(index=False),flush=True)
    signature=hashlib.sha256(json.dumps(protocol,sort_keys=True).encode()).hexdigest()
    checkpoint_dir=OUT/'model_checkpoints';checkpoint_dir.mkdir()
    models={};calibrators={};results=[]
    with threadpool_limits(limits=2):
        for family in ['HGB','LR']:
            print('\nFIVE-SEED FAMILY:',family,flush=True)
            for seed in SEEDS:
                for policy,rr in roles.items():
                    fit=source.iloc[rr['model_fit']];cal=source.iloc[rr['calibration']];val=source.iloc[rr['validation']]
                    checkpoint_name=f'{family}_seed_{seed}_{policy}_{signature[:16]}.joblib';checkpoint=checkpoint_dir/checkpoint_name
                    candidates=[]
                    for root in [W,PRIMARY]:
                        for folder in root.glob('CONTROLLED_FIVE_SEED_SOURCE_SPLIT_*'):
                            p=folder/'model_checkpoints'/checkpoint_name
                            if p.is_file() and p!=checkpoint:candidates.append(p)
                    cached=None
                    for p in candidates:
                        candidate=joblib.load(p)
                        if candidate.get('input_signature')==signature:cached=candidate;break
                    if cached is not None:
                        model=cached['model'];calibrator=cached['calibrator'];R['checkpoint_pairs_reused']+=1
                        shutil.copyfile(p,checkpoint)
                    else:
                        model=(HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=seed) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,solver='lbfgs',max_iter=5000,random_state=seed))]))
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always',ConvergenceWarning);model.fit(encode(fit),fit.y)
                            if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed primary model failed to converge')
                        R['new_primary_model_fits']+=1
                        calibrator=LogisticRegression(C=1.,solver='lbfgs',max_iter=2000,random_state=seed)
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always',ConvergenceWarning);calibrator.fit(logit(model.predict_proba(encode(cal))[:,1]),cal.y)
                            if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed calibrator failed to converge')
                        R['new_calibrator_fits']+=1
                        joblib.dump({'model':model,'calibrator':calibrator,'input_signature':signature},checkpoint,compress=3)
                    pval=model.predict_proba(encode(val))[:,1];qval=calibrator.predict_proba(logit(pval))[:,1]
                    raw_metrics=metrics(val.y,pval);cal_metrics=metrics(val.y,qval)
                    rows={'family':family,'model_seed':seed,'split_policy':policy,'fit_rows':len(fit),'calibration_rows':len(cal),'validation_rows':len(val),
                          **raw_metrics,'calibrated_Brier':cal_metrics['Brier'],'calibrated_ECE_10_bins':cal_metrics['ECE_10_bins'],
                          'calibrated_probability_accuracy_not_used_as_detector_accuracy':True}
                    results.append(rows);models[(policy,family,seed)]=model;calibrators[(policy,family,seed)]=calibrator
                    pd.DataFrame(results).to_csv(OUT/'fixed_outer_validation_results.csv',index=False);js(OUT/'receipt.json',R)
                    print('Completed',family,seed,policy,'(restored)' if cached is not None else '(new source-only fit)',flush=True)
    result=pd.DataFrame(results)
    if len(result)!=20:raise Stop('Expected 5 seeds x 2 families x 2 split policies')
    joblib.dump({'models':models,'calibrators':calibrators,'model_seeds':SEEDS,'input_signature':signature,
                'protocol':protocol,'source_roles':roles},OUT/'five_seed_models_and_calibrators.joblib',compress=3)
    index=['family','model_seed'];left=result[result.split_policy.eq('GROUP_DISJOINT')].set_index(index)
    right=result[result.split_policy.eq('ROW_FIT_CAL_CONTROL')].set_index(index).reindex(left.index)
    paired=[]
    for (family,seed),x in left.iterrows():
        z=right.loc[(family,seed)]
        paired.append({'family':family,'model_seed':seed,**{metric+'_ROW_minus_GROUP':float(z[metric]-x[metric]) for metric in ['accuracy','balanced_accuracy','AUROC','Brier','ECE_10_bins','calibrated_Brier','calibrated_ECE_10_bins']}})
    pd.DataFrame(paired).to_csv(OUT/'paired_split_policy_changes.csv',index=False)
    for family,title in [('HGB','EXPERIMENT 1 — HGB, FIVE MODEL SEEDS'),('LR','EXPERIMENT 2 — LR, FIVE MODEL SEEDS')]:
        print('\n'+title+'\n'+result[result.family.eq(family)].to_string(index=False),flush=True)
    print('\nEXPERIMENT 3 — MATCHED SPLIT-POLICY AND CALIBRATION CONTRAST\n'+pd.DataFrame(paired).to_string(index=False),flush=True)
    R.update({'status':'CONTROLLED_FIVE_SEED_SOURCE_SPLIT_BANK_COMPLETE','model_seed_count':5,
        'primary_model_calibrator_pairs':len(models),'fixed_split_across_model_seeds':True,
        'source_group_metadata_verified':len(source),'group_validation_disjoint_for_both_policies':True,
        'matched_fit_cal_class_capture_composition':True,'identical_predictions_across_seeds_allowed':True,
        'legacy_and_new_banks_pooled':False,'source_validation_is_not_target_confirmation':True,
        'next_step':'Apply this completed bank to the existing fixed capture49 and capture48 record/UID cohorts; no PCAP replay or new target sampling.',
        'remaining_packet_captures':[7,9,33,36,39,43],
        'interpretation':'Five model random_state settings, one declared source split. Not five-fold evaluation, five independent datasets, or proof that leakage uniquely caused prior failures.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'PRIVATE_five_seed_source_split_bank.zip';entries=[]
    try:
        with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for p in OUT.rglob('*'):
                if p.is_file() and p!=package and p.suffix.lower()!='.zip':
                    rel=str(p.relative_to(OUT));z.write(p,arcname=rel);entries.append({'member':rel,'sha256':sha_file(p),'bytes':p.stat().st_size})
            z.writestr('ARCHIVE_FILE_MANIFEST.json',json.dumps(entries,indent=2))
        with zipfile.ZipFile(package) as z:
            for entry in entries:
                h=hashlib.sha256()
                with z.open(entry['member']) as f:
                    for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
                if h.hexdigest()!=entry['sha256']:raise Stop('Archive verification failed')
        R['private_archive']={'path':str(package),'bytes':package.stat().st_size,'sha256':sha_file(package),'members_verified':len(entries),'models_included':any(e['member'].endswith('.joblib') for e in entries),'final_release':False}
    except Exception as error:R['archive_error']=str(error)
    js(OUT/'receipt.json',R);print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
