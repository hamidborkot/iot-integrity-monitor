# Strengthening batch: five grouped source folds, two fixed target cohorts,
# and bounded metadata intake for the six remaining planned captures.
# Does not inflate deterministic initialization seeds into independent evidence.
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from contextlib import contextmanager
from collections import defaultdict, Counter
import gzip, hashlib, io, json, time, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedGroupKFold, GroupShuffleSplit
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from sklearn.exceptions import ConvergenceWarning
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');RAW=Path('/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full')
OUT=W/('GROUP_VALIDITY_AND_FIVE_FOLD_EXTENSION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SOURCE_IDS=[f'CTU-IoT-Malware-Capture-{k}-1' for k in [1,3,8]]
REMAINING=[7,9,33,36,39,43]
MODEL_SEED=8101;OUTER_SPLIT_SEED=94001;THRESHOLD=.05
R={'status':'STARTED','historical_results_or_models_overwritten':False,'new_model_fits':0,'new_PCAP_replays':0,
   'five_initialization_seeds_claimed':False,'distinct_target_capture_identities':2,'capture_independence_established':False,'independent_confirmation':False,
   'six_remaining_packet_evaluations_completed':False,'manuscript_submission_ready':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def sha_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def latest(pattern,status):
    found=[]
    for p in W.glob(pattern):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        try:r=json.loads(rp.read_text())
        except (ValueError,OSError):continue
        if r.get('status')==status:found.append((p,r))
    if not found:raise Stop('Required current stage missing: '+status)
    return max(found,key=lambda x:x[0].name)
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def blob(a):
    with opened(a) as f:b=f.read(128*1024**2+1)
    if len(b)>128*1024**2:raise Stop('Bounded metadata read exceeded')
    return b

def sha_asset(a):
    h=hashlib.sha256()
    with opened(a) as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def csv(a):
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded input too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def normalize(df,labelled=True):
    df=df.copy();need=F+(['ks','y'] if labelled else [])
    if not set(need).issubset(df.columns):raise Stop('Missing required input fields')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    if labelled:
        y=pd.to_numeric(df.y,errors='raise')
        if not y.isin([0,1]).all():raise Stop('Invalid label')
        df['y']=y.astype(int)
    return df

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)
def us(x):return int((Decimal(str(x))*1000000).to_integral_value(rounding=ROUND_HALF_EVEN))
def record_key(row):
    value=[us(row['ts']),row['id.orig_h'],int(row['id.orig_p']),row['id.resp_h'],int(row['id.resp_p']),row['proto'].lower()]
    return hashlib.sha256(json.dumps(value,separators=(',',':')).encode()).hexdigest()
def group_key(row,scenario):
    ep=sorted([(row['id.orig_h'],int(row['id.orig_p'])),(row['id.resp_h'],int(row['id.resp_p']))])
    return hashlib.sha256(json.dumps([scenario,ep,row['proto'].lower()],separators=(',',':')).encode()).hexdigest()
def log_rows(path):
    fields=None
    with open(path,encoding='utf-8') as f:
        for line in f:
            if line.startswith('#fields'):
                fields=line.strip().split()[1:]
                if 'label' not in fields:raise Stop('Published primary label field missing')
            elif not line.startswith('#') and line.strip():
                if fields is None:raise Stop('Published field header missing')
                v=line.rstrip().split()
                if len(v)!=len(fields):raise Stop('Published record width differs')
                yield dict(zip(fields,v))

def calibration_metrics(y,p):
    y=np.asarray(y,int);p=np.asarray(p,float);bins=np.minimum((p*10).astype(int),9);ece=0.
    for b in range(10):
        m=bins==b
        if m.any():ece+=float(m.mean())*abs(float(p[m].mean()-y[m].mean()))
    return {'Brier':float(np.mean((p-y)**2)),'ECE_10_bins':ece}
def logit(p):
    p=np.clip(p,1e-6,1-1e-6)
    return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def atc_policy(conf,correct):
    conf=np.asarray(conf,float);n=len(conf);k=int(np.asarray(correct,bool).sum())
    if k==0:return float(np.nextafter(conf.max(),np.inf)),0.
    threshold=float(np.sort(conf)[::-1][k-1]);above=int((conf>threshold).sum());ties=int((conf==threshold).sum())
    alpha=(k-above)/ties
    if not 0<=alpha<=1:raise Stop('ATC tie calculation inconsistent')
    return threshold,float(alpha)

def load_targets(a,base49,fresh48,merge48):
    manifest=json.loads((a/'input_manifest.json').read_text());clean49=normalize(csv(manifest['clean']))
    if len(clean49)!=1024 or clean49.ks.duplicated().any():raise Stop('Invalid fixed Capture-49 cohort')
    y49=clean49.y.to_numpy(int);mk49=list(clean49.loc[y49==1,'ks'])
    mapping0=pd.read_csv(base49/'clean_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'zeek_uid':str})
    own0=mapping0.groupby('original_ks').zeek_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
    if set(own0)!=set(mk49) or any(len(v)!=1 for v in own0.values()):raise Stop('Default clean Capture-49 membership differs')
    positive=clean49.set_index('ks').loc[mk49,F].copy();positive['uid']=[own0[k][0] for k in mk49];positive=positive.reset_index(drop=True)
    targets={'CAPTURE49_LEGACY_COHORT':{'clean':clean49,'states':{0:{'selected':clean49,'records':positive,'owners':own0,'pure':dict.fromkeys(positive.uid,True),'complete':dict.fromkeys(mk49,True)}}}}
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds'])
        if delay not in [1,10]:continue
        if sha_asset(cond['candidate_asset'])!=cond['candidate_sha256']:raise Stop('Capture-49 selected features changed')
        selected=normalize(csv(cond['candidate_asset'])).set_index('ks').loc[clean49.ks].reset_index()
        p=Path(cond['validated_result_directory']);rr=json.loads((p/'receipt.json').read_text())
        if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr['historical_transformed_pcap_sha256']!=cond['historical_transformed_pcap_sha256']:raise Stop('Capture-49 trace identity changed')
        mp=pd.read_csv(p/'transformed_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'transformed_uid':str})
        memberships=pd.read_csv(p/'test2_transformed_membership.csv',dtype={'ks':str})
        if not boolean(memberships.transformed_membership_validated).all():raise Stop('Capture-49 membership is not fully validated')
        owners=mp.groupby('original_ks').transformed_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        records=normalize(pd.read_csv(p/'transformed_selected_connection_records.csv.gz',dtype={'uid':str},keep_default_na=False),False)
        if set(owners)!=set(mk49) or records.uid.duplicated().any() or set(records.uid)!=set(mp.transformed_uid):raise Stop('Capture-49 UID coverage differs')
        targets['CAPTURE49_LEGACY_COHORT']['states'][delay]={'selected':selected,'records':records,'owners':owners,'pure':dict.fromkeys(records.uid,True),'complete':dict.fromkeys(mk49,True)}
    clean48=normalize(pd.read_csv(fresh48/'fresh_clean_target_sample.csv.gz',dtype={'ks':str},keep_default_na=False));mk48=list(clean48.loc[clean48.y.eq(1),'ks'])
    if len(clean48)!=1024 or clean48.ks.duplicated().any() or len(mk48)!=512:raise Stop('Invalid fixed Capture-48 cohort')
    target48={'clean':clean48,'states':{}}
    baseline=None
    for delay in [0,1,10]:
        selected=normalize(pd.read_csv(fresh48/f'selected_features_{delay}s.csv.gz',dtype={'ks':str},keep_default_na=False)).set_index('ks').loc[clean48.ks].reset_index()
        records=normalize(pd.read_csv(fresh48/f'descendant_features_{delay}s.csv.gz',dtype={'uid':str},keep_default_na=False),False)
        mp=pd.read_csv(fresh48/f'packet_uid_mapping_{delay}s.csv.gz',dtype={'original_ks':str,'uid':str})
        current=mp[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True)
        if delay==0:baseline=current
        elif not current.equals(baseline):raise Stop('Capture-48 original packet occurrences differ across conditions')
        purities=pd.read_csv(merge48/f'UID_contributions_{delay}s.csv',dtype={'uid':str})
        pure=dict(zip(purities.uid,boolean(purities.pure_selected_original_witness_record)))
        owners=mp.groupby('original_ks').uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        if set(owners)!=set(mk48) or records.uid.duplicated().any() or set(records.uid)!=set(mp.uid) or set(pure)!=set(records.uid):raise Stop('Capture-48 UID coverage differs')
        target48['states'][delay]={'selected':selected,'records':records,'owners':owners,'pure':pure,'complete':dict.fromkeys(mk48,True)}
    targets['CAPTURE48_FRESH_COHORT']=target48
    for name,t in targets.items():
        if set(t['states'])!={0,1,10}:raise Stop('Fixed common condition missing: '+name)
        for state in t['states'].values():
            if not np.array_equal(state['selected'].y.to_numpy(),t['clean'].y.to_numpy()):raise Stop('Fixed target labels differ')
    return targets

try:
    if not RAW.is_dir():raise Stop('Original IoT-23 mount missing')
    if __import__('shutil').disk_usage(W).free<1024**3:raise Stop('At least 1 GiB free required')
    fresh48,_=latest('FRESH_RAW_CAPTURE48_*','FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE')
    merge48,_=latest('CAPTURE48_MERGE_WITNESS_AUDIT_*','CAPTURE48_MERGE_AND_ALARM_WITNESS_AUDIT_COMPLETE')
    a,_=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    base49,_=latest('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    source=normalize(pd.read_csv(fresh48/'fresh_source_panel.csv.gz',dtype={'ks':str},keep_default_na=False))
    if set(source.source_scenario)!=set(SOURCE_IDS) or source.duplicated(['source_scenario','ks']).any():raise Stop('Unexpected fixed source panel')
    targets=load_targets(a,base49,fresh48,merge48)
    for t in targets.values():
        if set(source.ks)&set(t['clean'].ks):raise Stop('Source/target record IDs overlap')
    scenarios=SOURCE_IDS+[f'CTU-IoT-Malware-Capture-{k}-1' for k in REMAINING]
    assets={s:{'logs':[],'pcaps':[]} for s in scenarios}
    for p in RAW.rglob('*'):
        if not p.is_file():continue
        for scenario in assets:
            if scenario in p.parts:
                if p.name=='conn.log.labeled':assets[scenario]['logs'].append(p)
                elif p.suffix.lower()=='.pcap':assets[scenario]['pcaps'].append(p)
    js(OUT/'pre_outcome_protocol.json',{'status':'new exploratory group-validity extension; no historical result overwritten',
        'outer_source_folds':5,'outer_split_seed':OUTER_SPLIT_SEED,'model_initialization_seed_fixed':MODEL_SEED,
        'inner_split':'GroupShuffleSplit(test_size=0.2, random_state=94100+fold)',
        'three_disjoint_roles':['model_fit','probability_and_threshold_calibration','outer_source_validation'],
        'source_groups':'capture identity + unordered endpoint/port pair + protocol',
        'families':['HGB','LR'],'HGB':{'max_iter':150,'learning_rate':.08,'early_stopping':False},
        'LR':{'C':1.0,'solver':'lbfgs','max_iter':5000,'scale':'fit on model-fit rows only'},
        'Platt':{'C':1.0,'solver':'lbfgs','max_iter':2000,'input':'logit(probability clipped 1e-6)'},
        'target_cohorts':list(targets),'target_conditions':[0,1,10],'target_labels_used_for_fitting':False,
        'ATC_GE':'source-calibration Kth largest confidence, >=; ties explicitly reported',
        'ATC_fractional':'separate sensitivity using fractional expected acceptance of threshold ties; not a novelty claim',
        'calibration_matching_error_hidden':False,'warning_threshold':THRESHOLD,
        'remaining_capture_intake':'metadata only, maximum 2M records or 30 seconds per capture; no target predictions',
        'packet_replays':0,'independent_capture_CI_or_significance':False})
    print('[1/3] Recovering actual source five-tuple groups from original published logs.',flush=True)
    grouped={};source_index=source.set_index(['source_scenario','ks'])
    for scenario in SOURCE_IDS:
        if len(assets[scenario]['logs'])!=1:raise Stop('Expected one original labelled source log: '+scenario)
        needed=set(source.loc[source.source_scenario.eq(scenario),'ks']);found=set()
        for row in log_rows(assets[scenario]['logs'][0]):
            try:k=record_key(row)
            except (ValueError,KeyError):continue
            if k not in needed:continue
            if k in found:raise Stop('Duplicate original source key: '+scenario)
            published_label=row['label'].lower();expected=int(source_index.loc[(scenario,k),'y'])
            if published_label not in ['benign','malicious'] or int(published_label=='malicious')!=expected:raise Stop('Source primary label does not reproduce')
            values=[]
            for f in F[:-1]:
                x=row[f];values.append(0. if x in ['-',''] else float(x))
            if not np.allclose(values,source_index.loc[(scenario,k),F[:-1]].to_numpy(float),atol=1e-9,rtol=1e-9):raise Stop('Source predictor values do not reproduce')
            grouped[(scenario,k)]=group_key(row,scenario);found.add(k)
        if found!=needed:raise Stop('Some source original keys were not recovered: '+scenario)
        print('Recovered source:',scenario,len(found),flush=True)
    groups=np.array([grouped[(s,k)] for s,k in zip(source.source_scenario,source.ks)])
    source['source_group']=groups
    source.to_csv(OUT/'source_panel_with_groups.csv.gz',index=False,compression='gzip')
    outer=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=OUTER_SPLIT_SEED)
    splits=[];split_rows=[];membership_rows=[]
    for fold,(development,validation) in enumerate(outer.split(np.zeros(len(source)),source.y,groups),1):
        inner=GroupShuffleSplit(n_splits=1,test_size=.2,random_state=94100+fold)
        fit_local,cal_local=next(inner.split(development,source.y.iloc[development],groups[development]))
        fit=development[fit_local];cal=development[cal_local]
        sets=[set(groups[x]) for x in [fit,cal,validation]]
        disjoint=not (sets[0]&sets[1] or sets[0]&sets[2] or sets[1]&sets[2])
        feasible=disjoint and min(len(fit),len(cal),len(validation))>=128 and all(set(source.y.iloc[x])=={0,1} for x in [fit,cal,validation])
        split_rows.append({'fold':fold,'fit_rows':len(fit),'calibration_rows':len(cal),'validation_rows':len(validation),
                           'fit_groups':len(sets[0]),'calibration_groups':len(sets[1]),'validation_groups':len(sets[2]),'three_way_group_disjoint':disjoint,'feasible':feasible})
        for role,indices in [('model_fit',fit),('calibration',cal),('validation',validation)]:
            membership_rows.extend({'fold':fold,'ks':source.iloc[i].ks,'source_scenario':source.iloc[i].source_scenario,'source_group':groups[i],'role':role} for i in indices)
        splits.append((fold,fit,cal,validation))
    pd.DataFrame(split_rows).to_csv(OUT/'three_way_source_split_audit.csv',index=False)
    pd.DataFrame(membership_rows).to_csv(OUT/'five_fold_source_membership.csv.gz',index=False,compression='gzip')
    print('\nEXPERIMENT 1 — FIVE GROUP-SEPARATED SOURCE FOLDS\n'+pd.DataFrame(split_rows).to_string(index=False),flush=True)
    if not all(x['feasible'] for x in split_rows):raise Stop('A declared source split is infeasible. No split was redrawn to improve results.')
    validation_rows=[];target_rows=[];monitor_rows=[];cal_rows=[];fit_models={};calibrators={}
    print('[2/3] Fitting ten matched primary models; evaluating both fixed cohorts with the same models.',flush=True)
    with threadpool_limits(limits=2):
        for fold,fit_ids,cal_ids,val_ids in splits:
            fit=source.iloc[fit_ids];cal=source.iloc[cal_ids];val=source.iloc[val_ids]
            for family in ['HGB','LR']:
                model=(HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=MODEL_SEED) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,solver='lbfgs',max_iter=5000,random_state=MODEL_SEED))]))
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always',ConvergenceWarning);model.fit(encode(fit),fit.y)
                    if any(issubclass(x.category,ConvergenceWarning) for x in caught):raise Stop('Fixed model did not converge')
                R['new_model_fits']+=1
                pc=model.predict_proba(encode(cal))[:,1];dc=pc>=.5;cc=np.maximum(pc,1-pc)
                calibration_accuracy=float((dc==cal.y.to_numpy()).mean());calibration_confidence=float(cc.mean())
                threshold,alpha=atc_policy(cc,dc==cal.y.to_numpy())
                calibrator=LogisticRegression(C=1.,solver='lbfgs',max_iter=2000,random_state=94501)
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always',ConvergenceWarning);calibrator.fit(logit(pc),cal.y)
                    if any(issubclass(x.category,ConvergenceWarning) for x in caught):raise Stop('Fixed probability calibrator did not converge')
                fit_models[(fold,family)]=model;calibrators[(fold,family)]=calibrator
                fractional=(cc>threshold).astype(float)+alpha*(cc==threshold)
                cal_rows.append({'fold':fold,'family':family,'calibration_rows':len(cal),'accuracy':calibration_accuracy,'ATC_threshold':threshold,
                    'ATC_GE_source_error':float((cc>=threshold).mean()-calibration_accuracy),
                    'ATC_fractional_source_error':float(fractional.mean()-calibration_accuracy),'tie_count':int((cc==threshold).sum()),'tie_fraction':alpha})
                pv=model.predict_proba(encode(val))[:,1];qv=calibrator.predict_proba(logit(pv))[:,1];dv=pv>=.5;yv=val.y.to_numpy()
                validation_rows.append({'fold':fold,'family':family,'validation_rows':len(val),'accuracy':float(accuracy_score(yv,dv)),
                    'balanced_accuracy':float(balanced_accuracy_score(yv,dv)),'AUROC':float(roc_auc_score(yv,pv)),
                    'malicious_recall':float(dv[yv==1].mean()),'benign_FPR':float(dv[yv==0].mean()),
                    'raw_Brier':calibration_metrics(yv,pv)['Brier'],'calibrated_Brier':calibration_metrics(yv,qv)['Brier'],
                    'raw_ECE':calibration_metrics(yv,pv)['ECE_10_bins'],'calibrated_ECE':calibration_metrics(yv,qv)['ECE_10_bins']})
                for target_name,t in targets.items():
                    clean=t['clean'];yy=clean.y.to_numpy();mk=list(clean.loc[yy==1,'ks']);N=len(mk)
                    records=[]
                    for delay in [0,1,10]:
                        state=t['states'][delay];frame=state['selected'];cf=state['records']
                        p=model.predict_proba(encode(frame))[:,1];d=p>=.5;confidence=np.maximum(p,1-p);q=calibrator.predict_proba(logit(p))[:,1]
                        alarm=dict(zip(cf.uid,model.predict_proba(encode(cf))[:,1]>=.5));pos=neg=unknown=overlap=0
                        for k in mk:
                            uu=state['owners'][k];has=any(alarm[u] for u in uu)
                            witness=any(alarm[u] and state['pure'].get(u,False) for u in uu)
                            none=state['complete'][k] and not has
                            pos+=int(witness);neg+=int(none);unknown+=int(not witness and not none);overlap+=int(has)
                        truth=float((d==yy).mean())
                        estimates={'AC':float(confidence.mean()),'DoC':float(np.clip(calibration_accuracy+confidence.mean()-calibration_confidence,0,1)),
                            'ATC_SOURCE_GE':float((confidence>=threshold).mean()),
                            'ATC_FRACTIONAL_TIE_EXPECTATION':float(((confidence>threshold).astype(float)+alpha*(confidence==threshold)).mean()),
                            'CBPE_ACC_POINT':float(np.where(d,q,1-q).mean())}
                        records.append((delay,truth,pos/N,(pos+unknown)/N,estimates))
                        target_rows.append({'fold':fold,'family':family,'target':target_name,'delay_seconds':delay,
                            'record_accuracy':truth,'selected_record_recall':float(d[yy==1].mean()),'benign_FPR':float(d[yy==0].mean()),
                            'original_units':N,'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                            'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap})
                    baseline=records[0]
                    for delay,truth,lower,upper,estimates in records:
                        for method,value in estimates.items():
                            estimated_drop=baseline[4][method]-value;loss_lower=baseline[2]-upper;loss_upper=baseline[3]-lower
                            monitor_rows.append({'fold':fold,'family':family,'target':target_name,'delay_seconds':delay,'estimator':method,
                                'true_record_accuracy':truth,'accuracy_estimate':value,'current_absolute_error':abs(value-truth),
                                'current_overestimation':value-truth,'true_record_accuracy_drop':baseline[1]-truth,
                                'estimated_record_accuracy_drop':estimated_drop,'differential_error':abs(estimated_drop-(baseline[1]-truth)),
                                'unit_detection_drop_lower':loss_lower,'unit_detection_drop_upper':loss_upper,
                                'warning_at_fixed_5pp':estimated_drop>=THRESHOLD,
                                'missed_definite_unit_damage':bool(loss_lower>=THRESHOLD and estimated_drop<THRESHOLD)})
                pd.DataFrame(validation_rows).to_csv(OUT/'source_outer_validation.csv',index=False)
                pd.DataFrame(target_rows).to_csv(OUT/'five_fold_common_model_target_results.csv',index=False)
                pd.DataFrame(monitor_rows).to_csv(OUT/'five_fold_group_disjoint_monitor_results.csv',index=False)
                pd.DataFrame(cal_rows).to_csv(OUT/'source_ATC_tie_audit.csv',index=False)
                print('Completed fold/family:',fold,family,flush=True)
    joblib.dump({'models':fit_models,'calibrators':calibrators,'model_seed':MODEL_SEED,'outer_split_seed':OUTER_SPLIT_SEED},OUT/'five_fold_models_and_calibrators.joblib',compress=3)
    tv=pd.DataFrame(target_rows);mm=pd.DataFrame(monitor_rows)
    print('\nEXPERIMENT 2 — COMMON-MODEL TARGET RESULTS, 10s\n'+tv[tv.delay_seconds.eq(10)].to_string(index=False),flush=True)
    print('\nGROUP-DISJOINT SOURCE VALIDATION\n'+pd.DataFrame(validation_rows).to_string(index=False),flush=True)
    print('\nATC TIE AUDIT\n'+pd.DataFrame(cal_rows).to_string(index=False),flush=True)
    print('[3/3] Metadata-only intake of all six remaining captures; no new target model predictions.',flush=True)
    inventory=[]
    for ident in REMAINING:
        scenario=f'CTU-IoT-Malware-Capture-{ident}-1';entry=assets[scenario]
        row={'capture':ident,'scenario':scenario,'pcap_files':len(entry['pcaps']),
             'pcap_total_bytes':sum(p.stat().st_size for p in entry['pcaps']),
             'planned_prefix_budget_MiB':512 if ident in [36,39] else 256,
             'packet_evaluation_complete':False,'eligibility_approved':False,'previously_exposed_capture':True}
        if len(entry['logs'])!=1 or not entry['pcaps']:
            row['status']='REQUIRED_ORIGINAL_ASSET_NOT_UNIQUE_OR_MISSING';inventory.append(row);continue
        t0=time.perf_counter();counts=Counter();scanned=0;end='EOF'
        for r in log_rows(entry['logs'][0]):
            scanned+=1;label=r['label'].lower()
            if label in ['benign','malicious']:
                counts[label]+=1
                if label=='malicious' and r['proto'].lower()=='tcp':
                    try:n=float(r['orig_pkts'])+float(r['resp_pkts'])
                    except ValueError:n=-1
                    if 2<=n<=64:counts['malicious_TCP_2_to_64_packets']+=1
            if scanned>=2000000:end='ROW_LIMIT';break
            if scanned%10000==0 and time.perf_counter()-t0>=30:end='TIME_LIMIT';break
        row.update({'status':'METADATA_SCAN_COMPLETE_NOT_PACKET_EVALUATION','labelled_log':str(entry['logs'][0]),
                    'largest_raw_pcap':str(max(entry['pcaps'],key=lambda p:p.stat().st_size)),
                    'records_scanned':scanned,'scan_end':end,'counts_are_full_log_totals':end=='EOF',
                    'benign_found':counts['benign'],'malicious_found':counts['malicious'],
                    'malicious_TCP_2_to_64_found':counts['malicious_TCP_2_to_64_packets'],
                    'note':'Counts do not prove prefix linkage, IPv4 status, packet ownership, or attack feasibility. No thresholds relaxed.'})
        inventory.append(row);print('Metadata:',ident,'rows',scanned,'benign',counts['benign'],'mutable-TCP candidates',counts['malicious_TCP_2_to_64_packets'],end,flush=True)
    inv=pd.DataFrame(inventory);inv.to_csv(OUT/'six_capture_metadata_intake.csv',index=False)
    summary=mm[mm.delay_seconds.eq(10)].groupby(['target','family','estimator'],as_index=False).agg(
        folds=('fold','nunique'),mean_absolute_error=('current_absolute_error','mean'),
        minimum_absolute_error=('current_absolute_error','min'),maximum_absolute_error=('current_absolute_error','max'),
        mean_differential_error=('differential_error','mean'),missed_definite_damage_folds=('missed_definite_unit_damage','sum'))
    summary.to_csv(OUT/'five_fold_descriptive_monitor_summary.csv',index=False)
    print('\nEXPERIMENT 3 — REMAINING CAPTURE INTAKE\n'+inv.to_string(index=False),flush=True)
    print('\nFIVE-FOLD MONITOR SUMMARY — DESCRIPTIVE, NOT CAPTURE-LEVEL CI\n'+summary.to_string(index=False),flush=True)
    R.update({'status':'FIVE_GROUP_FOLDS_TWO_COHORTS_AND_SIX_CAPTURE_INTAKE_COMPLETE',
              'source_rows':len(source),'source_groups':int(len(set(groups))),'outer_folds':5,
              'fit_calibration_validation_groups_disjoint_within_each_fold':True,'same_fold_training_rows_for_HGB_and_LR':True,
              'target_cohorts_unchanged':True,'models_shared_across_both_target_cohorts':True,
              'model_initialization_seed':MODEL_SEED,'folds_are_not_independent_target_captures':True,
              'remaining_packet_target_captures':REMAINING,
              'P3_full_eight_capture_evaluation_complete':False,'P4_broad_monitor_panel_complete':False,
              'interpretation':'This quantifies source-data-group sensitivity, not five stochastic initialization seeds. Calibration/validation are separated from fitting. Six-capture intake is metadata only. Current source-validation and target results remain exploratory.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'five_fold_validity_extension_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
