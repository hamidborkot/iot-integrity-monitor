# Controlled source-split ablation: fixed outer validation and matched fit/cal budgets.
# Reuses grouped models; adds a row-separated fit/cal control only.
# No new PCAP replay, target sampling, threshold search, or capture selection.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import gzip, hashlib, io, json, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import accuracy_score,balanced_accuracy_score,roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('CONTROLLED_FIT_CAL_SPLIT_ABLATION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MODEL_SEED=8101;THRESHOLD=.05
R={'status':'STARTED','new_primary_model_fits':0,'new_probability_calibrator_fits':0,'new_PCAP_replays':0,
   'target_cohorts_changed':False,'outer_validation_changed':False,'historical_outputs_overwritten':False,
   'five_initialization_seeds_claimed':False,'independent_confirmation':False,
   'six_remaining_packet_captures_completed':False,'manuscript_submission_ready':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def file_sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def latest(pattern,status):
    candidates=[]
    for p in W.glob(pattern):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        try:r=json.loads(rp.read_text())
        except (OSError,ValueError):continue
        if r.get('status')==status:candidates.append((p,r))
    if not candidates:raise Stop('Required completed stage missing: '+status)
    return max(candidates,key=lambda x:x[0].name)
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

def asset_sha(a):
    h=hashlib.sha256()
    with opened(a) as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def table(a):
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded input exceeds bound')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df,labelled=True):
    df=df.copy()
    if not set(F+(['ks','y'] if labelled else [])).issubset(df.columns):raise Stop('Required columns missing')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid protocol')
    if labelled:
        yy=pd.to_numeric(df.y,errors='raise')
        if not yy.isin([0,1]).all():raise Stop('Invalid labels')
        df['y']=yy.astype(int)
    return df

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def boolean(s):
    x=s.astype(str).str.lower()
    if not x.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return x.isin(['true','1']).to_numpy(bool)
def logit(p):
    p=np.clip(p,1e-6,1-1e-6);return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def score_metrics(y,p):
    y=np.asarray(y,int);d=p>=.5;b=np.minimum((p*10).astype(int),9);ece=0.
    for j in range(10):
        m=b==j
        if m.any():ece+=float(m.mean())*abs(float(p[m].mean()-y[m].mean()))
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
            'AUROC':float(roc_auc_score(y,p)),'malicious_recall':float(d[y==1].mean()),
            'benign_FPR':float(d[y==0].mean()),'Brier':float(np.mean((p-y)**2)),'ECE_10_bins':ece}

def atc(conf,correct):
    n=int(np.asarray(correct,bool).sum());conf=np.asarray(conf,float)
    if n==0:return float(np.nextafter(conf.max(),np.inf)),0.
    t=float(np.sort(conf)[::-1][n-1]);above=int((conf>t).sum());ties=int((conf==t).sum())
    alpha=(n-above)/ties
    if not 0<=alpha<=1:raise Stop('ATC fractional tie calculation failed')
    return t,float(alpha)

def targets_load():
    a,_=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    base,_=latest('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    fresh,_=latest('FRESH_RAW_CAPTURE48_*','FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE')
    merge,mr=latest('CAPTURE48_MERGE_WITNESS_AUDIT_*','CAPTURE48_MERGE_AND_ALARM_WITNESS_AUDIT_COMPLETE')
    if Path(mr['source_run'])!=fresh:raise Stop('Capture48 witness audit and fresh cohort identities differ')
    manifest=json.loads((a/'input_manifest.json').read_text());clean49=norm(table(manifest['clean']))
    if clean49.ks.duplicated().any() or len(clean49)!=1024:raise Stop('Invalid capture49 cohort')
    mk49=list(clean49.loc[clean49.y.eq(1),'ks']);mp0=pd.read_csv(base/'clean_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'zeek_uid':str})
    own0=mp0.groupby('original_ks').zeek_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
    if set(own0)!=set(mk49) or any(len(v)!=1 for v in own0.values()):raise Stop('Capture49 clean membership differs')
    positive=clean49.set_index('ks').loc[mk49,F].copy();positive['uid']=[own0[k][0] for k in mk49];positive=positive.reset_index(drop=True)
    targets={'CAPTURE49_LEGACY_COHORT':{'clean':clean49,'states':{0:{'selected':clean49,'records':positive,'owners':own0,'pure':dict.fromkeys(positive.uid,True),'complete':dict.fromkeys(mk49,True)}}}}
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds'])
        if delay not in [1,10]:continue
        if asset_sha(cond['candidate_asset'])!=cond['candidate_sha256']:raise Stop('Capture49 selected features changed')
        selected=norm(table(cond['candidate_asset'])).set_index('ks').loc[clean49.ks].reset_index()
        p=Path(cond['validated_result_directory']);rr=json.loads((p/'receipt.json').read_text())
        if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr['historical_transformed_pcap_sha256']!=cond['historical_transformed_pcap_sha256']:raise Stop('Capture49 trace binding differs')
        mm=pd.read_csv(p/'test2_transformed_membership.csv',dtype={'ks':str})
        if len(mm)!=512 or not boolean(mm.transformed_membership_validated).all():raise Stop('Capture49 membership is not fully validated')
        mp=pd.read_csv(p/'transformed_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'transformed_uid':str})
        owners=mp.groupby('original_ks').transformed_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        cf=norm(pd.read_csv(p/'transformed_selected_connection_records.csv.gz',dtype={'uid':str},keep_default_na=False),False)
        if set(owners)!=set(mk49) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.transformed_uid):raise Stop('Capture49 UID coverage differs')
        targets['CAPTURE49_LEGACY_COHORT']['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':dict.fromkeys(cf.uid,True),'complete':dict.fromkeys(mk49,True)}
    clean48=norm(pd.read_csv(fresh/'fresh_clean_target_sample.csv.gz',dtype={'ks':str},keep_default_na=False));mk48=list(clean48.loc[clean48.y.eq(1),'ks'])
    target48={'clean':clean48,'states':{}};canonical=None
    for delay in [0,1,10]:
        selected=norm(pd.read_csv(fresh/f'selected_features_{delay}s.csv.gz',dtype={'ks':str},keep_default_na=False)).set_index('ks').loc[clean48.ks].reset_index()
        cf=norm(pd.read_csv(fresh/f'descendant_features_{delay}s.csv.gz',dtype={'uid':str},keep_default_na=False),False)
        mp=pd.read_csv(fresh/f'packet_uid_mapping_{delay}s.csv.gz',dtype={'original_ks':str,'uid':str})
        current=mp[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True)
        if mp.packet_index.duplicated().any():raise Stop('Repeated capture48 packet occurrence')
        if delay==0:canonical=current
        elif not current.equals(canonical):raise Stop('Capture48 original packet occurrences differ')
        purity=pd.read_csv(merge/f'UID_contributions_{delay}s.csv',dtype={'uid':str})
        pure=dict(zip(purity.uid,boolean(purity.pure_selected_original_witness_record)))
        owners=mp.groupby('original_ks').uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        if set(owners)!=set(mk48) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.uid) or set(pure)!=set(cf.uid):raise Stop('Capture48 UID coverage differs')
        target48['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':pure,'complete':dict.fromkeys(mk48,True)}
    targets['CAPTURE48_FRESH_COHORT']=target48
    for name,t in targets.items():
        if len(t['clean'])!=1024 or t['clean'].ks.duplicated().any() or int(t['clean'].y.eq(1).sum())!=512 or set(t['states'])!={0,1,10}:raise Stop('Target cohort contract failed: '+name)
        for state in t['states'].values():
            if not np.array_equal(state['selected'].y.to_numpy(),t['clean'].y.to_numpy()):raise Stop('Target labels differ')
    return targets

try:
    candidates=[]
    needed=['five_fold_models_and_calibrators.joblib','source_panel_with_groups.csv.gz','five_fold_source_membership.csv.gz',
            'source_outer_validation.csv','five_fold_common_model_target_results.csv','pre_outcome_protocol.json']
    for p in W.glob('GROUP_VALIDITY_AND_FIVE_FOLD_EXTENSION_*'):
        if all((p/n).is_file() for n in needed):candidates.append(p)
    if not candidates:raise Stop('The completed five-fold model artifacts are not present; let that cell finish before running this one')
    base=max(candidates,key=lambda p:p.name)
    source=norm(pd.read_csv(base/'source_panel_with_groups.csv.gz',dtype={'ks':str,'source_group':str},keep_default_na=False))
    if source.duplicated(['source_scenario','ks']).any():raise Stop('Duplicate source original keys')
    membership=pd.read_csv(base/'five_fold_source_membership.csv.gz',dtype={'ks':str,'source_group':str})
    stored=joblib.load(base/'five_fold_models_and_calibrators.joblib')
    grouped_models=stored['models'];grouped_calibrators=stored['calibrators']
    expected={(fold,family) for fold in range(1,6) for family in ['HGB','LR']}
    if set(grouped_models)!=expected or set(grouped_calibrators)!=expected or int(stored['model_seed'])!=MODEL_SEED:raise Stop('Grouped model contract differs')
    original_validation=pd.read_csv(base/'source_outer_validation.csv')
    original_targets=pd.read_csv(base/'five_fold_common_model_target_results.csv')
    targets=targets_load();source_ids=pd.MultiIndex.from_frame(source[['source_scenario','ks']])
    groups=source.source_group.astype(str).to_numpy();strata=(source.source_scenario+'|'+source.y.astype(str)).to_numpy()
    split_roles={};audit_rows=[];allocation_rows=[]
    print('[1/3] Creating a matched row-separated control with the SAME outer validation records.',flush=True)
    for fold in range(1,6):
        m=membership[membership.fold.eq(fold)]
        if m.duplicated(['source_scenario','ks']).any() or len(m)!=len(source):raise Stop('Invalid grouped source membership')
        mi=pd.MultiIndex.from_frame(m[['source_scenario','ks']]);pos=source_ids.get_indexer(mi)
        if (pos<0).any() or len(set(pos))!=len(source):raise Stop('Grouped membership population differs')
        roles={role:pos[m.role.eq(role).to_numpy()] for role in ['model_fit','calibration','validation']}
        if sum(len(v) for v in roles.values())!=len(source):raise Stop('Unknown grouped role')
        gsets={role:set(groups[v]) for role,v in roles.items()}
        if gsets['model_fit']&gsets['calibration'] or gsets['model_fit']&gsets['validation'] or gsets['calibration']&gsets['validation']:raise Stop('Original grouped roles overlap')
        development=np.sort(np.concatenate([roles['model_fit'],roles['calibration']]))
        rng=np.random.default_rng(95000+fold);row_fit=[];row_cal=[]
        for stratum in sorted(set(strata[development])):
            pool=development[strata[development]==stratum];pool=rng.permutation(pool)
            nfit=int((strata[roles['model_fit']]==stratum).sum())
            row_fit.extend(pool[:nfit]);row_cal.extend(pool[nfit:])
        row_roles={'model_fit':np.sort(np.array(row_fit,int)),'calibration':np.sort(np.array(row_cal,int)),'validation':roles['validation'].copy()}
        if set(row_roles['model_fit'])&set(row_roles['calibration']) or set(np.concatenate([row_roles['model_fit'],row_roles['calibration']]))!=set(development):raise Stop('Row control record allocation failed')
        for role in roles:
            old_counts=pd.Series(strata[roles[role]]).value_counts().sort_index()
            new_counts=pd.Series(strata[row_roles[role]]).value_counts().sort_index()
            if not old_counts.equals(new_counts):raise Stop('Class/capture composition was not matched')
        if not np.array_equal(row_roles['validation'],roles['validation']):raise Stop('Outer validation changed')
        for policy,rr in [('GROUP_DISJOINT',roles),('ROW_FIT_CAL_CONTROL',row_roles)]:
            gs={role:set(groups[indices]) for role,indices in rr.items()}
            if gs['validation']&(gs['model_fit']|gs['calibration']):raise Stop('Outer validation groups leaked into model fit/calibration')
            audit_rows.append({'fold':fold,'split_policy':policy,'fit_rows':len(rr['model_fit']),'calibration_rows':len(rr['calibration']),
                'validation_rows':len(rr['validation']),'fit_cal_shared_groups':len(gs['model_fit']&gs['calibration']),
                'validation_shared_groups':len(gs['validation']&(gs['model_fit']|gs['calibration'])),
                'same_outer_validation':True,'matched_class_capture_counts':True})
            for role,indices in rr.items():
                allocation_rows.extend({'fold':fold,'split_policy':policy,'role':role,'ks':source.iloc[i].ks,
                    'source_scenario':source.iloc[i].source_scenario,'source_group':groups[i]} for i in indices)
        split_roles[fold]=(roles,row_roles)
    pd.DataFrame(audit_rows).to_csv(OUT/'matched_allocation_audit.csv',index=False)
    pd.DataFrame(allocation_rows).to_csv(OUT/'matched_source_memberships.csv.gz',index=False,compression='gzip')
    js(OUT/'pre_outcome_protocol.json',{'grouped_extension':str(base),'fixed_outer_validation':True,
        'matched_fit_calibration_record_counts_class_counts_and_capture_counts':True,
        'changed_factor':'fit/calibration grouping policy within fixed outer development pool',
        'row_control_is_recommended_final_protocol':False,'outer_validation_groups_disjoint_in_both_policies':True,
        'model_seed':MODEL_SEED,'row_control_allocation_seed':'95000+fold',
        'families':['HGB','LR'],'HGB':{'max_iter':150,'learning_rate':.08,'early_stopping':False},
        'LR':{'C':1.,'solver':'lbfgs','max_iter':5000},'calibrator':{'C':1.,'solver':'lbfgs','max_iter':2000},
        'target_cohorts':list(targets),'conditions':[0,1,10],'target_labels_used_for_fitting':False,
        'interpretation':'Controlled split-policy sensitivity, not proof of a unique causal mechanism or independent target confirmation'})
    js(OUT/'input_hashes.json',{n:file_sha(base/n) for n in needed})
    val_rows=[];target_rows=[];monitor_rows=[];reproduction=[];new_models={};new_calibrators={}
    with threadpool_limits(limits=2):
        for fold,(group_roles,row_roles) in split_roles.items():
            for family in ['HGB','LR']:
                for policy,roles in [('GROUP_DISJOINT',group_roles),('ROW_FIT_CAL_CONTROL',row_roles)]:
                    fit=source.iloc[roles['model_fit']];cal=source.iloc[roles['calibration']];validation=source.iloc[roles['validation']]
                    if policy=='GROUP_DISJOINT':model=grouped_models[(fold,family)];calibrator=grouped_calibrators[(fold,family)]
                    else:
                        model=(HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=MODEL_SEED) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,solver='lbfgs',max_iter=5000,random_state=MODEL_SEED))]))
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always',ConvergenceWarning);model.fit(encode(fit),fit.y)
                            if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed row-control primary model did not converge')
                        R['new_primary_model_fits']+=1
                        calibrator=LogisticRegression(C=1.,solver='lbfgs',max_iter=2000,random_state=94501)
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always',ConvergenceWarning);calibrator.fit(logit(model.predict_proba(encode(cal))[:,1]),cal.y)
                            if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed row-control calibrator did not converge')
                        R['new_probability_calibrator_fits']+=1
                        new_models[(fold,family)]=model;new_calibrators[(fold,family)]=calibrator
                    pc=model.predict_proba(encode(cal))[:,1];dc=pc>=.5;cc=np.maximum(pc,1-pc)
                    ca=float((dc==cal.y.to_numpy()).mean());cm=float(cc.mean());threshold,alpha=atc(cc,dc==cal.y.to_numpy())
                    pv=model.predict_proba(encode(validation))[:,1];qv=calibrator.predict_proba(logit(pv))[:,1]
                    raw_metrics=score_metrics(validation.y,pv);cal_metrics=score_metrics(validation.y,qv)
                    val_rows.append({'fold':fold,'family':family,'split_policy':policy,'validation_rows':len(validation),
                        **raw_metrics,'calibrated_Brier':cal_metrics['Brier'],'calibrated_ECE':cal_metrics['ECE_10_bins'],
                        'calibration_accuracy':ca,'calibration_mean_confidence':cm,
                        'ATC_GE_matching_error':float((cc>=threshold).mean()-ca),
                        'ATC_fractional_matching_error':float(((cc>threshold).astype(float)+alpha*(cc==threshold)).mean()-ca)})
                    if policy=='GROUP_DISJOINT':
                        old=original_validation[original_validation.fold.eq(fold)&original_validation.family.eq(family)]
                        if len(old)!=1:raise Stop('Original grouped validation row missing')
                        ok=all(np.isclose(raw_metrics[name],float(old.iloc[0][name]),atol=1e-10,rtol=0) for name in ['accuracy','balanced_accuracy','AUROC','malicious_recall','benign_FPR'])
                        reproduction.append({'fold':fold,'family':family,'group_validation_reproduced':bool(ok)})
                        if not ok:raise Stop('Grouped source validation does not reproduce; no row-control interpretation accepted')
                    for target_name,t in targets.items():
                        clean=t['clean'];yy=clean.y.to_numpy();mk=list(clean.loc[yy==1,'ks']);N=len(mk);states=[]
                        for delay in [0,1,10]:
                            state=t['states'][delay];frame=state['selected'];cf=state['records']
                            p=model.predict_proba(encode(frame))[:,1];d=p>=.5;confidence=np.maximum(p,1-p);q=calibrator.predict_proba(logit(p))[:,1]
                            alarms=dict(zip(cf.uid,model.predict_proba(encode(cf))[:,1]>=.5));pos=neg=unknown=overlap=0
                            for k in mk:
                                uu=state['owners'][k];has=any(alarms[u] for u in uu);pure=any(alarms[u] and state['pure'].get(u,False) for u in uu)
                                none=state['complete'][k] and not has
                                pos+=int(pure);neg+=int(none);unknown+=int(not pure and not none);overlap+=int(has)
                            accuracy=float((d==yy).mean())
                            values={'AC':float(confidence.mean()),'DoC':float(np.clip(ca+confidence.mean()-cm,0,1)),
                                    'ATC_SOURCE_GE':float((confidence>=threshold).mean()),
                                    'ATC_FRACTIONAL_TIE_EXPECTATION':float(((confidence>threshold).astype(float)+alpha*(confidence==threshold)).mean()),
                                    'CBPE_ACC_POINT':float(np.where(d,q,1-q).mean())}
                            tr={'fold':fold,'family':family,'split_policy':policy,'target':target_name,'delay_seconds':delay,
                                'record_accuracy':accuracy,'selected_record_recall':float(d[yy==1].mean()),'benign_FPR':float(d[yy==0].mean()),
                                'original_units':N,'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                                'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap}
                            target_rows.append(tr);states.append((delay,accuracy,pos/N,(pos+unknown)/N,values))
                            if policy=='GROUP_DISJOINT':
                                old=original_targets[original_targets.fold.eq(fold)&original_targets.family.eq(family)&original_targets.target.eq(target_name)&original_targets.delay_seconds.eq(delay)]
                                if len(old)!=1 or not all(np.isclose(float(old.iloc[0][name]),float(tr[name]),atol=1e-12,rtol=0) for name in ['record_accuracy','unit_detection_lower','unit_detection_upper']):raise Stop('Grouped target results do not reproduce')
                        baseline=states[0]
                        for delay,truth,lower,upper,values in states:
                            for name,value in values.items():
                                drop=baseline[4][name]-value;loss_lower=baseline[2]-upper;loss_upper=baseline[3]-lower
                                monitor_rows.append({'fold':fold,'family':family,'split_policy':policy,'target':target_name,
                                    'delay_seconds':delay,'estimator':name,'record_accuracy':truth,'estimate':value,
                                    'absolute_error':abs(value-truth),'overestimation':value-truth,
                                    'record_accuracy_drop':baseline[1]-truth,'estimated_record_accuracy_drop':drop,
                                    'differential_error':abs(drop-(baseline[1]-truth)),
                                    'original_unit_detection_drop_lower':loss_lower,'original_unit_detection_drop_upper':loss_upper,
                                    'warning_at_5pp':drop>=THRESHOLD,'definite_damage_present':loss_lower>=THRESHOLD,
                                    'missed_definite_damage':bool(loss_lower>=THRESHOLD and drop<THRESHOLD)})
                pd.DataFrame(val_rows).to_csv(OUT/'common_validation_results.csv',index=False)
                pd.DataFrame(target_rows).to_csv(OUT/'common_target_results.csv',index=False)
                pd.DataFrame(monitor_rows).to_csv(OUT/'common_monitor_results.csv',index=False)
                pd.DataFrame(reproduction).to_csv(OUT/'grouped_result_reproduction.csv',index=False)
                print('Completed controlled comparison:',fold,family,flush=True)
    joblib.dump({'models':new_models,'calibrators':new_calibrators},OUT/'row_control_models_and_calibrators.joblib',compress=3)
    val=pd.DataFrame(val_rows);tv=pd.DataFrame(target_rows);mv=pd.DataFrame(monitor_rows)
    for family,title in [('HGB','EXPERIMENT 1 — HGB, MATCHED SPLIT POLICIES'),('LR','EXPERIMENT 2 — LR, MATCHED SPLIT POLICIES')]:
        print('\n'+title+'\n'+tv[tv.family.eq(family)&tv.delay_seconds.eq(10)].to_string(index=False),flush=True)
    idx=['fold','family','target','delay_seconds']
    grouped=tv[tv.split_policy.eq('GROUP_DISJOINT')].set_index(idx)
    row=tv[tv.split_policy.eq('ROW_FIT_CAL_CONTROL')].set_index(idx).reindex(grouped.index)
    changes=grouped[['record_accuracy','unit_detection_lower','unit_detection_upper','benign_FPR']].copy()
    for name in list(changes.columns):changes[name+'_ROW_minus_GROUP']=row[name]-grouped[name]
    changes.reset_index().to_csv(OUT/'paired_split_policy_changes.csv',index=False)
    print('\nEXPERIMENT 3 — IDENTICAL VALIDATION / CALIBRATION AUDIT\n'+val.to_string(index=False),flush=True)
    print('\nALLOCATION CONTROL CHECKS\n'+pd.DataFrame(audit_rows).to_string(index=False),flush=True)
    print('\nPAIRED TARGET CHANGES, 10s\n'+changes.reset_index()[changes.reset_index().delay_seconds.eq(10)].to_string(index=False),flush=True)
    if (base/'six_capture_metadata_intake.csv').is_file():
        intake=pd.read_csv(base/'six_capture_metadata_intake.csv');intake.to_csv(OUT/'remaining_capture_intake_reference.csv',index=False)
    gaps=[{'package':'P0','status':'SPLIT_POLICY_CONTROL_COMPUTED','remaining':'Legacy AUROC and final paper/method-fidelity review'},
          {'package':'P1','status':'CAPTURE49_ACCOUNTING_AND_HORIZON_RUNS_PRESENT','remaining':'Final policy wording'},
          {'package':'P2','status':'FRESH_INJECTION_CONTROL_PRESENT_WITH_AMENDMENT','remaining':'Do not claim historical numerical replication'},
          {'package':'P3','status':'SOURCE_GROUP_AND_COMMON_MODEL_SENSITIVITY_COMPUTED','remaining':'Packet-aware captures 7,9,33,36,39,43 remain'},
          {'package':'P4','status':'FIVE_POINT_ESTIMATORS_ON_TWO_FIXED_COHORTS','remaining':'Broader capture testing and full bank/gate/MD3 information-setting alignment'},
          {'package':'P5','status':'PRIVATE_CHECKPOINT_ONLY','remaining':'Refresh archive after extensions; end-to-end clean reproduction and manuscript/novelty audit'}]
    pd.DataFrame(gaps).to_csv(OUT/'P0_P5_remaining_work.csv',index=False)
    R.update({'status':'CONTROLLED_FIT_CAL_SPLIT_ABLATION_COMPLETE','source_grouped_models_reused':10,
        'outer_validation_identical_between_policies':True,'fit_calibration_sizes_and_class_capture_composition_matched':True,
        'row_control_retains_group_disjoint_outer_validation':True,'row_control_is_not_recommended_final_split':True,
        'source_fold_count':5,'independent_target_capture_count_claimed':False,
        'does_not_prove_leakage_caused_original_failure':True,
        'remaining_packet_target_captures':[7,9,33,36,39,43],
        'interpretation':'Report both policies, all folds, and all outcomes. A split-policy contrast is not proof of a unique causal mechanism; source folds are not independent target captures. No parameter or target selection follows from the result.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'controlled_split_ablation_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
