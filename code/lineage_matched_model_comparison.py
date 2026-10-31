# P3 subtask: aligned HGB/LR model-family comparison + protocol-only control.
# New comparison models use exactly the same preserved source allocation.
# Historical models/results are never modified. No PCAP replay or target tuning.
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
OUT=W/('LINEAGE_MATCHED_MODEL_FAMILIES_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SEEDS=[8101,8102,8103]
R={'status':'STARTED','historical_models_retrained_or_overwritten':False,'new_comparison_models_trained':0,
   'new_PCAP_replays':0,'injection_control_completed':False,'cross_capture_confirmation_completed':False,
   'target_labels_used_for_fitting':False,'target_based_parameter_selection':False,
   'independent_confirmation':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def latest(pattern,status):
    found=[]
    for p in W.glob(pattern):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        try:r=json.loads(rp.read_text())
        except (OSError,ValueError):continue
        if r.get('status')==status:found.append((p,r))
    if not found:raise Stop('Required completed stage missing: '+status)
    return max(found,key=lambda x:x[0].name)
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def blob(a):
    with opened(a) as f:b=f.read(128*1024**2+1)
    if len(b)>128*1024**2:raise Stop('Bounded read exceeded')
    return b

def sha_asset(a):return hashlib.sha256(blob(a)).hexdigest()
def file_sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def table(a):
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded table too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df,labelled=True):
    df=df.copy();required=F+(['ks','y'] if labelled else [])
    if not set(required).issubset(df.columns):raise Stop('Required input columns missing')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    if labelled:
        y=pd.to_numeric(df.y,errors='raise')
        if not y.isin([0,1]).all():raise Stop('Invalid labels')
        df['y']=y.astype(int)
    return df

def encode(df,protocol_only=False):
    protocol=np.column_stack([df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']])
    return protocol if protocol_only else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),protocol])

def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)

def metrics(y,p):
    y=np.asarray(y,int);d=p>=.5;positive=y==1;negative=y==0
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
            'AUROC':float(roc_auc_score(y,p)) if len(np.unique(y))==2 else np.nan,
            'malicious_recall':float(d[positive].mean()) if positive.any() else np.nan,
            'benign_FPR':float(d[negative].mean()) if negative.any() else np.nan}

try:
    a,_=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    b,_=latest('LINEAGE_MONITOR_BATCH_B_*','P4_FROZEN_ATC_DOC_BATCH_COMPLETE')
    md3,_=latest('LINEAGE_MONITOR_BATCH_D_MD3_*','P4_MD3_WARNING_AND_ORDER_CONTROL_COMPLETE')
    reconciliation,_=latest('LINEAGE_WINDOW_ORDER_RECONCILIATION_*','WINDOW_ORDER_RECONCILIATION_COMPLETE')
    manifest=json.loads((a/'input_manifest.json').read_text())
    calibration=json.loads((b/'calibration_inputs.json').read_text())
    if sha_asset(manifest['models'])!=calibration['model_sha256']:raise Stop('Historical model identity changed')
    if json.loads(blob(calibration['assets']['contract']))!=calibration['contract']:raise Stop('Source calibration contract changed')
    source=norm(table(calibration['assets']['reference']))
    if len(source)!=12288 or 'source_scenario' not in source:raise Stop('Unexpected source panel')
    allowed={'CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1'}
    if set(source.source_scenario)!=allowed or source.duplicated(['source_scenario','ks']).any():raise Stop('Source scenario/key contract failed')
    allocation=pd.read_csv(md3/'source_membership.csv',dtype=str,keep_default_na=False)
    if allocation.duplicated(['source_scenario','ks']).any():raise Stop('Duplicate source allocation keys')
    si=pd.MultiIndex.from_frame(source[['source_scenario','ks']]);ai=pd.MultiIndex.from_frame(allocation[['source_scenario','ks']])
    if set(si)!=set(ai):raise Stop('Source allocation population differs')
    labels=pd.Series(allocation.allocation.to_numpy(),index=ai).reindex(si).to_numpy()
    train_mask=labels=='MD3_reference';test_mask=labels=='MD3_source_holdout'
    if train_mask.sum()!=9830 or test_mask.sum()!=2458 or not (train_mask|test_mask).all():raise Stop('Expected the fixed 9830/2458 source allocation')
    train=source.loc[train_mask].reset_index(drop=True);hold=source.loc[test_mask].reset_index(drop=True)
    clean=norm(table(manifest['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Invalid fixed target sample')
    if set(clean.ks)&set(source.ks):raise Stop('Source/target original keys overlap')
    keys=clean.ks.astype(str).to_numpy();y=clean.y.to_numpy(int);malicious=y==1
    if int(malicious.sum())!=512:raise Stop('Expected 512 selected malicious original units')
    mk=keys[malicious];frames={0:clean};descendants={};memberships={};input_rows=[]
    print('[1/3] Loading the existing packet-mapped outcomes; no extraction is rerun.',flush=True)
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds']);asset=cond['candidate_asset']
        if sha_asset(asset)!=cond['candidate_sha256']:raise Stop('Changed selected-record features')
        frame=norm(table(asset))
        if frame.ks.duplicated().any() or set(frame.ks)!=set(keys):raise Stop('Target membership differs')
        frame=frame.set_index('ks').loc[keys].reset_index()
        if not np.array_equal(frame.y.to_numpy(int),y):raise Stop('Candidate labels differ')
        directory=Path(cond['validated_result_directory']);rr=json.loads((directory/'receipt.json').read_text())
        if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr.get('historical_transformed_pcap_sha256')!=cond['historical_transformed_pcap_sha256']:raise Stop('Packet-mapped trace identity differs')
        member_path=directory/'test2_transformed_membership.csv'
        members=pd.read_csv(member_path,dtype={'ks':str})
        if len(members)!=512 or members.ks.duplicated().any() or set(members.ks)!=set(mk) or not boolean(members.transformed_membership_validated).all():raise Stop('Original-unit membership is not fully validated')
        mapping_path=directory/'transformed_packet_uid_mapping.csv.gz'
        mapping=pd.read_csv(mapping_path,dtype={'original_ks':str,'transformed_uid':str})
        if mapping.packet_index.duplicated().any() or set(mapping.original_ks)!=set(mk):raise Stop('Invalid packet occurrence mapping')
        if mapping.groupby('transformed_uid').original_ks.nunique().gt(1).any():raise Stop('Mixed-origin descendant UID')
        counts=mapping.groupby('original_ks').size().reindex(members.ks).to_numpy()
        if not np.array_equal(counts,members.expected_packets.to_numpy(int)):raise Stop('Packet occurrence counts differ from validated membership')
        conn_path=directory/'transformed_selected_connection_records.csv.gz'
        conn=norm(pd.read_csv(conn_path,dtype=str,keep_default_na=False),labelled=False)
        if conn.uid.duplicated().any() or set(conn.uid)!=set(mapping.transformed_uid):raise Stop('Descendant UID feature coverage differs')
        owners=mapping.groupby('original_ks').transformed_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        conn=conn.set_index('uid').loc[sorted(set(mapping.transformed_uid))].reset_index()
        frames[delay]=frame;descendants[delay]=(conn,owners);memberships[delay]=members
        input_rows.append({'delay_seconds':delay,'validated_directory':str(directory),
            'mapping_sha256':file_sha(mapping_path),'descendant_features_sha256':file_sha(conn_path),
            'membership_sha256':file_sha(member_path),'transformed_pcap_sha256':cond['historical_transformed_pcap_sha256']})
    if set(frames)!={0,1,3,10}:raise Stop('Expected four validated conditions')
    policy={'status':'new exploratory matched-training comparison; historical models untouched',
            'source_train_rows':len(train),'source_holdout_rows':len(hold),
            'source_allocation':'same existing MD3 allocation for every model and seed',
            'target_capture':'49-1, already exposed','seeds':SEEDS,'decision_threshold':.5,
            'HGB':{'max_iter':150,'learning_rate':.08,'early_stopping':False},
            'LR':{'C':1.0,'solver':'lbfgs','max_iter':5000,'preprocessing':'historical encoding + source-fitted StandardScaler'},
            'protocol_control':'same LR policy, only three protocol indicators',
            'target_labels_used_for_fitting':False,'parameter_search':False,
            'descendant_labels_assigned':False,'original_unit_policy':'any packet-mapped descendant raises alarm',
            'source_holdout_is_cross_capture_test':False,'historical_HGB_training_population_reproduced':False,
            'interpretation':'HGB and LR are aligned to each other, not pooled with the old differently trained HGB as if training were identical'}
    js(OUT/'model_comparison_policy.json',policy)
    js(OUT/'input_manifest.json',{'prior_batches':[str(a),str(b),str(md3),str(reconciliation)],'source_asset':calibration['assets']['reference'],
                                'source_reference_sha256':sha_asset(calibration['assets']['reference']),'packet_inputs':input_rows})
    allocation.to_csv(OUT/'source_allocation.csv',index=False)
    source_rows=[];target_rows=[];unit_rows=[];families={}
    print('[2/3] Training matched HGB/LR models and the protocol-only control on source data only.',flush=True)
    with threadpool_limits(limits=2):
        for family in ['HGB_MATCHED','LR_MATCHED','PROTOCOL_ONLY_LR']:
            protocol_only=family=='PROTOCOL_ONLY_LR'
            Xtrain=encode(train,protocol_only);Xhold=encode(hold,protocol_only)
            for seed in SEEDS:
                if family=='HGB_MATCHED':
                    model=HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=seed)
                else:
                    model=Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.0,solver='lbfgs',max_iter=5000,random_state=seed))])
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always',ConvergenceWarning)
                    model.fit(Xtrain,train.y.to_numpy())
                    if any(issubclass(x.category,ConvergenceWarning) for x in caught):raise Stop('Fixed model did not converge: '+family)
                R['new_comparison_models_trained']+=1
                families[(family,seed)]=model
                if list(model.classes_)!=[0,1]:raise Stop('Unexpected fitted class order')
                hold_p=model.predict_proba(Xhold)[:,1]
                source_rows.append({'family':family,'seed':seed,'source_holdout_rows':len(hold),**metrics(hold.y.to_numpy(),hold_p)})
                clean_p=model.predict_proba(encode(clean,protocol_only))[:,1];clean_d=clean_p>=.5
                clean_unit=clean_d[malicious];initial=int(clean_unit.sum())
                for delay,frame in sorted(frames.items()):
                    p=model.predict_proba(encode(frame,protocol_only))[:,1];d=p>=.5
                    selected_unit=d[malicious]
                    if delay==0:
                        unit_alarm=clean_unit.copy();descendant_count={k:1 for k in mk}
                    else:
                        conn,owners=descendants[delay]
                        cp=model.predict_proba(encode(conn,protocol_only))[:,1]
                        uid_alarm=dict(zip(conn.uid,cp>=.5))
                        unit_alarm=np.array([any(uid_alarm[u] for u in owners[k]) for k in mk],dtype=bool)
                        descendant_count={k:len(owners[k]) for k in mk}
                    lost_selected=clean_unit&~selected_unit
                    lost_after_accounting=clean_unit&~unit_alarm
                    target_rows.append({'family':family,'seed':seed,'delay_seconds':delay,
                        'record_rows':len(frame),**metrics(y,p),
                        'record_accuracy_drop':float((clean_d==y).mean()-(d==y).mean()),
                        'original_malicious_units':len(mk),'clean_detected_original_units':initial,
                        'selected_record_detected_units':int(selected_unit.sum()),
                        'any_descendant_detected_units':int(unit_alarm.sum()),
                        'original_unit_detection_fraction':float(unit_alarm.mean()),
                        'original_unit_detection_drop':float(clean_unit.mean()-unit_alarm.mean()),
                        'selected_record_misses_with_descendant_alarm':int((~selected_unit&unit_alarm).sum()),
                        'clean_detected_selected_losses_recovered':int((lost_selected&unit_alarm).sum()),
                        'clean_detected_losses_after_accounting':int(lost_after_accounting.sum()),
                        'loss_fraction_among_clean_detected':float(lost_after_accounting.sum()/initial) if initial else np.nan,
                        'zero_clean_detection_floor':initial==0,
                        'functionality_preservation_proved':False})
                    unit_rows.extend({'family':family,'seed':seed,'delay_seconds':delay,'ks':str(k),
                        'clean_detected':bool(cd),'selected_record_detected':bool(sd),
                        'any_packet_mapped_descendant_alarm':bool(ad),'descendant_records':descendant_count[k]}
                        for k,cd,sd,ad in zip(mk,clean_unit,selected_unit,unit_alarm))
                pd.DataFrame(source_rows).to_csv(OUT/'source_holdout_metrics.csv',index=False)
                pd.DataFrame(target_rows).to_csv(OUT/'matched_model_target_metrics.csv',index=False)
                print('Completed:',family,seed,flush=True)
    joblib.dump(families,OUT/'new_matched_comparison_models.joblib',compress=3)
    source_table=pd.DataFrame(source_rows);target_table=pd.DataFrame(target_rows)
    pd.DataFrame(unit_rows).to_csv(OUT/'new_model_original_unit_predictions.csv.gz',index=False,compression='gzip')
    print('\nSOURCE HOLDOUT SANITY CHECK\n'+source_table.to_string(index=False),flush=True)
    cols=['seed','delay_seconds','accuracy','malicious_recall','benign_FPR','record_accuracy_drop',
          'clean_detected_original_units','selected_record_detected_units','any_descendant_detected_units',
          'original_unit_detection_drop','selected_record_misses_with_descendant_alarm','loss_fraction_among_clean_detected']
    for family,title in [('HGB_MATCHED','EXPERIMENT 1 — MATCHED HGB'),('LR_MATCHED','EXPERIMENT 2 — MATCHED LOGISTIC REGRESSION'),('PROTOCOL_ONLY_LR','EXPERIMENT 3 — PROTOCOL SHORTCUT CONTROL')]:
        print('\n'+title+'\n'+target_table[target_table.family.eq(family)][cols].to_string(index=False),flush=True)
    R.update({'status':'MATCHED_MODEL_FAMILIES_AND_PROTOCOL_CONTROL_COMPLETE',
              'source_train_rows':len(train),'source_holdout_rows':len(hold),
              'same_source_allocation_for_all_models':True,'source_holdout_key_disjointness_verified':True,
              'target_keys_disjoint_from_source_keys':True,'seeds':SEEDS,'target_capture_count':1,
              'comparison_models_are_not_the_historical_frozen_models':True,
              'remaining_P3_work':['Other eligible captures','Alternative extractor configuration with its own clean reference'],
              'remaining_P2_work':['Capture-1-1 injection control'],
              'interpretation':'Exploratory same-capture model-family comparison. Source-reference row holdout is not capture-held-out validation. Report clean detection floors and all outcomes; no parameter tuning follows from unfavorable results.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'matched_model_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
