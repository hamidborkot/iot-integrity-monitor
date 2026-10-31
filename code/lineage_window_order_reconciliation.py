# P4 reconciliation: three declared window orders, same frozen methods/records.
# No threshold selection, retraining, calibration fitting, or PCAP replay.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import gzip, hashlib, io, json, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('LINEAGE_WINDOW_ORDER_RECONCILIATION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
V={'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],'V_time_proto':['duration','proto']}
GATES=['COMBINED_HARD_GATE','DRIFT_ONLY','COMPETENCE_ONLY']
METHODS=['AC','SEMANTIC_AGREE','ATC_FROZEN','DoC_FROZEN','CBPE_SOURCE_PLATT_EXACT']+GATES
R={'status':'STARTED','deployed_models_retrained':False,'calibration_refitted':False,'new_PCAP_replays':0,
   'injection_control_completed':False,'independent_confirmation':False,'best_order_selected':False,
   'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def latest(pattern,status):
    found=[]
    for p in W.glob(pattern):
        q=p/'receipt.json'
        if not q.is_file():continue
        try:r=json.loads(q.read_text())
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
    if len(b)>128*1024**2:raise Stop('Input exceeds bounded read limit')
    return b

def sha(a):return hashlib.sha256(blob(a)).hexdigest()
def table(a):
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded input too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df):
    df=df.copy()
    if not set(F+['ks','y']).issubset(df.columns):raise Stop('Required predictor/key/label columns missing')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower();y=pd.to_numeric(df.y,errors='raise')
    if not y.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid labels/protocols')
    df['y']=y.astype(int)
    return df

def encode(df,cols):
    nums=[c for c in cols if c!='proto'];parts=[]
    if nums:parts.append(np.log1p(df[nums].to_numpy(float)))
    if 'proto' in cols:parts.append(np.column_stack([df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]))
    return np.hstack(parts)

def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)

def logit(p):
    p=np.clip(p,1e-6,1-1e-6)
    return (np.log(p)-np.log1p(-p)).reshape(-1,1)

def gated(d,v,profile,method):
    mu,sd,competence=profile;z=np.abs(v.mean(axis=0)-mu)/np.maximum(sd,.01)
    drift=np.exp(-.5*z*z)
    if method=='COMPETENCE_ONLY':weights=competence.copy();abstain=weights.sum()<=0
    elif method=='DRIFT_ONLY':weights=drift;abstain=weights.sum()<=0
    else:weights=competence*drift*(z<=3.0);abstain=(weights>0).sum()<2
    return (np.nan,True) if abstain else (float((d==((v@weights)/weights.sum()>.5)).mean()),False)

def close(a,b):return bool((pd.isna(a) and pd.isna(b)) or (not pd.isna(a) and not pd.isna(b) and np.isclose(float(a),float(b),atol=1e-10,rtol=0)))

try:
    a,ar=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    b,_=latest('LINEAGE_MONITOR_BATCH_B_*','P4_FROZEN_ATC_DOC_BATCH_COMPLETE')
    c,_=latest('LINEAGE_MONITOR_BATCH_C_*','P4_GATE_AND_TWO_ABLATIONS_COMPLETE')
    e,_=latest('LINEAGE_MONITOR_BATCH_E_CBPE_*','P4_CBPE_SOURCE_CALIBRATION_AND_EXACT_METRICS_COMPLETE')
    manifest=json.loads((a/'input_manifest.json').read_text());calibration=json.loads((b/'calibration_inputs.json').read_text())
    model_hash=sha(manifest['models'])
    if model_hash!=calibration['model_sha256']:raise Stop('Model/calibration identity mismatch')
    if json.loads(blob(calibration['assets']['contract']))!=calibration['contract']:raise Stop('Source contract changed')
    stats=table(calibration['assets']['stats']);stats['seed']=pd.to_numeric(stats.seed).astype(int)
    clean=norm(table(manifest['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Invalid frozen target sample')
    y=clean.y.to_numpy(int);keys=clean.ks.astype(str).to_numpy();malicious=y==1
    frames={0:clean};unit_results={}
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds']);asset=cond['candidate_asset']
        if sha(asset)!=cond['candidate_sha256']:raise Stop('Target features changed')
        frame=norm(table(asset))
        if frame.ks.duplicated().any() or set(frame.ks)!=set(keys):raise Stop('Candidate key set differs')
        frame=frame.set_index('ks').loc[keys].reset_index()
        if not np.array_equal(frame.y.to_numpy(int),y):raise Stop('Candidate labels differ')
        result_dir=Path(cond['validated_result_directory'])
        rr=json.loads((result_dir/'receipt.json').read_text())
        if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr.get('historical_transformed_pcap_sha256')!=cond['historical_transformed_pcap_sha256']:raise Stop('Packet-mapped outcome identity differs')
        units=pd.read_csv(result_dir/'test3_unit_detection.csv',dtype={'ks':str})
        if units.duplicated(['seed','ks']).any() or not boolean(units.membership_validated).all():raise Stop('Ambiguous packet-mapped outcomes')
        frames[delay]=frame;unit_results[delay]=units
    if set(frames)!={0,1,3,10}:raise Stop('Expected four conditions')
    banks={int(k):v for k,v in joblib.load(io.BytesIO(blob(manifest['models'])))['models'].items()}
    calibrators={int(k):v for k,v in joblib.load(e/'source_only_probability_calibrators.joblib').items()}
    if set(banks)!={8101,8102,8103} or set(calibrators)!=set(banks):raise Stop('Unexpected frozen seed sets')
    cbpe_policy=json.loads((e/'CBPE_policy.json').read_text())
    if cbpe_policy.get('clip_epsilon')!=1e-6:raise Stop('CBPE calibrator preprocessing policy differs')
    profile_df=pd.read_csv(c/'source_gate_profile.csv')
    profiles={}
    for seed in banks:
        z=profile_df[profile_df.seed.eq(seed)].set_index('view')
        if len(z)!=3 or set(z.index)!=set(V):raise Stop('Invalid saved gate profile')
        z=z.loc[list(V)]
        profiles[seed]=(z.source_window_rate_mean.to_numpy(float),z.source_window_rate_SD.to_numpy(float),z.competence_weight.to_numpy(float))
    old_c=pd.read_csv(c/'gate_paired_windows.csv')
    old_predictions=pd.read_csv(a/'primary_prediction_checks.csv.gz',dtype={'ks':str})
    orders={'SAVED_SAMPLE_ORDER':np.arange(len(clean)),
            'HISTORICAL_GATE_HASH_ORDER':np.argsort([hashlib.sha256(('POST_EXPOSURE_GATE_WINDOWS_v1'+k).encode()).hexdigest() for k in keys],kind='stable'),
            'MD3_LABEL_FREE_HASH_ORDER':np.argsort([hashlib.sha256(('MD3_ORDER_SENSITIVITY_v1|'+k).encode()).hexdigest() for k in keys],kind='stable')}
    WIN=int(ar['window_size']);THRESH=float(ar['warning_drop_threshold'])
    if WIN!=128:raise Stop('Unexpected window size')
    js(OUT/'policy.json',{'orders':list(orders),'methods':METHODS,'window_size':WIN,'warning_threshold':THRESH,
                          'labels_used_for_ordering':False,'best_order_selected':False,'all_orders_reported':True,
                          'source_profiles_reused_without_refit':True,'chronological_stream_order_claimed':False,
                          'purpose':'Reconcile current saved-order results with historical gate-window order; do not optimize the gate'})
    js(OUT/'inputs.json',{'batch_a':str(a),'batch_b':str(b),'batch_c':str(c),'CBPE_batch':str(e),'model_sha256':model_hash})
    members=[]
    for order_name,order in orders.items():
        for rank,idx in enumerate(order):members.append({'ordering':order_name,'window':rank//WIN,'row_in_window':rank%WIN,'ks':keys[idx]})
    pd.DataFrame(members).to_csv(OUT/'window_membership.csv',index=False)
    rows=[];verification=[]
    print('[1/3] Computing frozen predictions once per seed and condition.',flush=True)
    with threadpool_limits(limits=2):
        for seed,bank in sorted(banks.items()):
            ref=stats[stats.seed.eq(seed)]
            if len(ref)!=1:raise Stop('Calibration seed not unique')
            ref=ref.iloc[0];threshold=float(ref.ATC_confidence_threshold)
            cached={}
            for delay,frame in sorted(frames.items()):
                p=bank['PRIMARY'].predict_proba(encode(frame,F))[:,1];d=p>=.5
                votes=np.column_stack([bank[name].predict(encode(frame,cols)) for name,cols in V.items()]).astype(int)
                q=calibrators[seed].predict_proba(logit(p))[:,1]
                if not np.isfinite(p).all() or not np.isfinite(q).all():raise Stop('Nonfinite probabilities')
                old=old_predictions[old_predictions.seed.eq(seed)&old_predictions.delay_seconds.eq(delay)]
                if old.ks.duplicated().any() or set(old.ks)!=set(keys):raise Stop('Prior prediction membership differs')
                if not np.array_equal(boolean(old.set_index('ks').loc[keys,'primary_predicted_malicious']),d):raise Stop('Frozen predictions changed')
                cached[delay]={'d':d,'v':votes,'confidence':np.maximum(p,1-p),
                    'SEMANTIC_AGREE':(d==(votes.sum(axis=1)>=2)).astype(float),
                    'ATC_FROZEN':(np.maximum(p,1-p)>=threshold).astype(float),
                    'CBPE_SOURCE_PLATT_EXACT':np.where(d,q,1-q)}
            def estimate(delay,indices,method):
                x=cached[delay]
                if method in GATES:return gated(x['d'][indices],x['v'][indices],profiles[seed],method)
                if method=='AC':value=x['confidence'][indices].mean()
                elif method=='DoC_FROZEN':value=np.clip(float(ref.primary_reference_accuracy)+x['confidence'][indices].mean()-float(ref.primary_reference_confidence),0,1)
                else:value=x[method][indices].mean()
                return float(value),False
            for delay in sorted(frames):
                uc=np.full(len(clean),np.nan);ua=np.full(len(clean),np.nan)
                uc[malicious]=cached[0]['d'][malicious].astype(float)
                if delay==0:ua[malicious]=uc[malicious]
                else:
                    u=unit_results[delay];u=u[u.seed.eq(seed)]
                    if set(u.ks)!=set(keys[malicious]) or len(u)!=int(malicious.sum()):raise Stop('Original-unit population differs')
                    u=u.set_index('ks').loc[keys[malicious]]
                    if not np.array_equal(boolean(u.clean_detected),cached[0]['d'][malicious]) or not np.array_equal(boolean(u.selected_record_detected),cached[delay]['d'][malicious]):raise Stop('Original-unit predictions no longer match')
                    ua[malicious]=boolean(u.any_packet_mapped_descendant_alarm).astype(float)
                for ordering,order in orders.items():
                    for start in range(0,len(order),WIN):
                        idx=order[start:start+WIN];wi=start//WIN
                        a0=float((cached[0]['d'][idx]==y[idx]).mean());a1=float((cached[delay]['d'][idx]==y[idx]).mean())
                        mm=malicious[idx];unit_drop=float(np.mean(uc[idx][mm])-np.mean(ua[idx][mm])) if mm.any() else np.nan
                        for method in METHODS:
                            e0,s0=estimate(0,idx,method);e1,s1=estimate(delay,idx,method);retained=not s0 and not s1
                            row={'ordering':ordering,'delay_seconds':delay,'seed':seed,'window':wi,'estimator':method,
                                'malicious_fraction':float(y[idx].mean()),'malicious_original_units':int(mm.sum()),
                                'clean_record_accuracy':a0,'record_accuracy':a1,'true_record_accuracy_drop':a0-a1,
                                'original_unit_detection_drop':unit_drop,'clean_estimate':e0,'estimate':e1,
                                'clean_abstained':s0,'attack_abstained':s1,'paired_retained':retained,
                                'estimated_record_accuracy_drop':e0-e1 if retained else np.nan,
                                'current_absolute_error':abs(e1-a1) if not s1 else np.nan,
                                'current_overestimation':e1-a1 if not s1 else np.nan,
                                'differential_error':abs((e0-e1)-(a0-a1)) if retained else np.nan,
                                'clean_reject_attack_accept':bool(s0 and not s1)}
                            rows.append(row)
                            if ordering=='SAVED_SAMPLE_ORDER' and method in GATES:
                                old=old_c[old_c.seed.eq(seed)&old_c.delay_seconds.eq(delay)&old_c.window.eq(wi)&old_c.configuration.eq(method)]
                                if len(old)!=1:raise Stop('Prior gate row not unique')
                                old=old.iloc[0]
                                ok=(bool(old.clean_abstained)==s0 and bool(old.attack_abstained)==s1 and close(old.clean_estimate,e0) and close(old.estimate,e1))
                                verification.append({'seed':seed,'delay_seconds':delay,'window':wi,'method':method,'saved_order_reproduced':bool(ok)})
            print('Completed seed:',seed,flush=True)
    df=pd.DataFrame(rows);ver=pd.DataFrame(verification)
    df.to_csv(OUT/'all_order_monitor_windows.csv',index=False);ver.to_csv(OUT/'saved_order_reproduction.csv',index=False)
    if not ver.saved_order_reproduced.all():raise Stop('Saved-order gate results do not reproduce; no cross-order conclusion accepted')
    summary=[];warn=[]
    for (ordering,delay,method),g in df.groupby(['ordering','delay_seconds','estimator']):
        summary.append({'ordering':ordering,'delay_seconds':delay,'estimator':method,'seed_window_rows':len(g),
            'clean_coverage':float((~g.clean_abstained).mean()),'condition_coverage':float((~g.attack_abstained).mean()),
            'paired_coverage':float(g.paired_retained.mean()),'clean_reject_condition_accept_rows':int(g.clean_reject_attack_accept.sum()),
            'current_absolute_error_on_reported_windows':g.current_absolute_error.mean(),
            'current_overestimation_on_reported_windows':g.current_overestimation.mean(),
            'conditional_differential_error':g.differential_error.mean()})
        for target,column in [('RECORD_ACCURACY_DAMAGE','true_record_accuracy_drop'),('ORIGINAL_UNIT_DETECTION_DAMAGE','original_unit_detection_drop')]:
            eligible=g[column].notna().to_numpy();truth=g[column].ge(THRESH).to_numpy()
            usable=eligible&g.paired_retained.to_numpy(bool);alarm=g.estimated_record_accuracy_drop.ge(THRESH).to_numpy()
            tp=int((usable&truth&alarm).sum());fn=int((usable&truth&~alarm).sum());fp=int((usable&~truth&alarm).sum());tn=int((usable&~truth&~alarm).sum())
            warn.append({'ordering':ordering,'delay_seconds':delay,'estimator':method,'warning_target':target,
                'eligible_rows':int(eligible.sum()),'paired_evaluable_rows':int(usable.sum()),
                'unpaired_or_abstained_rows':int((eligible&~usable).sum()),'TP':tp,'FN':fn,'FP':fp,'TN':tn,
                'conditional_warning_TPR':tp/(tp+fn) if tp+fn else np.nan,'conditional_warning_FPR':fp/(fp+tn) if fp+tn else np.nan})
    sm=pd.DataFrame(summary);ws=pd.DataFrame(warn)
    sm.to_csv(OUT/'order_coverage_error_summary.csv',index=False);ws.to_csv(OUT/'order_warning_summary.csv',index=False)
    composition=df.drop_duplicates(['ordering','delay_seconds','seed','window']).groupby(['ordering','delay_seconds'],as_index=False).agg(
        minimum_malicious_fraction=('malicious_fraction','min'),maximum_malicious_fraction=('malicious_fraction','max'),
        mean_malicious_fraction=('malicious_fraction','mean'),pure_class_window_fraction=('malicious_fraction',lambda s:float(s.isin([0.,1.]).mean())))
    composition.to_csv(OUT/'window_class_composition.csv',index=False)
    for i,ordering in enumerate(orders,1):
        print('\nEXPERIMENT '+str(i)+' — '+ordering,flush=True)
        print(sm[sm.ordering.eq(ordering)&sm.delay_seconds.isin([0,10])].drop(columns='ordering').to_string(index=False),flush=True)
    print('\nWINDOW COMPOSITION\n'+composition.to_string(index=False),flush=True)
    print('\n10s ORIGINAL-UNIT DAMAGE WARNINGS\n'+ws[ws.delay_seconds.eq(10)&ws.warning_target.eq('ORIGINAL_UNIT_DETECTION_DAMAGE')].to_string(index=False),flush=True)
    R.update({'status':'WINDOW_ORDER_RECONCILIATION_COMPLETE','orders':list(orders),'methods':METHODS,
              'paired_window_rows':len(df),'saved_order_gate_rows_reproduced':len(ver),
              'warning_threshold_calibrated_to_FPR':False,'chronological_order_claimed':False,
              'interpretation':'All orders are reported. No best order is selected. Conditional errors require coverage. Saved sample windows and hash-permuted windows are not independent captures. This is not cross-capture generalization.',
              'next_required_work':['Capture-1-1 injection control','Cross-capture/model/extractor configuration tests','Final protocol/resource/claim-evidence package']})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'window_order_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
