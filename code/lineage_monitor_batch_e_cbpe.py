# P4 Batch E: CBPE formula reproduction with source-only Platt calibration.
# Accuracy distribution: Poisson-binomial correct-count / n.
# Recall distribution: independent TP and FN Poisson-binomial counts;
# undefined recall outcomes are assigned zero, as in the cited paper.
# No deployed detector is retrained. No target labels enter calibration.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import gzip, hashlib, io, json, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.exceptions import ConvergenceWarning
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('LINEAGE_MONITOR_BATCH_E_CBPE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
R={'status':'STARTED','deployed_models_retrained':False,'new_PCAP_replays':0,
   'new_source_only_probability_calibrators_fitted':False,'target_labels_used_for_calibration':False,
   'source_training_disjointness_from_primary_established':False,'injection_control_completed':False,
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
    if not found:raise Stop('Missing completed stage '+status)
    return max(found,key=lambda x:x[0].name)
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def blob(a):
    with opened(a) as f:b=f.read(128*1024**2+1)
    if len(b)>128*1024**2:raise Stop('Bounded input read exceeded')
    return b

def sha(a):return hashlib.sha256(blob(a)).hexdigest()
def table(a):
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded CSV too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df):
    df=df.copy()
    if not set(F+['ks','y']).issubset(df.columns):raise Stop('Required columns missing')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower();y=pd.to_numeric(df.y,errors='raise')
    if not y.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid labels/protocols')
    df['y']=y.astype(int)
    return df

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)
def logit(p):
    p=np.clip(np.asarray(p,float),1e-6,1-1e-6)
    return (np.log(p)-np.log1p(-p)).reshape(-1,1)

def calibration_metrics(y,p):
    y=np.asarray(y,int);p=np.asarray(p,float)
    bins=np.minimum((p*10).astype(int),9);ece=0.
    for k in range(10):
        mask=bins==k
        if mask.any():ece+=float(mask.mean())*abs(float(y[mask].mean()-p[mask].mean()))
    clipped=np.clip(p,1e-12,1-1e-12)
    return {'Brier':float(np.mean((p-y)**2)),
            'log_loss':float(-np.mean(y*np.log(clipped)+(1-y)*np.log1p(-clipped))),
            'ECE_10_equal_width':ece}

def pb(probabilities):
    probabilities=np.asarray(probabilities,float)
    if not np.isfinite(probabilities).all() or ((probabilities<0)|(probabilities>1)).any():raise Stop('Invalid Bernoulli probabilities')
    pmf=np.array([1.])
    for p in probabilities:
        nxt=np.zeros(len(pmf)+1);nxt[:-1]+=pmf*(1-p);nxt[1:]+=pmf*p;pmf=nxt
    mass=float(pmf.sum())
    if not np.isfinite(mass) or abs(mass-1)>1e-8:raise Stop('Poisson-binomial mass check failed')
    return pmf/mass

def wquantile(values,mass,level):
    values=np.asarray(values).ravel();mass=np.asarray(mass).ravel()
    keep=mass>0;values=values[keep];mass=mass[keep]
    order=np.argsort(values,kind='stable');values=values[order];mass=mass[order]
    cumulative=np.cumsum(mass);cumulative/=cumulative[-1]
    return float(values[min(int(np.searchsorted(cumulative,level,side='left')),len(values)-1)])

def cbpe(q,d):
    q=np.asarray(q,float);d=np.asarray(d,bool);n=len(q)
    if not n:raise Stop('Empty monitoring window')
    correct=np.where(d,q,1-q)
    acc_pmf=pb(correct);acc_values=np.arange(n+1)/n
    tp_pmf=pb(q[d]);fn_pmf=pb(q[~d])
    tp=np.arange(len(tp_pmf))[:,None];fn=np.arange(len(fn_pmf))[None,:]
    den=tp+fn;recall_values=np.divide(tp,den,out=np.zeros_like(den,dtype=float),where=den>0)
    joint=tp_pmf[:,None]*fn_pmf[None,:]
    expected_tp=float(q[d].sum());expected_fn=float(q[~d].sum())
    plugin=expected_tp/(expected_tp+expected_fn) if expected_tp+expected_fn else 0.
    result={'expected_TP':expected_tp,'expected_FP':float((1-q[d]).sum()),
            'expected_FN':expected_fn,'expected_TN':float((1-q[~d]).sum()),
            'accuracy_estimate':float(correct.mean()),
            'accuracy_nominal_lower':wquantile(acc_values,acc_pmf,.025),
            'accuracy_nominal_upper':wquantile(acc_values,acc_pmf,.975),
            'record_recall_exact_expectation':float((recall_values*joint).sum()),
            'record_recall_plugin_approximation':plugin,
            'record_recall_nominal_lower':wquantile(recall_values,joint,.025),
            'record_recall_nominal_upper':wquantile(recall_values,joint,.975),
            'zero_positive_count_probability':float(tp_pmf[0]*fn_pmf[0])}
    if not np.isclose(np.dot(acc_values,acc_pmf),result['accuracy_estimate'],atol=1e-10,rtol=0):raise Stop('Accuracy shortcut and exact distribution disagree')
    return result

try:
    a,ar=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    b,_=latest('LINEAGE_MONITOR_BATCH_B_*','P4_FROZEN_ATC_DOC_BATCH_COMPLETE')
    md3,_=latest('LINEAGE_MONITOR_BATCH_D_MD3_*','P4_MD3_WARNING_AND_ORDER_CONTROL_COMPLETE')
    manifest=json.loads((a/'input_manifest.json').read_text())
    inputs=json.loads((b/'calibration_inputs.json').read_text())
    model_hash=sha(manifest['models'])
    if model_hash!=inputs['model_sha256']:raise Stop('Model binding differs')
    if json.loads(blob(inputs['assets']['contract']))!=inputs['contract']:raise Stop('Calibration contract changed')
    source=norm(table(inputs['assets']['reference']))
    if len(source)!=12288 or 'source_scenario' not in source:raise Stop('Unexpected source-reference structure')
    if source.duplicated(['source_scenario','ks']).any():raise Stop('Source keys are not unique; the saved allocation cannot be joined safely')
    allocation=pd.read_csv(md3/'source_membership.csv',dtype=str,keep_default_na=False)
    needed={'source_scenario','ks','allocation'}
    if not needed.issubset(allocation.columns) or allocation.duplicated(['source_scenario','ks']).any():raise Stop('MD3 source allocation is ambiguous')
    index=pd.MultiIndex.from_frame(source[['source_scenario','ks']]);ai=pd.MultiIndex.from_frame(allocation[['source_scenario','ks']])
    if set(index)!=set(ai):raise Stop('MD3 allocation and current source population differ')
    labels=pd.Series(allocation.allocation.to_numpy(),index=ai).reindex(index).to_numpy()
    fit_mask=labels=='MD3_reference';hold_mask=labels=='MD3_source_holdout'
    if fit_mask.sum()!=9830 or hold_mask.sum()!=2458 or not (fit_mask|hold_mask).all():raise Stop('Unexpected fixed source allocation')
    fit=source.loc[fit_mask].reset_index(drop=True);hold=source.loc[hold_mask].reset_index(drop=True)
    allocation.to_csv(OUT/'source_calibration_allocation.csv',index=False)
    clean=norm(table(manifest['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Invalid target sample')
    frames={0:clean};y=clean.y.to_numpy(int)
    for cond in manifest['conditions']:
        if sha(cond['candidate_asset'])!=cond['candidate_sha256']:raise Stop('Target input changed')
        frame=norm(table(cond['candidate_asset']))
        if frame.ks.duplicated().any() or set(frame.ks)!=set(clean.ks):raise Stop('Target membership differs')
        frame=frame.set_index('ks').loc[clean.ks].reset_index()
        if not np.array_equal(frame.y.to_numpy(int),y):raise Stop('Target labels differ')
        frames[int(cond['delay_seconds'])]=frame
    if set(frames)!={0,1,3,10}:raise Stop('Expected four validated conditions')
    banks={int(k):v for k,v in joblib.load(io.BytesIO(blob(manifest['models'])))['models'].items()}
    if set(banks)!={8101,8102,8103}:raise Stop('Unexpected seeds')
    old_pred=pd.read_csv(a/'primary_prediction_checks.csv.gz',dtype={'ks':str})
    target=pd.read_csv(a/'fixed_window_warning_results.csv');target=target[target.estimator.eq('AC')].copy()
    if target.duplicated(['delay_seconds','seed','window']).any():raise Stop('Duplicate fixed-window outcomes')
    WIN=int(ar['window_size']);THRESH=float(ar['warning_drop_threshold'])
    policy={'reference':'Kivimaki et al., Machine Learning 115:67, 2026, DOI 10.1007/s10994-025-06970-3',
            'implementation':'Direct formula reproduction, not NannyML package reproduction',
            'calibrator':'LogisticRegression on clipped raw probability logit; C=1, solver=lbfgs, max_iter=2000',
            'clip_epsilon':1e-6,'calibration_allocation':'Reuse fixed MD3 source reference/holdout; no new split',
            'frozen_decisions':'original uncalibrated primary probability >= 0.5; never recalculated from calibrated probability',
            'accuracy':'exact expectation and Poisson-binomial distribution',
            'record_recall':'exact TP/FN joint-distribution expectation; zero-denominator outcomes assigned zero',
            'intervals':'95% equal-tail nominal model intervals; calibration and conditional independence are assumptions, not established guarantees',
            'window_order':'same saved-order blocks as Batches A/B/C','post_exposure':True,
            'original_unit_recall_estimated':False,'source_overlap_with_primary_training_excluded':False}
    js(OUT/'CBPE_policy.json',policy)
    js(OUT/'input_manifest.json',{'model_sha256':model_hash,'inputs':manifest,'source_assets':inputs['assets'],'source_allocation':str(md3/'source_membership.csv')})
    source_metrics=[];whole=[];window_rows=[];score_rows=[];calibrators={}
    print('[1/3] Fit three one-dimensional source-only probability calibrators; deployed models stay frozen.',flush=True)
    with threadpool_limits(limits=2):
        for seed,bank in sorted(banks.items()):
            model=bank['PRIMARY']
            if list(model.classes_)!=[0,1]:raise Stop('Unexpected primary label ordering')
            pf=model.predict_proba(encode(fit))[:,1];ph=model.predict_proba(encode(hold))[:,1]
            cal=LogisticRegression(C=1.0,solver='lbfgs',max_iter=2000,random_state=64501)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always',ConvergenceWarning);cal.fit(logit(pf),fit.y.to_numpy())
                if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed calibrator did not converge')
            if abs(float(cal.coef_[0,0]))<1e-12:raise Stop('Calibrator collapsed to a constant; confidence-consistency needs separate treatment')
            calibrators[seed]=cal
            qh=cal.predict_proba(logit(ph))[:,1]
            for state,p in [('RAW',ph),('SOURCE_PLATT_CALIBRATED',qh)]:
                source_metrics.append({'seed':seed,'state':state,'source_holdout_rows':len(hold),
                    **calibration_metrics(hold.y.to_numpy(),p),'frozen_primary_accuracy':float(((ph>=.5)==hold.y.to_numpy()).mean()),
                    'calibrator_slope':float(cal.coef_[0,0]),'calibrator_intercept':float(cal.intercept_[0])})
            p0=model.predict_proba(encode(clean))[:,1];d0=p0>=.5;q0=cal.predict_proba(logit(p0))[:,1]
            clean_cbpe=cbpe(q0,d0)
            for delay,frame in sorted(frames.items()):
                p=model.predict_proba(encode(frame))[:,1];d=p>=.5;q=cal.predict_proba(logit(p))[:,1]
                previous=old_pred[old_pred.seed.eq(seed)&old_pred.delay_seconds.eq(delay)]
                if previous.ks.duplicated().any() or set(previous.ks)!=set(clean.ks):raise Stop('Saved prediction membership differs')
                if not np.array_equal(boolean(previous.set_index('ks').loc[clean.ks,'primary_predicted_malicious']),d):raise Stop('Frozen predictions no longer reproduce')
                if not np.isclose(np.where(d,p,1-p).mean(),np.maximum(p,1-p).mean(),atol=1e-12,rtol=0):raise Stop('Raw CBPE accuracy does not equal AC')
                estimate=cbpe(q,d);truth=float((d==y).mean());truth0=float((d0==y).mean());recall=float(d[y==1].mean()) if (y==1).any() else np.nan
                whole.append({'delay_seconds':delay,'seed':seed,'rows':len(y),'true_record_accuracy':truth,
                    'true_selected_record_recall':recall,**estimate,
                    'accuracy_absolute_error':abs(estimate['accuracy_estimate']-truth),
                    'accuracy_overestimation':estimate['accuracy_estimate']-truth,
                    'record_recall_absolute_error':abs(estimate['record_recall_exact_expectation']-recall),
                    'true_record_accuracy_drop':truth0-truth,
                    'estimated_record_accuracy_drop':clean_cbpe['accuracy_estimate']-estimate['accuracy_estimate'],
                    'differential_error':abs((clean_cbpe['accuracy_estimate']-estimate['accuracy_estimate'])-(truth0-truth)),
                    'true_accuracy_inside_nominal_interval':estimate['accuracy_nominal_lower']<=truth<=estimate['accuracy_nominal_upper'],
                    'calibrated_target_ECE_offline_only':calibration_metrics(y,q)['ECE_10_equal_width']})
                score_rows.extend({'seed':seed,'delay_seconds':delay,'ks':str(k),'raw_probability':float(rp),
                                   'calibrated_probability':float(cp),'frozen_prediction':bool(dp)} for k,rp,cp,dp in zip(clean.ks,p,q,d))
                for start in range(0,len(clean),WIN):
                    sl=slice(start,start+WIN);wi=start//WIN
                    outcome=target[target.seed.eq(seed)&target.delay_seconds.eq(delay)&target.window.eq(wi)]
                    if len(outcome)!=1:raise Stop('Fixed warning outcome is not unique')
                    baseline=cbpe(q0[sl],d0[sl]);current=cbpe(q[sl],d[sl])
                    actual=float((d[sl]==y[sl]).mean());actual0=float((d0[sl]==y[sl]).mean())
                    row=outcome.iloc[0].to_dict();drop=baseline['accuracy_estimate']-current['accuracy_estimate']
                    row.update({'estimator':'CBPE_SOURCE_PLATT_EXACT','estimated_record_accuracy_drop':drop,'monitor_warning':drop>=THRESH,
                        'record_accuracy':actual,'accuracy_estimate':current['accuracy_estimate'],
                        'accuracy_absolute_error':abs(current['accuracy_estimate']-actual),
                        'differential_error':abs(drop-(actual0-actual)),
                        'accuracy_nominal_lower':current['accuracy_nominal_lower'],'accuracy_nominal_upper':current['accuracy_nominal_upper'],
                        'true_accuracy_inside_nominal_interval':current['accuracy_nominal_lower']<=actual<=current['accuracy_nominal_upper'],
                        'record_recall_exact_expectation':current['record_recall_exact_expectation']})
                    window_rows.append(row)
            print('Completed CBPE seed:',seed,flush=True)
    R['new_source_only_probability_calibrators_fitted']=True
    joblib.dump(calibrators,OUT/'source_only_probability_calibrators.joblib',compress=3)
    sm=pd.DataFrame(source_metrics);ag=pd.DataFrame(whole);win=pd.DataFrame(window_rows)
    sm.to_csv(OUT/'source_holdout_calibration_metrics.csv',index=False);ag.to_csv(OUT/'CBPE_whole_sample_results.csv',index=False)
    win.to_csv(OUT/'CBPE_window_results.csv',index=False)
    pd.DataFrame(score_rows).to_csv(OUT/'CBPE_probability_scores.csv.gz',index=False,compression='gzip')
    print('\nEXPERIMENT 1 — SOURCE HOLDOUT CALIBRATION\n'+sm.to_string(index=False),flush=True)
    print('\nEXPERIMENT 2 — EXACT CBPE RECORD METRICS\n'+ag[['delay_seconds','seed','true_record_accuracy','accuracy_estimate','accuracy_absolute_error','true_selected_record_recall','record_recall_exact_expectation','record_recall_absolute_error','accuracy_nominal_lower','accuracy_nominal_upper','true_accuracy_inside_nominal_interval','calibrated_target_ECE_offline_only']].to_string(index=False),flush=True)
    warning_rows=[]
    for delay,g in win.groupby('delay_seconds'):
        for name,column in [('RECORD_ACCURACY_DAMAGE','record_damage_ge_5pp'),('ORIGINAL_UNIT_DETECTION_DAMAGE','original_unit_damage_ge_5pp')]:
            z=g[g[column].notna()];truth=boolean(z[column]);warn=z.monitor_warning.to_numpy(bool)
            tp=int((truth&warn).sum());fn=int((truth&~warn).sum());fp=int((~truth&warn).sum());tn=int((~truth&~warn).sum())
            warning_rows.append({'delay_seconds':delay,'warning_target':name,'seed_window_rows_not_independent_captures':len(z),
                'TP':tp,'FN':fn,'FP':fp,'TN':tn,'warning_TPR':tp/(tp+fn) if tp+fn else np.nan,'warning_FPR':fp/(fp+tn) if fp+tn else np.nan})
    ws=pd.DataFrame(warning_rows);ws.to_csv(OUT/'CBPE_warning_target_comparison.csv',index=False)
    print('\nEXPERIMENT 3 — CBPE ACCURACY-DROP WARNINGS\n'+ws.to_string(index=False),flush=True)
    R.update({'status':'P4_CBPE_SOURCE_CALIBRATION_AND_EXACT_METRICS_COMPLETE','source_fit_rows':len(fit),'source_holdout_rows':len(hold),
              'whole_sample_rows':len(ag),'monitoring_window_rows':len(win),'deployed_decisions_unchanged':True,
              'accuracy_and_record_recall_distributions_computed':True,'conditional_independence_assumed_for_distributions':True,
              'target_calibration_established':False,'nominal_intervals_have_unconditional_coverage_guarantee':False,
              'CBPE_official_package_reproduction_claimed':False,'original_unit_recall_estimated':False,
              'capture49_baseline_panel_computations_run':['AC','semantic agreement','frozen ATC','frozen source-offset confidence','existing gate and ablations','SVM-margin MD3 warning','CBPE formula reproduction'],
              'overall_P4_complete':False,
              'remaining_work':['Baseline-fidelity and window-order reconciliation','Capture-1-1 injection control','Cross-capture/model/configuration evaluation','Final protocol/resources/claim-evidence package']})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'CBPE_batch_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
