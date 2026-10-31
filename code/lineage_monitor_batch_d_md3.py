# P4 Batch D: actual SVM-margin Menelaus MD3 warning stage and ordering control.
# Baseline settings follow uploaded notebook cell 256. Not an accuracy estimator.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import copy, gzip, hashlib, importlib.metadata, io, json, subprocess, sys, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.exceptions import ConvergenceWarning
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('LINEAGE_MONITOR_BATCH_D_MD3_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
R={'status':'STARTED','deployed_models_retrained':False,'auxiliary_source_SVM_trained':False,
   'new_PCAP_replays':0,'oracle_confirmation_executed':False,'source_training_disjointness_from_primary_established':False,
   'injection_control_completed':False,'independent_confirmation':False,'output_directory':str(OUT)}
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
    if not set(F+['ks','y']).issubset(df.columns):raise Stop('Missing required sample fields')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or (df[c]<0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.str.lower();y=pd.to_numeric(df.y,errors='raise')
    if not y.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid labels/protocols')
    df['y']=y.astype(int)
    return df

def matrix(df):
    return pd.DataFrame(np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]]),columns=F[:-1]+['proto_tcp','proto_udp','proto_icmp'])

def svm_margin(detector,sample,classifier):
    row=pd.DataFrame([sample],columns=detector.reference_batch_features.columns)
    return int(abs(float(classifier.decision_function(row)[0]))<=1.0)

try:
    a,_=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    b,_=latest('LINEAGE_MONITOR_BATCH_B_*','P4_FROZEN_ATC_DOC_BATCH_COMPLETE')
    c,_=latest('LINEAGE_MONITOR_BATCH_C_*','P4_GATE_AND_TWO_ABLATIONS_COMPLETE')
    manifest=json.loads((a/'input_manifest.json').read_text())
    calibration=json.loads((b/'calibration_inputs.json').read_text())
    model_hash=sha(manifest['models'])
    if model_hash!=calibration['model_sha256']:raise Stop('Current model identity differs from source calibration')
    if json.loads(blob(calibration['assets']['contract']))!=calibration['contract']:raise Stop('Calibration contract changed')
    source=norm(table(calibration['assets']['reference']))
    if len(source)!=12288 or 'source_scenario' not in source:raise Stop('Unexpected source-reference schema')
    allowed={'CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1'}
    if set(source.source_scenario)!=allowed:raise Stop('Reference contains unexpected scenarios')
    clean=norm(table(manifest['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Invalid clean target membership')
    frames={0:clean}
    for x in manifest['conditions']:
        if sha(x['candidate_asset'])!=x['candidate_sha256']:raise Stop('Changed target feature artifact')
        frame=norm(table(x['candidate_asset']))
        if frame.ks.duplicated().any() or set(frame.ks)!=set(clean.ks):raise Stop('Target key set differs')
        frame=frame.set_index('ks').loc[clean.ks].reset_index()
        if not np.array_equal(frame.y.to_numpy(),clean.y.to_numpy()):raise Stop('Target labels differ')
        frames[int(x['delay_seconds'])]=frame
    if set(frames)!={0,1,3,10}:raise Stop('Expected four validated conditions')
    # Install only the previously used pure-Python baseline package if absent.
    try:version=importlib.metadata.version('menelaus')
    except importlib.metadata.PackageNotFoundError:
        print('Installing only menelaus==0.2.0; Kaggle Internet is required.',flush=True)
        log=OUT/'menelaus_install.log'
        with open(log,'w') as f:
            p=subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-deps','menelaus==0.2.0'],stdout=f,stderr=subprocess.STDOUT,timeout=240)
        if p.returncode:raise Stop('Menelaus installation failed; see menelaus_install.log')
        version=importlib.metadata.version('menelaus')
    if version!='0.2.0':raise Stop('Menelaus version is '+version+'; expected 0.2.0. Existing installation was not replaced.')
    from menelaus.concept_drift.md3 import MD3
    policy={'baseline':'Menelaus 0.2.0 MD3 warning stage with separate source-only linear SVM',
            'source_split_seed':64201,'source_reference_fraction':.8,'strata':'source_scenario | y',
            'SVM':{'C':1.0,'dual':'auto','max_iter':20000,'random_state':64401},
            'preprocessing':'historical log1p numerical fields + protocol indicators + StandardScaler',
            'margin':'abs(SVM decision_function)<=1.0','sensitivity':2,'reference_CV_folds':10,
            'oracle_confirmation':'not run; stop at first request for oracle',
            'target_order_1':'saved sample order; not claimed chronological',
            'target_order_2':'SHA256(MD3_ORDER_SENSITIVITY_v1|ks), same permutation across conditions',
            'target_order_2_is_chronological':False,'target_labels_used_for_fitting_or_order':False,
            'source_training_overlap_with_deployed_model_excluded':False,
            'scope':'post-exposure baseline and ordering sensitivity; not exact original-paper hyperparameter replication'}
    js(OUT/'baseline_policy.json',policy)
    strata=source.source_scenario.astype(str)+'|'+source.y.astype(str)
    fit_idx,hold_idx=train_test_split(np.arange(len(source)),test_size=.2,random_state=64201,stratify=strata)
    fit=source.iloc[fit_idx].reset_index(drop=True);hold=source.iloc[hold_idx].reset_index(drop=True)
    fit_ids=set(zip(fit.source_scenario,fit.ks));hold_ids=set(zip(hold.source_scenario,hold.ks))
    if fit_ids&hold_ids:raise Stop('Source fit/holdout original keys overlap; no new allocation silently substituted')
    pd.concat([pd.DataFrame({'source_scenario':fit.source_scenario,'ks':fit.ks,'allocation':'MD3_reference'}),
               pd.DataFrame({'source_scenario':hold.source_scenario,'ks':hold.ks,'allocation':'MD3_source_holdout'})],ignore_index=True).to_csv(OUT/'source_membership.csv',index=False)
    Xfit=matrix(fit);Xhold=matrix(hold)
    svm=Pipeline([('scale',StandardScaler()),('svm',LinearSVC(C=1.0,dual='auto',max_iter=20000,random_state=64401))])
    print('[1/3] Fitting the separate source-only MD3 SVM and its source CV reference.',flush=True)
    with threadpool_limits(limits=2),warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always',ConvergenceWarning)
        svm.fit(Xfit,fit.y.to_numpy());R['auxiliary_source_SVM_trained']=True
        prototype=MD3(svm,margin_calculation_function=svm_margin,sensitivity=2,k=10)
        reference=Xfit.copy();reference['target']=fit.y.to_numpy()
        prototype.set_reference(reference,target_name='target')
        if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('SVM fit/CV did not converge under the fixed settings')
    joblib.dump(svm,OUT/'source_only_MD3_SVM.joblib',compress=3)
    stats={k:float(v) for k,v in prototype.reference_distribution.items()}
    js(OUT/'MD3_reference_statistics.json',stats)
    def recurrence(scores):
        signals=np.abs(scores)<=1.0
        density=float(prototype.reference_distribution['md']);mu=density
        threshold=prototype.sensitivity*float(prototype.reference_distribution['md_std'])
        forgetting=float(prototype.forgetting_factor);first=None;maxdev=0.;used=0
        for i,signal in enumerate(signals):
            density=forgetting*density+(1-forgetting)*int(signal)
            dev=abs(density-mu);maxdev=max(maxdev,dev);used=i+1
            if dev>threshold:first=i+1;break
        return {'warning':first is not None,'first_warning_row':first,'rows_consumed':used,
                'terminal_margin_density':density,'maximum_density_deviation':maxdev,
                'warning_threshold':threshold,'whole_stream_margin_density':float(signals.mean())}
    def evaluate_stream(X,label,verify_library=True):
        scores=svm.decision_function(X);expected=recurrence(scores)
        if verify_library:
            detector=copy.deepcopy(prototype);first=None
            for i in range(len(X)):
                detector.update(X.iloc[[i]])
                if detector.waiting_for_oracle:first=i+1;break
            if first!=expected['first_warning_row']:raise Stop('Accelerated recurrence does not match actual library warning: '+label)
            if not np.isclose(detector.curr_margin_density,expected['terminal_margin_density'],atol=1e-12,rtol=0):raise Stop('Library margin-density state mismatch: '+label)
        return {**expected,'actual_library_warning_verified':verify_library}
    with threadpool_limits(limits=2):
        source_result=evaluate_stream(Xhold,'source_holdout')
        source_result.update({'rows':len(hold),'source_SVM_accuracy':float((svm.predict(Xhold)==hold.y.to_numpy()).mean())})
    pd.DataFrame([source_result]).to_csv(OUT/'experiment1_source_holdout.csv',index=False)
    print('\nEXPERIMENT 1 — SOURCE HOLDOUT AND LIBRARY VERIFICATION\n'+pd.DataFrame([source_result]).to_string(index=False),flush=True)
    order_hash=np.argsort([hashlib.sha256(('MD3_ORDER_SENSITIVITY_v1|'+str(k)).encode()).hexdigest() for k in clean.ks],kind='stable')
    orders={'SAVED_SAMPLE_ORDER':np.arange(len(clean)),'LABEL_FREE_HASH_ORDER':order_hash}
    target_rows=[]
    with threadpool_limits(limits=2):
        for order_name,order in orders.items():
            for delay,frame in sorted(frames.items()):
                ordered=frame.iloc[order].reset_index(drop=True);X=matrix(ordered)
                result=evaluate_stream(X,f'{order_name}/{delay}s')
                target_rows.append({'ordering':order_name,'delay_seconds':delay,'rows':len(X),
                    'auxiliary_SVM_accuracy':float((svm.predict(X)==ordered.y.to_numpy()).mean()),**result})
                print('MD3 completed:',order_name,delay,'seconds',flush=True)
    results=pd.DataFrame(target_rows);results.to_csv(OUT/'MD3_target_stream_results.csv',index=False)
    for name,title in [('SAVED_SAMPLE_ORDER','EXPERIMENT 2 — EXISTING ROW ORDER'),('LABEL_FREE_HASH_ORDER','EXPERIMENT 3 — LABEL-FREE ORDER SENSITIVITY')]:
        print('\n'+title+'\n'+results[results.ordering.eq(name)].to_string(index=False),flush=True)
    contrasts=[]
    for ordering,g in results.groupby('ordering'):
        base=g[g.delay_seconds.eq(0)].iloc[0]
        for row in g.to_dict('records'):
            contrasts.append({'ordering':ordering,'delay_seconds':row['delay_seconds'],
                'clean_warning':bool(base.warning),'condition_warning':bool(row['warning']),
                'condition_only_warning':bool(row['warning'] and not base.warning),
                'clean_only_warning':bool(base.warning and not row['warning']),
                'clean_first_warning_row':base.first_warning_row,'condition_first_warning_row':row['first_warning_row']})
    co=pd.DataFrame(contrasts);co.to_csv(OUT/'MD3_clean_condition_contrasts.csv',index=False)
    print('\nCLEAN-VERSUS-CONDITION WARNINGS\n'+co.to_string(index=False),flush=True)
    R.update({'status':'P4_MD3_WARNING_AND_ORDER_CONTROL_COMPLETE','menelaus_version':version,
              'source_reference_rows':len(fit),'source_holdout_rows':len(hold),'target_streams':len(results),
              'actual_library_verified_on_every_stream':True,'deployed_primary_models_loaded_or_refitted':False,
              'source_SVM_CV_clone_fitting':True,'remaining_P4_methods':['CBPE'],
              'interpretation':'MD3 warns about margin-density change, not true accuracy. Source/target order is explicit. First-warning row is an input index, not elapsed seconds. Same-capture conditions are not independent trials.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'MD3_batch_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
