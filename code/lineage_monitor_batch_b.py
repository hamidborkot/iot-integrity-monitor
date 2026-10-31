# P4 Batch B: frozen source-calibrated ATC, DoC, and warning-target comparison.
# Formula contract: uploaded notebook cell 221. No calibration is refitted.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from collections import defaultdict
import os, io, gzip, hashlib, json, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');OWNER=Path('/kaggle/input/datasets/mdhamidborkottulla')
OUT=W/('LINEAGE_MONITOR_BATCH_B_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
FAMILY='TRACE_CONFIRMATORY_SOURCE_CALIBRATION_20261012T175838844123Z'
ROOTS=[W]+[OWNER/n for n in ['zeek-new','full-backup','all-kaggle-work','complete-backup','last-day-backup','one-last','ran-files','the-last-update','whole-in-one','the-last-days-backup']]
R={'status':'STARTED','models_retrained':False,'calibration_refitted':False,'new_PCAP_replays':0,
   'injection_control_completed':False,'source_training_disjointness_established':False,
   'independent_confirmation':False,'output_directory':str(OUT)}
LIMIT=128*1024**2
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def blob(a):
    with opened(a) as f:b=f.read(LIMIT+1)
    if len(b)>LIMIT:raise Stop('Input exceeds bounded-read limit')
    return b

def digest(a):return hashlib.sha256(blob(a)).hexdigest()
def csv(a):
    b=blob(a)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(LIMIT+1)
        if len(b)>LIMIT:raise Stop('Expanded CSV exceeds limit')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df):
    df=df.copy()
    required=set(F+['ks','y'])
    if not required.issubset(df.columns):raise Stop('Required reference/sample columns missing: '+str(required-set(df.columns)))
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid numeric predictor '+c)
    df['proto']=df.proto.str.lower();labels=pd.to_numeric(df.y,errors='raise')
    if not labels.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid protocol or label')
    df['y']=labels.astype(int)
    return df

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean column '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)

def calibration_groups():
    groups=defaultdict(dict);errors=[];archives=[]
    names={'calibration_contract.json':'contract','source_seed_calibration_statistics.csv':'stats',
           'source_reference_sample.csv.gz':'reference','source_reference_sample.csv':'reference'}
    def add(path,member,name):
        value=member or str(path)
        parts=Path(value).parts
        if FAMILY not in parts or name not in names:return
        parent=str(Path(value).parent)
        group=(str(path),parent) if member else ('directory',parent)
        kind=names[name];a={'path':str(path),'member':member}
        old=groups[group].get(kind)
        # Prefer the original .csv.gz file over its uncompressed convenience copy.
        if old is None or (kind=='reference' and value.endswith('.csv.gz')):groups[group][kind]=a
    for root in ROOTS:
        if not root.is_dir():continue
        for current,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if d not in ['.git','__pycache__'] and not d.startswith('LINEAGE_MONITOR_BATCH_B_')]
            for name in files:
                p=Path(current)/name
                if p.is_symlink():continue
                if name in names and FAMILY in p.parts:add(p,'',name)
                elif name.lower().endswith('.zip'):archives.append(p)
    for p in archives:
        try:
            with zipfile.ZipFile(p) as z:
                for m in z.infolist():
                    if not m.is_dir() and m.file_size<=LIMIT:add(p,m.filename,Path(m.filename).name)
        except (OSError,zipfile.BadZipFile) as e:errors.append({'path':str(p),'error':str(e)})
    js(OUT/'archive_errors.json',errors)
    return [g for g in groups.values() if {'contract','stats','reference'}.issubset(g)]

def canonical_source(df):
    cols=['source_scenario','ks','y']+F
    x=df[cols].sort_values(cols,kind='stable').reset_index(drop=True)
    return hashlib.sha256(pd.util.hash_pandas_object(x,index=False).to_numpy().tobytes()).hexdigest()

try:
    completed=[]
    for p in W.glob('LINEAGE_MONITOR_BATCH_A_*'):
        rp=p/'receipt.json'
        if rp.is_file():
            r=json.loads(rp.read_text())
            if r.get('status')=='P4_AC_AGREEMENT_BATCH_COMPLETE':completed.append((p,r))
    if not completed:raise Stop('Completed monitor Batch A is required')
    prior,policy=max(completed,key=lambda x:x[0].name)
    WINDOW=int(policy['window_size']);THRESHOLD=float(policy['warning_drop_threshold'])
    manifest=json.loads((prior/'input_manifest.json').read_text())
    model_asset=manifest['models'];model_hash=digest(model_asset)
    if model_asset.get('sha256') and model_hash!=model_asset['sha256']:raise Stop('Frozen model hash changed')
    print('[1/3] Resolving only the frozen source-calibration artifacts.',flush=True)
    groups=calibration_groups();variants=defaultdict(list);candidate_audit=[]
    for group in groups:
        try:
            contract=json.loads(blob(group['contract']))
            if contract.get('source_model_bundle_sha256')!=model_hash:raise Stop('Calibration contract belongs to a different model bundle')
            source=norm(csv(group['reference']));stats=csv(group['stats'])
            if len(source)!=12288 or 'source_scenario' not in source:raise Stop('Unexpected frozen reference schema/size')
            allowed={'CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1'}
            if set(source.source_scenario)!=allowed:raise Stop('Reference includes unexpected scenarios')
            fields=['seed','primary_reference_accuracy','primary_reference_confidence','ATC_confidence_threshold']
            if not set(fields).issubset(stats.columns):raise Stop('Frozen calibration statistics schema mismatch')
            st=stats[fields].copy()
            for c in fields:st[c]=pd.to_numeric(st[c],errors='raise')
            st['seed']=st.seed.astype(int);st=st.sort_values('seed').reset_index(drop=True)
            if len(st)!=3 or set(st.seed)!={8101,8102,8103}:raise Stop('Unexpected source-calibration seeds')
            signature=canonical_source(source)+'|'+st.to_json(orient='split',index=False,double_precision=15)+'|'+str(contract.get('calibration_contract_sha256'))
            sig=hashlib.sha256(signature.encode()).hexdigest()
            variants[sig].append((group,contract,source,st))
            candidate_audit.append({'group':group,'status':'MODEL_BOUND_REFERENCE','semantic_signature':sig})
        except Exception as e:candidate_audit.append({'group':group,'status':str(e)})
    js(OUT/'calibration_candidate_audit.json',candidate_audit)
    if len(variants)!=1:raise Stop(f'Found {len(variants)} distinct compatible calibration sets. No arbitrary set selected; see calibration_candidate_audit.json')
    candidates=next(iter(variants.values()))
    group,contract,reference,stats=min(candidates,key=lambda x:(bool(x[0]['reference'].get('member')),len(x[0]['reference']['path']),x[0]['reference']['path']))
    js(OUT/'calibration_inputs.json',{'assets':group,'model_sha256':model_hash,
        'contract':contract,'source_rows':len(reference),
        'source_duplicate_scenario_keys':int(reference.duplicated(['source_scenario','ks']).sum()),
        'source_training_disjointness_established':False})
    clean=norm(csv(manifest['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Historical target membership invalid')
    y=clean.y.to_numpy(int);frames={0:clean}
    for condition in manifest['conditions']:
        delay=int(condition['delay_seconds']);a=condition['candidate_asset']
        if digest(a)!=condition['candidate_sha256']:raise Stop('Changed candidate features')
        frame=norm(csv(a))
        if frame.ks.duplicated().any() or set(frame.ks)!=set(clean.ks):raise Stop('Candidate keys differ')
        frame=frame.set_index('ks').loc[clean.ks].reset_index()
        if not np.array_equal(frame.y.to_numpy(int),y):raise Stop('Target labels differ')
        frames[delay]=frame
    if set(frames)!={0,1,3,10}:raise Stop('Expected the four validated conditions')
    bundle=joblib.load(io.BytesIO(blob(model_asset)));banks={int(k):v for k,v in bundle['models'].items()}
    if set(banks)!={8101,8102,8103}:raise Stop('Unexpected model bank')
    previous_predictions=pd.read_csv(prior/'primary_prediction_checks.csv.gz',dtype={'ks':str})
    previous_windows=pd.read_csv(prior/'fixed_window_warning_results.csv')
    target_windows=previous_windows[previous_windows.estimator.eq('AC')].copy()
    if target_windows.duplicated(['delay_seconds','seed','window']).any():raise Stop('Duplicate baseline windows')
    rows=[];windows=[];audits=[]
    print('[2/3] Reproducing frozen source statistics; evaluating ATC and DoC without refitting.',flush=True)
    with threadpool_limits(limits=2):
        for seed in sorted(banks):
            model=banks[seed]['PRIMARY']
            if list(model.classes_)!=[0,1]:raise Stop('Unexpected primary label order')
            ref=stats[stats.seed.eq(seed)].iloc[0]
            pr=model.predict_proba(encode(reference))[:,1];cr=np.maximum(pr,1-pr)
            acc=float(((pr>=.5)==reference.y.to_numpy(int)).mean());conf=float(cr.mean())
            threshold=float(ref.ATC_confidence_threshold)
            if not np.isfinite(threshold):raise Stop('Nonfinite frozen ATC threshold')
            audit={'seed':seed,'source_rows':len(reference),'recorded_source_accuracy':float(ref.primary_reference_accuracy),
                   'recomputed_source_accuracy':acc,'recorded_source_confidence':float(ref.primary_reference_confidence),
                   'recomputed_source_confidence':conf,'frozen_ATC_threshold':threshold,
                   'source_ATC_fraction_ge_threshold':float((cr>=threshold).mean()),
                   'ATC_source_matching_error':abs(float((cr>=threshold).mean())-acc),
                   'confidence_ties_at_threshold':int((cr==threshold).sum()),
                   'source_training_disjointness_established':False}
            audits.append(audit)
            pd.DataFrame(audits).to_csv(OUT/'source_statistics_reproduction.csv',index=False)
            if not np.isclose(acc,ref.primary_reference_accuracy,atol=1e-8,rtol=0) or not np.isclose(conf,ref.primary_reference_confidence,atol=1e-8,rtol=0):
                raise Stop('Frozen source statistics do not reproduce; no target result interpreted')
            def estimate(c,method):
                if method=='ATC_FROZEN':return float((c>=threshold).mean())
                return float(np.clip(float(ref.primary_reference_accuracy)+c.mean()-float(ref.primary_reference_confidence),0,1))
            p0=model.predict_proba(encode(clean))[:,1];d0=p0>=.5;c0=np.maximum(p0,1-p0)
            for delay,frame in sorted(frames.items()):
                p=model.predict_proba(encode(frame))[:,1];d=p>=.5;c=np.maximum(p,1-p)
                previous=previous_predictions[previous_predictions.seed.eq(seed)&previous_predictions.delay_seconds.eq(delay)]
                if previous.ks.duplicated().any() or set(previous.ks)!=set(clean.ks):raise Stop('Saved prediction membership differs')
                recorded=boolean(previous.set_index('ks').loc[clean.ks,'primary_predicted_malicious'])
                if not np.array_equal(recorded,d):raise Stop('Primary predictions differ from completed Batch A')
                truth=float((d==y).mean());truth0=float((d0==y).mean())
                for method in ['ATC_FROZEN','DoC_FROZEN']:
                    e0=estimate(c0,method);e=estimate(c,method)
                    rows.append({'delay_seconds':delay,'seed':seed,'estimator':method,'clean_record_accuracy':truth0,
                        'record_accuracy':truth,'true_record_accuracy_drop':truth0-truth,'clean_estimate':e0,'estimate':e,
                        'estimated_record_accuracy_drop':e0-e,'current_absolute_error':abs(e-truth),
                        'current_overestimation':e-truth,'differential_error':abs((e0-e)-(truth0-truth))})
                    for start in range(0,len(clean),WINDOW):
                        sl=slice(start,min(start+WINDOW,len(clean)));window=start//WINDOW
                        original=target_windows[target_windows.seed.eq(seed)&target_windows.delay_seconds.eq(delay)&target_windows.window.eq(window)]
                        if len(original)!=1:raise Stop('Fixed window target is not unique')
                        row=original.iloc[0].to_dict();edrop=estimate(c0[sl],method)-estimate(c[sl],method)
                        row.update({'estimator':method,'estimated_record_accuracy_drop':edrop,'monitor_warning':edrop>=THRESHOLD})
                        windows.append(row)
    ag=pd.DataFrame(rows);win=pd.DataFrame(windows)
    ag.to_csv(OUT/'frozen_ATC_DoC_results.csv',index=False);win.to_csv(OUT/'frozen_ATC_DoC_windows.csv',index=False)
    combined=pd.concat([previous_windows,win],ignore_index=True)
    combined.to_csv(OUT/'four_monitor_windows.csv',index=False)
    print('\nSOURCE STATISTICS AUDIT\n'+pd.DataFrame(audits).to_string(index=False),flush=True)
    cols=['delay_seconds','seed','true_record_accuracy_drop','estimated_record_accuracy_drop','current_absolute_error','current_overestimation','differential_error']
    print('\nEXPERIMENT 1 — FROZEN SOURCE-CALIBRATED ATC\n'+ag[ag.estimator.eq('ATC_FROZEN')][cols].to_string(index=False),flush=True)
    print('\nEXPERIMENT 2 — FROZEN DIFFERENCE OF CONFIDENCE\n'+ag[ag.estimator.eq('DoC_FROZEN')][cols].to_string(index=False),flush=True)
    summary=[]
    for (delay,method),g in combined.groupby(['delay_seconds','estimator']):
        for target,column in [('RECORD_ACCURACY_DAMAGE','record_damage_ge_5pp'),('ORIGINAL_UNIT_DETECTION_DAMAGE','original_unit_damage_ge_5pp')]:
            z=g[g[column].notna()];truth=boolean(z[column]);alarm=boolean(z.monitor_warning)
            tp=int((truth&alarm).sum());fn=int((truth&~alarm).sum());fp=int((~truth&alarm).sum());tn=int((~truth&~alarm).sum())
            summary.append({'delay_seconds':delay,'estimator':method,'warning_target':target,'seed_window_rows_not_independent_captures':len(z),
                'TP':tp,'FN':fn,'FP':fp,'TN':tn,'warning_TPR':tp/(tp+fn) if tp+fn else np.nan,'warning_FPR':fp/(fp+tn) if fp+tn else np.nan})
    ws=pd.DataFrame(summary);ws.to_csv(OUT/'four_monitor_warning_comparison.csv',index=False)
    print('\nANALYSIS 3 — FOUR-MONITOR WARNING COMPARISON\n'+ws.to_string(index=False),flush=True)
    R.update({'status':'P4_FROZEN_ATC_DOC_BATCH_COMPLETE','source_statistics_reproduced':True,
              'ATC_operator':'confidence >= frozen source threshold','DoC_operator':'clip(source accuracy + target mean confidence - source mean confidence, 0, 1)',
              'window_size':WINDOW,'warning_drop_threshold':THRESHOLD,'threshold_calibrated_to_5_percent_FPR':False,
              'remaining_P4_methods':['CBPE','existing gate','MD3 warning baseline'],
              'interpretation':'Post-exposure fixed-baseline evaluation. Source statistics consistency does not establish source training/calibration independence or target calibration.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'monitor_batch_b_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nSmall result package:',package,flush=True)
