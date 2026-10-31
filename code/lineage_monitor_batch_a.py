# P4, Batch A: AC, semantic agreement, and fixed-threshold warning comparison.
# Reuses completed Capture-49 packet-mapped experiments; no PCAP replay.
from pathlib import Path
from datetime import datetime, timezone
import hashlib, io, json, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

WORK=Path('/kaggle/working')
OUT=WORK/('LINEAGE_MONITOR_BATCH_A_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True,exist_ok=False)
WINDOW=128
WARNING_DROP=0.05
DELAYS=[0,1,3,10]
SEEDS={8101,8102,8103}
R={'status':'STARTED','models_retrained':False,'new_PCAP_replays':0,'injection_control_completed':False,
   'window_size':WINDOW,'warning_drop_threshold':WARNING_DROP,
   'scope':'Exploratory monitor evaluation on one exposed capture; not independent confirmation',
   'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def boolean(s):
    v=s.astype(str).str.strip().str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean in '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)
def completed(pattern,status):
    found=[]
    for p in WORK.glob(pattern):
        rp=p/'receipt.json'
        if not rp.is_file():continue
        try:r=json.loads(rp.read_text())
        except (OSError,ValueError):continue
        if r.get('status')==status:found.append((p,r))
    if not found:raise Stop('Missing completed stage: '+status)
    return max(found,key=lambda x:x[0].name)
def helper_source():
    found=[]
    for p in WORK.glob('ZEEK_DEPENDENCY_REPAIR_*'):
        source=p/'resumed_batch2_source.py';rp=p/'receipt.json'
        if not source.is_file() or not rp.is_file():continue
        meta=json.loads(rp.read_text());text=source.read_text()
        if hashlib.sha256(text.encode()).hexdigest()==meta.get('batch2_source_sha256'):
            found.append((p,source,text))
    if not found:raise Stop('Verified saved helper source missing')
    _,source,text=max(found,key=lambda x:x[0].name)
    ns={'__name__':'monitor_batch_helpers','__file__':str(source)}
    exec(compile(text,str(source),'exec'),ns)
    return ns

def outcome_run(delay,source_hash):
    patterns={1:['LINEAGE_BATCH4_PACE_1S_*','LINEAGE_TIMING_PACE_1S_*'],
              3:['LINEAGE_BATCH4_PACE_3S_*'],
              10:['LINEAGE_TRANSFORM_BATCH3_*','LINEAGE_TIMING_PACE_10S_*']}[delay]
    found=[]
    for pattern in patterns:
        for p in WORK.glob(pattern):
            rp=p/'receipt.json';ip=p/'test1_transformation_identity.json';up=p/'test3_unit_detection.csv'
            if not all(x.is_file() for x in [rp,ip,up]):continue
            r=json.loads(rp.read_text());identity=json.loads(ip.read_text())
            if (r.get('status')=='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED'
                and r.get('source_pcap_sha256')==source_hash
                and identity.get('delay_seconds')==delay
                and identity.get('exact_historical_hash_match') is True):found.append((p,r))
    if not found:raise Stop(f'Validated {delay}s original-unit outcomes unavailable')
    signatures={r['historical_transformed_pcap_sha256'] for _,r in found}
    if len(signatures)!=1:raise Stop(f'Conflicting validated {delay}s transformed identities')
    return max(found,key=lambda x:x[0].name)

try:
    H=helper_source();F=H['F']
    b1,_=completed('LINEAGE_SCREEN_BATCH1_REPAIRED_*','BATCH1_COMPLETED_NOT_PACKET_LINEAGE_PROOF')
    base,_=completed('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    source_hash=json.loads((base/'selected_slice.json').read_text())['sha256']
    assets=json.loads((b1/'resolved_inputs.json').read_text())
    for key in ['clean','selected10','models']:
        if assets[key].get('sha256') and H['sha'](assets[key])!=assets[key]['sha256']:
            raise Stop('Input hash mismatch: '+key)
    clean=H['norm'](H['table'](assets['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Historical sample contract failed')
    y=pd.to_numeric(clean.y,errors='raise').to_numpy(int)
    if not set(y).issubset({0,1}) or (y==1).sum()!=512:raise Stop('Unexpected historical labels')
    malicious_keys=set(clean.loc[y==1,'ks'])
    banks=joblib.load(io.BytesIO(H['data'](assets['models'])))['models']
    banks={int(k):v for k,v in banks.items()}
    if set(banks)!=SEEDS:raise Stop('Unexpected model seeds')
    views={'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],
           'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],
           'V_time_proto':['duration','proto']}
    manifest=[];frames={0:clean};outcomes={}
    print('[1/3] Loading validated saved conditions; no replay or training.',flush=True)
    for delay in [1,3,10]:
        directory,receipt=outcome_run(delay,source_hash)
        asset=dict(assets['selected10'])
        if delay!=10:
            changed=False
            for field in ['path','member']:
                if '/delay_10s/' in asset.get(field,''):
                    asset[field]=asset[field].replace('/delay_10s/',f'/delay_{delay}s/');changed=True
            if not changed:raise Stop('Historical delay reference cannot be resolved without guessing')
        checks_asset=dict(asset)
        if checks_asset.get('member'):
            checks_asset['member']=str(Path(checks_asset['member']).with_name('packet_checks.json'))
        else:checks_asset['path']=str(Path(checks_asset['path']).with_name('packet_checks.json'))
        checks=json.loads(H['data'](checks_asset))
        if (checks.get('source_pcap_sha256')!=source_hash or checks.get('transformed_pcap_sha256')!=receipt['historical_transformed_pcap_sha256']):
            raise Stop(f'Historical feature reference and validated {delay}s outcome are not the same trace')
        frame=H['norm'](H['table'](asset))
        if frame.ks.duplicated().any() or set(frame.ks)!=set(clean.ks):raise Stop('Condition key set mismatch')
        frame=frame.set_index('ks').loc[clean.ks].reset_index()
        if not np.array_equal(pd.to_numeric(frame.y).to_numpy(int),y):raise Stop('Condition labels differ')
        unit=pd.read_csv(directory/'test3_unit_detection.csv',dtype={'ks':str})
        required={'seed','ks','membership_validated','clean_detected','selected_record_detected','any_packet_mapped_descendant_alarm'}
        if not required.issubset(unit.columns):raise Stop('Original-unit result schema differs')
        if unit.duplicated(['seed','ks']).any():raise Stop('Duplicate original-unit results')
        if not boolean(unit.membership_validated).all():raise Stop('Unresolved original-unit memberships')
        for seed in SEEDS:
            part=unit[unit.seed.eq(seed)]
            if set(part.ks)!=malicious_keys or len(part)!=512:raise Stop('Original-unit population mismatch')
        frames[delay]=frame;outcomes[delay]=unit
        manifest.append({'delay_seconds':delay,'validated_result_directory':str(directory),
                         'candidate_asset':asset,'candidate_sha256':H['sha'](asset),
                         'historical_transformed_pcap_sha256':receipt['historical_transformed_pcap_sha256']})
    js(OUT/'input_manifest.json',{'source_pcap_sha256':source_hash,'conditions':manifest,
        'clean':assets['clean'],'models':assets['models']})
    # Historical helper matrix() in some versions takes one argument only.
    # Use the explicit historical encoding for arbitrary view columns.
    def encode(frame,columns):
        numeric=[c for c in columns if c!='proto'];parts=[]
        if numeric:parts.append(np.log1p(frame[numeric].to_numpy(float)))
        if 'proto' in columns:parts.append(np.column_stack([frame.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]))
        return np.hstack(parts)
    def evaluate(frame,bank):
        model=bank['PRIMARY']
        if list(model.classes_)!=[0,1]:raise Stop('Unexpected primary class ordering')
        p=model.predict_proba(encode(frame,F))[:,1]
        if not np.isfinite(p).all():raise Stop('Nonfinite probability')
        d=p>=.5
        votes=np.column_stack([bank[name].predict(encode(frame,cols)) for name,cols in views.items()])
        return d,{'AC':np.maximum(p,1-p),'SEMANTIC_AGREE':(d==(votes.sum(axis=1)>=2)).astype(float)}
    aggregate=[];windows=[];prediction_rows=[]
    with threadpool_limits(limits=2):
        for seed in sorted(SEEDS):
            d0,s0=evaluate(clean,banks[seed])
            for delay in DELAYS:
                d,s=evaluate(frames[delay],banks[seed])
                clean_unit=np.full(len(clean),np.nan);target_unit=np.full(len(clean),np.nan)
                if delay==0:
                    clean_unit[y==1]=d0[y==1].astype(float);target_unit[y==1]=d0[y==1].astype(float)
                else:
                    u=outcomes[delay];u=u[u.seed.eq(seed)].set_index('ks').loc[clean.loc[y==1,'ks']]
                    uc=boolean(u.clean_detected);us=boolean(u.selected_record_detected);ua=boolean(u.any_packet_mapped_descendant_alarm)
                    if not np.array_equal(uc,d0[y==1]) or not np.array_equal(us,d[y==1]):raise Stop('Frozen predictions do not reproduce the validated original-unit table')
                    clean_unit[y==1]=uc.astype(float);target_unit[y==1]=ua.astype(float)
                truth0=float((d0==y).mean());truth=float((d==y).mean());record_damage=truth0-truth
                for estimator in ['AC','SEMANTIC_AGREE']:
                    e0=float(s0[estimator].mean());e=float(s[estimator].mean())
                    aggregate.append({'delay_seconds':delay,'seed':seed,'estimator':estimator,
                        'record_count':len(clean),'clean_record_accuracy':truth0,'record_accuracy':truth,
                        'true_record_accuracy_drop':record_damage,'clean_estimate':e0,'estimate':e,
                        'estimated_record_accuracy_drop':e0-e,'current_absolute_error':abs(e-truth),
                        'current_overestimation':e-truth,'differential_error':abs((e0-e)-record_damage),
                        'original_unit_detection_drop':float(np.nanmean(clean_unit)-np.nanmean(target_unit)),
                        'record_drop_warning':e0-e>=WARNING_DROP})
                    for start in range(0,len(clean),WINDOW):
                        sl=slice(start,min(start+WINDOW,len(clean)));mask=y[sl]==1
                        wtruth0=float((d0[sl]==y[sl]).mean());wtruth=float((d[sl]==y[sl]).mean())
                        edrop=float(s0[estimator][sl].mean()-s[estimator][sl].mean())
                        unit_drop=float(np.mean(clean_unit[sl][mask])-np.mean(target_unit[sl][mask])) if mask.any() else np.nan
                        windows.append({'delay_seconds':delay,'seed':seed,'window':start//WINDOW,'estimator':estimator,
                            'original_rows':len(y[sl]),'malicious_original_units':int(mask.sum()),
                            'true_record_accuracy_drop':wtruth0-wtruth,'estimated_record_accuracy_drop':edrop,
                            'original_unit_detection_drop':unit_drop,'monitor_warning':edrop>=WARNING_DROP,
                            'record_damage_ge_5pp':wtruth0-wtruth>=WARNING_DROP,
                            'original_unit_damage_ge_5pp':unit_drop>=WARNING_DROP if np.isfinite(unit_drop) else None})
                prediction_rows.extend({'delay_seconds':delay,'seed':seed,'ks':str(k),'y':int(label),
                                        'primary_predicted_malicious':bool(pred)} for k,label,pred in zip(clean.ks,y,d))
    ag=pd.DataFrame(aggregate);win=pd.DataFrame(windows)
    ag.to_csv(OUT/'monitor_record_accuracy_results.csv',index=False)
    win.to_csv(OUT/'fixed_window_warning_results.csv',index=False)
    pd.DataFrame(prediction_rows).to_csv(OUT/'primary_prediction_checks.csv.gz',index=False,compression='gzip')
    print('\nEXPERIMENT 1 — AC: RECORD-ACCURACY ESTIMATION',flush=True)
    cols=['delay_seconds','seed','true_record_accuracy_drop','estimated_record_accuracy_drop','current_absolute_error','current_overestimation','differential_error']
    print(ag[ag.estimator.eq('AC')][cols].to_string(index=False))
    print('\nEXPERIMENT 2 — SEMANTIC AGREEMENT: RECORD-ACCURACY ESTIMATION',flush=True)
    print(ag[ag.estimator.eq('SEMANTIC_AGREE')][cols].to_string(index=False))
    warnings_out=[]
    for (delay,estimator),g in win.groupby(['delay_seconds','estimator']):
        for target,column in [('RECORD_ACCURACY_DAMAGE','record_damage_ge_5pp'),('ORIGINAL_UNIT_DETECTION_DAMAGE','original_unit_damage_ge_5pp')]:
            z=g[g[column].notna()];truth=z[column].astype(bool).to_numpy();warning=z.monitor_warning.to_numpy(bool)
            tp=int((truth&warning).sum());fn=int((truth&~warning).sum());fp=int((~truth&warning).sum());tn=int((~truth&~warning).sum())
            warnings_out.append({'delay_seconds':delay,'estimator':estimator,'warning_target':target,
                'seed_window_rows_not_independent_captures':len(z),'TP':tp,'FN':fn,'FP':fp,'TN':tn,
                'warning_TPR':tp/(tp+fn) if tp+fn else np.nan,'warning_FPR':fp/(fp+tn) if fp+tn else np.nan})
    wa=pd.DataFrame(warnings_out);wa.to_csv(OUT/'warning_target_comparison.csv',index=False)
    print('\nANALYSIS 3 — WARNINGS AGAINST TWO DISTINCT OUTCOMES',flush=True)
    print(wa.to_string(index=False))
    R.update({'status':'P4_AC_AGREEMENT_BATCH_COMPLETE','conditions_seconds':DELAYS,'seeds':sorted(SEEDS),
              'record_estimator_rows':len(ag),'window_result_rows':len(win),
              'historical_original_unit_predictions_reproduced':True,
              'threshold_calibrated_to_5_percent_FPR':False,'original_unit_recall_estimated':False,
              'remaining_P4_methods':['source-calibrated ATC','CBPE','existing gate','MD3 warning baseline'],
              'note':'Estimator errors target selected-record accuracy only. Original-unit outcomes are used as separate offline warning targets; they are not treated as accuracy estimates.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED'
    R['reason']=str(e);(OUT/'error.txt').write_text(traceback.format_exc())
    print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'monitor_batch_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nSmall result package:',package,flush=True)
