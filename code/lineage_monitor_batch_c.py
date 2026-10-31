# P4 Batch C: existing hard gate, drift-only, and competence-only ablations.
# Method parameters reproduce notebook cell 254. Target windows match current Batches A/B.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import gzip, io, json, hashlib, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('LINEAGE_MONITOR_BATCH_C_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
V={'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],'V_time_proto':['duration','proto']}
CONFIGS=['COMBINED_HARD_GATE','DRIFT_ONLY','COMPETENCE_ONLY']
R={'status':'STARTED','models_retrained':False,'new_PCAP_replays':0,'injection_control_completed':False,
   'source_training_disjointness_established':False,'independent_confirmation':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def latest(pattern,status):
    found=[]
    for p in W.glob(pattern):
        rp=p/'receipt.json'
        if rp.is_file():
            try:r=json.loads(rp.read_text())
            except (OSError,ValueError):continue
            if r.get('status')==status:found.append((p,r))
    if not found:raise Stop('Missing successful stage '+status)
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
        if len(b)>128*1024**2:raise Stop('Expanded CSV too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df):
    df=df.copy()
    if not set(F+['ks','y']).issubset(df.columns):raise Stop('Missing required sample columns')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid feature '+c)
    df['proto']=df.proto.str.lower();label=pd.to_numeric(df.y,errors='raise')
    if not label.isin([0,1]).all() or not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid label/protocol')
    df['y']=label.astype(int)
    return df

def encode(df,cols):
    numeric=[c for c in cols if c!='proto'];parts=[]
    if numeric:parts.append(np.log1p(df[numeric].to_numpy(float)))
    if 'proto' in cols:parts.append(np.column_stack([df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]))
    return np.hstack(parts)

def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid saved Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)

def infer(frame,bank):
    if list(bank['PRIMARY'].classes_)!=[0,1]:raise Stop('Unexpected primary label order')
    p=bank['PRIMARY'].predict_proba(encode(frame,F))[:,1]
    if not np.isfinite(p).all():raise Stop('Nonfinite prediction')
    votes=np.column_stack([bank[name].predict(encode(frame,cols)) for name,cols in V.items()]).astype(int)
    if not np.isin(votes,[0,1]).all():raise Stop('Invalid view predictions')
    return p>=.5,votes

def gate(decisions,votes,profile,configuration):
    mu,sd,competence=profile
    rates=votes.mean(axis=0)
    z=np.abs(rates-mu)/np.maximum(sd,.01)
    drift=np.exp(-.5*z*z)
    if configuration=='COMPETENCE_ONLY':
        weights=competence.copy();abstain=bool(weights.sum()<=0)
    elif configuration=='DRIFT_ONLY':
        weights=drift;abstain=bool(weights.sum()<=0)
    else:
        weights=competence*drift*(z<=3.0);abstain=bool((weights>0).sum()<2)
    estimate=np.nan
    if not abstain:
        pseudo=(votes@weights)/weights.sum()>.5
        estimate=float((decisions==pseudo).mean())
    return estimate,abstain,z,weights

try:
    a,ar=latest('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    b,br=latest('LINEAGE_MONITOR_BATCH_B_*','P4_FROZEN_ATC_DOC_BATCH_COMPLETE')
    manifest=json.loads((a/'input_manifest.json').read_text())
    calibration=json.loads((b/'calibration_inputs.json').read_text())
    model_asset=manifest['models'];model_hash=sha(model_asset)
    if model_hash!=calibration['model_sha256']:raise Stop('Source calibration and target model identities differ')
    current_contract=json.loads(blob(calibration['assets']['contract']))
    if current_contract!=calibration['contract']:raise Stop('Calibration contract changed')
    if current_contract['source_model_bundle_sha256']!=model_hash:raise Stop('Contract model binding failed')
    source=norm(table(calibration['assets']['reference']))
    if len(source)!=12288:raise Stop('Expected 12288 preserved source rows')
    stats=table(calibration['assets']['stats']);stats['seed']=pd.to_numeric(stats.seed).astype(int)
    clean=norm(table(manifest['clean']))
    if len(clean)!=1024 or clean.ks.duplicated().any():raise Stop('Invalid target membership')
    y=clean.y.to_numpy(int);frames={0:clean}
    for c in manifest['conditions']:
        if sha(c['candidate_asset'])!=c['candidate_sha256']:raise Stop('Candidate input changed')
        f=norm(table(c['candidate_asset']))
        if f.ks.duplicated().any() or set(f.ks)!=set(clean.ks):raise Stop('Candidate membership differs')
        f=f.set_index('ks').loc[clean.ks].reset_index()
        if not np.array_equal(f.y.to_numpy(int),y):raise Stop('Candidate labels differ')
        frames[int(c['delay_seconds'])]=f
    if set(frames)!={0,1,3,10}:raise Stop('Expected the four validated conditions')
    bundle=joblib.load(io.BytesIO(blob(model_asset)));banks={int(k):v for k,v in bundle['models'].items()}
    if set(banks)!={8101,8102,8103}:raise Stop('Unexpected seed set')
    WIN=int(ar['window_size']);THRESH=float(ar['warning_drop_threshold'])
    if WIN!=128:raise Stop('Window size differs from historical gate calibration')
    old_pred=pd.read_csv(a/'primary_prediction_checks.csv.gz',dtype={'ks':str})
    target=pd.read_csv(a/'fixed_window_warning_results.csv')
    target=target[target.estimator.eq('AC')].copy()
    if target.duplicated(['delay_seconds','seed','window']).any():raise Stop('Duplicate fixed-window targets')
    policy={'method_source':'Original notebook cell 254','source_reference_windows':512,'source_seed':64301,
            'source_window_draw':'128 rows without replacement per draw; draws may overlap',
            'competence':'max(2*source_view_accuracy-1,0)','drift':'exp(-0.5*z^2)',
            'z':'absolute positive-rate deviation / max(source window SD,0.01)',
            'gate_z':3.0,'combined_weight':'competence*drift*I(z<=3)',
            'combined_abstention':'fewer than two positive weights','pseudo_label':'weighted positive vote > 0.5',
            'target_windowing':'SAME saved-row-order 128-record blocks as current Batches A/B',
            'historical_target_windowing_changed_for_aligned_comparison':True,
            'historical_gate_formula_or_hyperparameters_changed':False,
            'source_training_disjointness_established':False,'post_exposure_analysis':True}
    js(OUT/'evaluation_policy.json',policy)
    js(OUT/'input_manifest.json',{'batch_a':str(a),'batch_b':str(b),'model_sha256':model_hash,
                               'calibration':calibration['assets'],'target_inputs':manifest})
    rng=np.random.default_rng(64301)
    reference_indices=np.array([rng.choice(len(source),WIN,replace=False) for _ in range(512)])
    profiles={};calibration_rows=[];results=[];evidence=[]
    print('[1/3] Reproducing source statistics and the existing gate profile.',flush=True)
    with threadpool_limits(limits=2):
        for seed,bank in sorted(banks.items()):
            ds,vs=infer(source,bank)
            ps=bank['PRIMARY'].predict_proba(encode(source,F))[:,1]
            st=stats[stats.seed.eq(seed)]
            if len(st)!=1:raise Stop('Source statistics seed is not unique')
            st=st.iloc[0]
            if not np.isclose((ds==source.y.to_numpy()).mean(),float(st.primary_reference_accuracy),atol=1e-8,rtol=0):raise Stop('Source accuracy mismatch')
            if not np.isclose(np.maximum(ps,1-ps).mean(),float(st.primary_reference_confidence),atol=1e-8,rtol=0):raise Stop('Source confidence mismatch')
            rates=vs[reference_indices].mean(axis=1)
            acc=(vs==source.y.to_numpy()[:,None]).mean(axis=0)
            profile=(rates.mean(axis=0),rates.std(axis=0,ddof=0),np.maximum(2*acc-1,0))
            profiles[seed]=profile
            for j,name in enumerate(V):
                calibration_rows.append({'seed':seed,'view':name,'source_accuracy':float(acc[j]),
                    'competence_weight':float(profile[2][j]),'source_window_rate_mean':float(profile[0][j]),
                    'source_window_rate_SD':float(profile[1][j])})
            d0,v0=infer(clean,bank)
            for delay,frame in sorted(frames.items()):
                d,v=infer(frame,bank)
                old=old_pred[old_pred.seed.eq(seed)&old_pred.delay_seconds.eq(delay)]
                if old.ks.duplicated().any() or set(old.ks)!=set(clean.ks):raise Stop('Saved primary prediction membership differs')
                if not np.array_equal(boolean(old.set_index('ks').loc[clean.ks,'primary_predicted_malicious']),d):raise Stop('Primary predictions differ from Batch A')
                for start in range(0,len(clean),WIN):
                    sl=slice(start,start+WIN);wi=start//WIN
                    truth=target[target.seed.eq(seed)&target.delay_seconds.eq(delay)&target.window.eq(wi)]
                    if len(truth)!=1:raise Stop('Original-unit window target not unique')
                    unit_drop=float(truth.iloc[0].original_unit_detection_drop)
                    a0=float((d0[sl]==y[sl]).mean());a1=float((d[sl]==y[sl]).mean())
                    for configuration in CONFIGS:
                        e0,s0,z0,w0=gate(d0[sl],v0[sl],profile,configuration)
                        e1,s1,z1,w1=gate(d[sl],v[sl],profile,configuration)
                        retained=not s0 and not s1
                        results.append({'delay_seconds':delay,'seed':seed,'window':wi,'configuration':configuration,
                            'clean_accuracy':a0,'record_accuracy':a1,'true_record_accuracy_drop':a0-a1,
                            'original_unit_detection_drop':unit_drop,'clean_estimate':e0,'estimate':e1,
                            'clean_abstained':s0,'attack_abstained':s1,'paired_retained':retained,
                            'clean_reject_attack_accept':bool(s0 and not s1),
                            'estimated_record_accuracy_drop':e0-e1 if retained else np.nan,
                            'differential_error':abs((e0-e1)-(a0-a1)) if retained else np.nan,
                            'accepted_current_absolute_error':abs(e1-a1) if not s1 else np.nan,
                            'accepted_current_overestimation':e1-a1 if not s1 else np.nan,
                            'unit_damage_ge_5pp':unit_drop>=THRESH if np.isfinite(unit_drop) else None,
                            'monitor_warning':bool(e0-e1>=THRESH) if retained else None})
                        evidence.append({'delay_seconds':delay,'seed':seed,'window':wi,'configuration':configuration,
                            'clean_z':z0.tolist(),'attack_z':z1.tolist(),'clean_weights':w0.tolist(),'attack_weights':w1.tolist()})
            print('Completed frozen seed:',seed,flush=True)
    pd.DataFrame(calibration_rows).to_csv(OUT/'source_gate_profile.csv',index=False)
    df=pd.DataFrame(results);df.to_csv(OUT/'gate_paired_windows.csv',index=False)
    with open(OUT/'gate_evidence.jsonl','w') as f:
        for row in evidence:f.write(json.dumps(row)+'\n')
    summary=[]
    for (delay,configuration),g in df.groupby(['delay_seconds','configuration']):
        damage=g.original_unit_detection_drop.notna()&g.original_unit_detection_drop.ge(THRESH)
        summary.append({'delay_seconds':delay,'configuration':configuration,'seed_window_rows':len(g),
            'clean_reporting_coverage':float((~g.clean_abstained).mean()),
            'attack_reporting_coverage':float((~g.attack_abstained).mean()),
            'paired_reporting_coverage':float(g.paired_retained.mean()),
            'clean_reject_attack_accept_rows':int(g.clean_reject_attack_accept.sum()),
            'accepted_current_absolute_error':g.accepted_current_absolute_error.mean(),
            'accepted_current_overestimation':g.accepted_current_overestimation.mean(),
            'conditional_differential_error':g.differential_error.mean(),
            'unit_damage_rows':int(damage.sum()),'unit_damage_rows_attack_accepted':int((damage&~g.attack_abstained).sum())})
    sm=pd.DataFrame(summary);sm.to_csv(OUT/'gate_coverage_and_error_summary.csv',index=False)
    print('\nEXPERIMENT 1 — EXISTING COMBINED HARD GATE\n'+sm[sm.configuration.eq('COMBINED_HARD_GATE')].to_string(index=False),flush=True)
    print('\nEXPERIMENT 2 — DRIFT-ONLY ABLATION\n'+sm[sm.configuration.eq('DRIFT_ONLY')].to_string(index=False),flush=True)
    print('\nEXPERIMENT 3 — COMPETENCE-ONLY ABLATION\n'+sm[sm.configuration.eq('COMPETENCE_ONLY')].to_string(index=False),flush=True)
    # Compare errors only on windows retained by all three configurations.
    retained=df.pivot(index=['delay_seconds','seed','window'],columns='configuration',values='paired_retained')
    common=retained.all(axis=1);common_keys=set(common[common].index)
    df['common_retained']=list(zip(df.delay_seconds,df.seed,df.window))
    df['common_retained']=df.common_retained.isin(common_keys)
    fair=[]
    for (delay,configuration),g in df.groupby(['delay_seconds','configuration']):
        x=g[g.common_retained]
        fair.append({'delay_seconds':delay,'configuration':configuration,'identical_retained_windows':len(x),
                     'mean_differential_error_on_common_windows':x.differential_error.mean()})
    fs=pd.DataFrame(fair);fs.to_csv(OUT/'matched_retention_ablation_comparison.csv',index=False)
    print('\nIDENTICAL-RETENTION COMPARISON\n'+fs.to_string(index=False),flush=True)
    # Keep abstention separate from a negative warning.
    ws=[]
    for (delay,configuration),g in df.groupby(['delay_seconds','configuration']):
        for name,truth in [('RECORD_ACCURACY_DAMAGE',g.true_record_accuracy_drop.ge(THRESH)),
                           ('ORIGINAL_UNIT_DETECTION_DAMAGE',g.original_unit_detection_drop.ge(THRESH))]:
            eligible=np.ones(len(g),dtype=bool) if name=='RECORD_ACCURACY_DAMAGE' else g.original_unit_detection_drop.notna().to_numpy()
            evaluable=g.paired_retained.to_numpy(bool)&eligible
            tt=truth.to_numpy(bool);warning=g.estimated_record_accuracy_drop.ge(THRESH).to_numpy(bool)
            ws.append({'delay_seconds':delay,'configuration':configuration,'warning_target':name,
                'eligible_rows':int(eligible.sum()),'paired_evaluable_rows':int(evaluable.sum()),
                'abstained_or_unpaired_rows':int((eligible&~evaluable).sum()),
                'TP':int((evaluable&tt&warning).sum()),'FN':int((evaluable&tt&~warning).sum()),
                'FP':int((evaluable&~tt&warning).sum()),'TN':int((evaluable&~tt&~warning).sum())})
    pd.DataFrame(ws).to_csv(OUT/'gate_three_state_warning_results.csv',index=False)
    R.update({'status':'P4_GATE_AND_TWO_ABLATIONS_COMPLETE','paired_window_rows':len(df),
              'source_profile_reproduced_from_existing_reference':True,'gate_hyperparameters_changed':False,
              'target_windows_aligned_to_current_batches_AB':True,'historical_hashed_window_order_not_reproduced':True,
              'abstention_counted_as_warning_negative':False,'remaining_P4_methods':['CBPE','MD3 warning baseline'],
              'interpretation':'Single exposed-capture analysis. Report coverage with conditional errors. NaN means no evaluable rows, not zero error. Seed/window rows are not independent captures.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'gate_batch_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nSmall result package:',package,flush=True)
