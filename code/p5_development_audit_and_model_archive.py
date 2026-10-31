# P5 development checkpoint: evidence audit, reproducibility/resources, verified archive.
# Does not mark the eight-capture research plan or manuscript complete.
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import ast, gzip, hashlib, importlib.metadata, io, json, os, platform, shutil, subprocess, sys, time, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('P5_VERIFIED_DEVELOPMENT_SNAPSHOT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
V={'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],'V_time_proto':['duration','proto']}
R={'status':'STARTED','new_PCAP_replays':0,'models_trained':False,'independent_confirmation':False,
   'original_eight_capture_plan_complete':False,'manuscript_submission_ready':False,'private_only':True,
   'public_release_approved':False,'output_directory':str(OUT)}
STAGES=[
 ('capture49_clean','LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED'),
 ('capture49_10s','LINEAGE_TRANSFORM_BATCH3_*','TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED'),
 ('pacing_controls','LINEAGE_BATCH4_CONTROLS_*','BATCH4_CONTROLS_AND_COMPARISON_COMPLETE'),
 ('timing','LINEAGE_TIMING_BATCH_*','TWO_TIMING_EXPERIMENTS_COMPLETE'),
 ('AC_agreement','LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE'),
 ('ATC_DoC','LINEAGE_MONITOR_BATCH_B_*','P4_FROZEN_ATC_DOC_BATCH_COMPLETE'),
 ('gate','LINEAGE_MONITOR_BATCH_C_*','P4_GATE_AND_TWO_ABLATIONS_COMPLETE'),
 ('MD3','LINEAGE_MONITOR_BATCH_D_MD3_*','P4_MD3_WARNING_AND_ORDER_CONTROL_COMPLETE'),
 ('CBPE','LINEAGE_MONITOR_BATCH_E_CBPE_*','P4_CBPE_SOURCE_CALIBRATION_AND_EXACT_METRICS_COMPLETE'),
 ('window_order','LINEAGE_WINDOW_ORDER_RECONCILIATION_*','WINDOW_ORDER_RECONCILIATION_COMPLETE'),
 ('matched_models','LINEAGE_MATCHED_MODEL_FAMILIES_*','MATCHED_MODEL_FAMILIES_AND_PROTOCOL_CONTROL_COMPLETE'),
 ('fresh48','FRESH_RAW_CAPTURE48_*','FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE'),
 ('merge48','CAPTURE48_MERGE_WITNESS_AUDIT_*','CAPTURE48_MERGE_AND_ALARM_WITNESS_AUDIT_COMPLETE'),
 ('injection','CAPTURE1_UID_INJECTION_CONTINUATION_*','CAPTURE1_OBSERVED_UID_NULL_K1_K3_CONTROL_COMPLETE'),
 ('timeout','CAPTURE49_SYN_TIMEOUT_SENSITIVITY_*','CAPTURE49_ALTERNATIVE_SYN_TIMEOUT_SENSITIVITY_COMPLETE')]
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def file_hash(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
@contextmanager
def opened(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
    else:
        with open(a['path'],'rb') as f:yield f

def embed(a,name,expected=None):
    target=OUT/'referenced_inputs'/name;target.parent.mkdir(exist_ok=True)
    h=hashlib.sha256();total=0
    with opened(a) as src,open(target,'wb') as dst:
        for b in iter(lambda:src.read(4*1024**2),b''):
            total+=len(b)
            if total>128*1024**2:raise Stop('Referenced input exceeds archive safety limit')
            dst.write(b);h.update(b)
    digest=h.hexdigest()
    if expected and digest!=expected:raise Stop('Referenced-input hash mismatch: '+name)
    return target,{'archive_path':str(target.relative_to(OUT)),'original_asset':a,'sha256':digest,'bytes':total}

def frame(path):
    with open(path,'rb') as f:compressed=f.read(2)==b'\x1f\x8b'
    return pd.read_csv(path,compression='gzip' if compressed else None,dtype=str,keep_default_na=False)

def normalize(df):
    x=df[F].copy()
    for c in F[:-1]:
        x[c]=pd.to_numeric(x[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(x[c]).all() or x[c].lt(0).any():raise Stop('Invalid predictor')
    x['proto']=x.proto.str.lower()
    if not x.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    return x

def encode(df,cols):
    nums=[c for c in cols if c!='proto'];p=[]
    if nums:p.append(np.log1p(df[nums].to_numpy(float)))
    if 'proto' in cols:p.append(np.column_stack([df.proto.eq(s).to_numpy(float) for s in ['tcp','udp','icmp']]))
    return np.hstack(p)

def bools(s):
    x=s.astype(str).str.lower()
    if not x.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean')
    return x.isin(['true','1']).to_numpy(bool)

def create_archive(roots):
    package=OUT/'PRIVATE_model_backed_development_snapshot.zip';entries=[];omitted=[];seen=set();total=0
    allowed={'.csv','.gz','.json','.jsonl','.py','.txt','.md','.yaml','.yml','.toml','.joblib','.npz'}
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for root in roots:
            if not root.is_dir():continue
            for current,dirs,files in os.walk(root,followlinks=False):
                dirs[:]=[d for d in dirs if d not in {'scratch','temporary_replay','clean_replay','__pycache__','.git'}]
                for name in files:
                    p=Path(current)/name
                    if p.is_symlink() or p.suffix.lower() not in allowed:continue
                    rel=p.relative_to(root);arc=str(Path(root.name)/rel)
                    if arc in seen:continue
                    size=p.stat().st_size
                    if size>64*1024**2 or total+size>512*1024**2:
                        omitted.append({'path':str(p),'bytes':size,'reason':'declared size limit'});continue
                    seen.add(arc);digest=file_hash(p);z.write(p,arcname=arc)
                    entries.append({'member':arc,'bytes':size,'sha256':digest});total+=size
        z.writestr('ARCHIVE_FILE_MANIFEST.json',json.dumps(entries,indent=2))
        z.writestr('OMITTED_FILES.json',json.dumps(omitted,indent=2))
    failures=[]
    with zipfile.ZipFile(package) as z:
        for row in entries:
            h=hashlib.sha256()
            with z.open(row['member']) as f:
                for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
            if h.hexdigest()!=row['sha256']:failures.append(row['member'])
    return {'archive':str(package),'archive_bytes':package.stat().st_size,'archive_sha256':file_hash(package),
            'members_verified':len(entries),'uncompressed_bytes':total,'hash_mismatches':failures,
            'omitted_by_size_limit':omitted,'raw_PCАPs_included':False,'models_included':any(x['member'].endswith('.joblib') for x in entries),
            'private_only':True,'complete_end_to_end_reproduction_claimed':False}

roots=[OUT];selected={};checks=[]
try:
    if shutil.disk_usage(W).free<1024**3:raise Stop('At least 1 GiB free is required for a private verified snapshot')
    stage_rows=[]
    print('[1/3] Auditing completed stages and writing the honest P0–P5 gap ledger.',flush=True)
    for name,pattern,status in STAGES:
        found=[]
        for p in W.glob(pattern):
            rp=p/'receipt.json'
            if rp.is_file():
                try:r=json.loads(rp.read_text())
                except (OSError,ValueError):continue
                if r.get('status')==status:found.append((p,r))
        if found:
            p,r=max(found,key=lambda x:x[0].name);selected[name]=(p,r);roots.append(p)
            stage_rows.append({'stage':name,'status':'RECEIPT_PRESENT','directory':str(p),'receipt_sha256':file_hash(p/'receipt.json')})
        else:stage_rows.append({'stage':name,'status':'NOT_FOUND','directory':'','receipt_sha256':''})
    pd.DataFrame(stage_rows).to_csv(OUT/'completed_stage_ledger.csv',index=False)
    required=['capture49_clean','capture49_10s','AC_agreement','ATC_DoC','gate','MD3','CBPE','window_order','matched_models','fresh48','merge48','injection','timeout']
    missing=[k for k in required if k not in selected]
    if missing:raise Stop('Required current stages missing: '+', '.join(missing))
    # Include predecessor source-fit artifacts, even where its old ownership attempt blocked.
    predecessor=Path(selected['injection'][1]['source_run'])
    if predecessor.is_dir():roots.append(predecessor)
    def audit(name,condition,detail):checks.append({'check':name,'passed':bool(condition),'detail':detail})
    inj=selected['injection'][0];it=pd.read_csv(inj/'injection_model_results.csv')
    audit('injection_result_shape',len(it)==27 and set(it.clones_per_eligible_unit)=={0,1,3},f'rows={len(it)}')
    for k in [0,1,3]:
        t=pd.read_csv(inj/f'packet_membership_k{k}.csv')
        audit(f'injection_packet_membership_k{k}',len(t)==512 and bools(t.packet_membership_complete).all(),f'rows={len(t)}')
    c49=pd.read_csv(selected['capture49_10s'][0]/'test3_detection_summary.csv')
    audit('capture49_detection_accounting',((c49.validated_units+c49.unresolved_units)==c49.original_units).all(),'Each original unit accounted for')
    w48=pd.read_csv(selected['merge48'][0]/'test3_alarm_witness_results.csv')
    audit('capture48_witness_accounting',(w48.detected_with_pure_record_witness+w48.no_associated_record_alarm+w48.strict_attribution_unresolved==w48.original_units).all(),'Detected + no alarm + unresolved = cohort size')
    cfg=pd.read_csv(selected['timeout'][0]/'configuration_model_comparison.csv')
    fields=['unit_detection_lower','unit_detection_upper','any_overlap_alarm_units','descendant_UIDs','common_record_accuracy','common_record_benign_FPR']
    left=cfg[cfg.configuration.eq('DEFAULT_5S')].set_index(['family','seed','delay_seconds'])
    right=cfg[cfg.configuration.eq('ALTERNATIVE_15S')].set_index(['family','seed','delay_seconds']).reindex(left.index)
    same=np.isclose(left[fields].to_numpy(float),right[fields].to_numpy(float),equal_nan=True,atol=1e-12,rtol=0).all(axis=1)
    audit('timeout_comparison_coverage',len(left)==24 and len(right)==24,'12 models × clean/10s')
    pd.DataFrame(checks).to_csv(OUT/'evidence_checks.csv',index=False)
    claims=[
        {'claim':'Capture49 accounting discrepancy','status':'DESCRIPTIVE_SUPPORTED','basis':str(selected['capture49_10s'][0]),'limits':'One exposed capture; original-unit alarm policy, not application functionality'},
        {'claim':'Capture48 pure-witness contrast','status':'DESCRIPTIVE_SUPPORTED','basis':str(selected['merge48'][0]),'limits':'Fresh sample/models differ from historical capture49; one unit remains unresolved in reported results'},
        {'claim':'Fresh injection damage','status':'REPORT_ACTUAL_NULL_RESULT','basis':str(inj),'limits':'New group-disjoint within-capture control; does not reproduce historical damage setup'},
        {'claim':'Changing SYN timeout changes these measured outcomes','status':'NO_OBSERVED_CHANGE' if same.all() else 'SOME_MEASURED_OUTCOMES_CHANGED','basis':str(selected['timeout'][0]),'limits':'One documented parameter change, not general extractor invariance'},
        {'claim':'Universal accuracy guarantee or robust defense','status':'UNSUPPORTED','basis':'','limits':'Not a contribution of this study'},
        {'claim':'Eight-target packet-aware evaluation complete','status':'NOT_COMPLETE','basis':'','limits':'7,9,33,36,39,43 remain without this evaluation'},
        {'claim':'Packet edits preserve malware/application functionality','status':'NOT_TESTED','basis':'','limits':'Do not claim host-realizable end-to-end evasion'},
        {'claim':'Independent confirmatory significance','status':'NOT_ESTABLISHED','basis':'','limits':'Seeds/windows/slices are not additional independent captures'},
        {'claim':'Legacy conflicting AUROC table resolved','status':'NOT_ESTABLISHED','basis':'','limits':'Exclude that table from manuscript claims until reconciled'}]
    pd.DataFrame(claims).to_csv(OUT/'claim_evidence_matrix.csv',index=False)
    gaps=[
        {'package':'P0','status':'PARTIAL','remaining':'Legacy AUROC and final bibliography/method-fidelity review; versioned amendments'},
        {'package':'P1','status':'CURRENT_CAPTURE_COMPUTATIONS_COMPLETE','remaining':'Final wording/policy audit, not another attack sweep'},
        {'package':'P2','status':'FRESH_CONTROL_COMPUTATIONS_COMPLETE_WITH_AMENDMENT','remaining':'Disclose fresh injection sample/models and non-replication of historical setup'},
        {'package':'P3','status':'PARTIAL','remaining':'Packet-aware eligible-target evaluation on captures 7,9,33,36,39,43; common-model comparison where required'},
        {'package':'P4','status':'CAPTURE49_PANEL_IMPLEMENTED','remaining':'Broader-capture monitor evaluation and final fidelity review; no generalization claim yet'},
        {'package':'P5','status':'PRIVATE_DEVELOPMENT_FREEZE_ONLY','remaining':'End-to-end clean-environment reproduction, full lineage resource profiling, final manuscript/novelty audit'}]
    pd.DataFrame(gaps).to_csv(OUT/'P0_P5_status.csv',index=False)
    R['uncompleted_planned_target_captures']=[7,9,33,36,39,43]
    R['evidence_checks_passed']=all(x['passed'] for x in checks)
    print('\nP0–P5 STATUS\n'+pd.DataFrame(gaps).to_string(index=False),flush=True)
    print('\nEVIDENCE CHECKS\n'+pd.DataFrame(checks).to_string(index=False),flush=True)
    print('[2/3] Model-backed fresh-process reproduction and point-monitor software benchmark.',flush=True)
    a=selected['AC_agreement'][0];b=selected['ATC_DoC'][0];c=selected['gate'][0];e=selected['CBPE'][0]
    manifest=json.loads((a/'input_manifest.json').read_text());calibration=json.loads((b/'calibration_inputs.json').read_text())
    refs={};model_path,refs['models']=embed(manifest['models'],'frozen_source_models.joblib',calibration['model_sha256'])
    clean_path,refs['clean']=embed(manifest['clean'],'clean_sample.csv',manifest['clean'].get('sha256'))
    for key in ['contract','stats','reference']:
        original=calibration['assets'][key];suffix=Path(original.get('member') or original['path']).name
        _,refs[key]=embed(original,'calibration_'+suffix)
    js(OUT/'relocated_reference_inputs.json',refs)
    raw=frame(clean_path);clean=normalize(raw);banks={int(k):v for k,v in joblib.load(model_path)['models'].items()}
    stats=pd.read_csv(OUT/refs['stats']['archive_path']);profiles=pd.read_csv(c/'source_gate_profile.csv')
    calibrators={int(k):v for k,v in joblib.load(e/'source_only_probability_calibrators.joblib').items()}
    env={'python':sys.version,'platform':platform.platform(),'CPU_count':os.cpu_count(),
         'CPU_affinity_count':len(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else None,
         'packages':{},'benchmark_threads':2,'hardware_claim':'current Kaggle environment, not physical IoT-edge hardware'}
    for name in ['numpy','pandas','scipy','scikit-learn','joblib','menelaus']:
        try:env['packages'][name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:env['packages'][name]='not installed'
    quota=Path('/sys/fs/cgroup/cpu.max')
    if quota.is_file():env['CPU_quota_raw']=quota.read_text().strip()
    js(OUT/'environment.json',env)
    expected={}
    with threadpool_limits(limits=2):
        for seed,bank in sorted(banks.items()):
            expected[f'{seed}_PRIMARY']=bank['PRIMARY'].predict_proba(encode(clean,F))[:,1]
            for name,cols in V.items():expected[f'{seed}_{name}']=bank[name].predict_proba(encode(clean,cols))[:,1]
    child=r"""from pathlib import Path
import sys,json
import numpy as np,pandas as pd,joblib
from threadpoolctl import threadpool_limits
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
V={'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],'V_time_proto':['duration','proto']}
p=Path(sys.argv[2])
with open(p,'rb') as f:gzip=f.read(2)==b'\x1f\x8b'
df=pd.read_csv(p,compression='gzip' if gzip else None,dtype=str,keep_default_na=False)
for c in F[:-1]:df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
df['proto']=df.proto.str.lower()
def enc(cols):
    nums=[c for c in cols if c!='proto'];parts=[]
    if nums:parts.append(np.log1p(df[nums].to_numpy(float)))
    if 'proto' in cols:parts.append(np.column_stack([df.proto.eq(s).to_numpy(float) for s in ['tcp','udp','icmp']]))
    return np.hstack(parts)
banks=joblib.load(sys.argv[1])['models'];out={}
with threadpool_limits(limits=2):
    for seed,bank in banks.items():
        out[f'{int(seed)}_PRIMARY']=bank['PRIMARY'].predict_proba(enc(F))[:,1]
        for name,cols in V.items():out[f'{int(seed)}_{name}']=bank[name].predict_proba(enc(cols))[:,1]
np.savez_compressed(sys.argv[3],**out)
"""
    child_path=OUT/'clean_process_prediction_check.py';child_path.write_text(child)
    child_npz=OUT/'clean_process_predictions.npz'
    ce={**os.environ,'OMP_NUM_THREADS':'2','OPENBLAS_NUM_THREADS':'2','MKL_NUM_THREADS':'2'}
    result=subprocess.run([sys.executable,str(child_path),str(model_path),str(clean_path),str(child_npz)],capture_output=True,text=True,timeout=180,env=ce)
    (OUT/'clean_process_stderr.txt').write_text(result.stderr)
    if result.returncode:raise Stop('Fresh-process model check failed; stderr retained')
    checks_repro=[]
    with np.load(child_npz,allow_pickle=False) as got:
        if set(got.files)!=set(expected):raise Stop('Fresh-process output names differ')
        for name,p in expected.items():checks_repro.append({'output':name,'rows':len(p),'max_absolute_probability_difference':float(np.max(abs(p-got[name]))),'passed':bool(np.allclose(p,got[name],atol=1e-12,rtol=0))})
    pd.DataFrame(checks_repro).to_csv(OUT/'fresh_process_prediction_reproduction.csv',index=False)
    R['fresh_process_core_predictions_reproduced']=all(x['passed'] for x in checks_repro)
    # Benchmark tabular point-estimate pipelines only; exact CBPE distributions are excluded.
    CONFIGS=['PRIMARY_ONLY','AC','ATC_FROZEN','DoC_FROZEN','CBPE_ACC_POINT_ONLY','SEMANTIC_AGREE','COMBINED_HARD_GATE']
    def pipeline(raw_features,seed,method):
        df=normalize(raw_features);bank=banks[seed];p=bank['PRIMARY'].predict_proba(encode(df,F))[:,1];d=p>=.5
        conf=np.maximum(p,1-p);ref=stats[stats.seed.eq(seed)].iloc[0];views=None
        if method in ['SEMANTIC_AGREE','COMBINED_HARD_GATE']:views=np.column_stack([bank[n].predict(encode(df,cols)) for n,cols in V.items()])
        q=None
        if method=='CBPE_ACC_POINT_ONLY':
            clipped=np.clip(p,1e-6,1-1e-6);q=calibrators[seed].predict_proba((np.log(clipped)-np.log1p(-clipped)).reshape(-1,1))[:,1]
        estimates=[];abstentions=0
        for start in range(0,len(df),128):
            sl=slice(start,start+128)
            if method=='PRIMARY_ONLY':value=float(d[sl].mean())
            elif method=='AC':value=float(conf[sl].mean())
            elif method=='ATC_FROZEN':value=float((conf[sl]>=float(ref.ATC_confidence_threshold)).mean())
            elif method=='DoC_FROZEN':value=float(np.clip(float(ref.primary_reference_accuracy)+conf[sl].mean()-float(ref.primary_reference_confidence),0,1))
            elif method=='CBPE_ACC_POINT_ONLY':value=float(np.where(d[sl],q[sl],1-q[sl]).mean())
            elif method=='SEMANTIC_AGREE':value=float((d[sl]==(views[sl].sum(axis=1)>=2)).mean())
            else:
                pp=profiles[profiles.seed.eq(seed)].set_index('view').loc[list(V)]
                z=np.abs(views[sl].mean(axis=0)-pp.source_window_rate_mean.to_numpy())/np.maximum(pp.source_window_rate_SD.to_numpy(),.01)
                weights=pp.competence_weight.to_numpy()*np.exp(-.5*z*z)*(z<=3)
                if (weights>0).sum()<2:value=None;abstentions+=1
                else:value=float((d[sl]==((views[sl]@weights)/weights.sum()>.5)).mean())
            estimates.append(value)
        return json.dumps({'configuration':method,'point_outputs':estimates,'abstained_windows':abstentions},allow_nan=False)
    raw_features=raw[F].copy();bench=[];rng=np.random.default_rng(64601)
    with threadpool_limits(limits=2):
        for seed in sorted(banks):
            for method in CONFIGS:
                for _ in range(2):pipeline(raw_features,seed,method)
            for repetition in range(7):
                for method in rng.permutation(CONFIGS):
                    t=time.perf_counter_ns();encoded=pipeline(raw_features,seed,str(method));elapsed=(time.perf_counter_ns()-t)/1e6
                    bench.append({'seed':seed,'configuration':str(method),'repetition':repetition,'rows':len(raw_features),
                                  'ms_per_1000_records':elapsed*1000/len(raw_features),'serialized_evidence_bytes':len(encoded.encode())})
    bt=pd.DataFrame(bench);bt.to_csv(OUT/'point_pipeline_timing_repetitions.csv',index=False)
    bs=bt.groupby('configuration',as_index=False).agg(median_ms_per_1000=('ms_per_1000_records','median'),
        p95_observed_ms_per_1000=('ms_per_1000_records',lambda x:float(x.quantile(.95))),timed_runs=('ms_per_1000_records','size'))
    bs.to_csv(OUT/'point_pipeline_timing_summary.csv',index=False)
    js(OUT/'resource_measurement_scope.json',{'includes':['numeric conversion','encoding','applicable frozen-model inference','point monitoring/gate logic','JSON point-output serialization'],
        'excludes':['disk/model loading','packet capture','Zeek extraction','lineage construction','source fitting','CBPE exact metric distributions/intervals'],
        'thread_limit':2,'warmups_per_seed_method':2,'timed_repetitions_per_seed_method':7,
        'timing_is_software_measurement_not_edge_hardware_or_energy':True,
        'gate_time_includes_profile_table_lookup':True})
    print('\nFRESH-PROCESS REPRODUCTION\n'+pd.DataFrame(checks_repro).to_string(index=False),flush=True)
    print('\nPOINT-PIPELINE SOFTWARE TIMING\n'+bs.to_string(index=False),flush=True)
    if not R['evidence_checks_passed'] or not R['fresh_process_core_predictions_reproduced']:raise Stop('An audit/reproduction check failed; the package must not be called verified')
    R['status']='P5_DEVELOPMENT_AUDIT_AND_COMPONENT_REPRODUCTION_COMPLETE_WITH_OPEN_GAPS'
except Exception as error:
    R['status']='P5_PARTIAL_WITH_SAVED_ERROR';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    # Preserve executed cell sources where available; syntax success is not end-to-end validation.
    try:
        history=list(get_ipython().history_manager.input_hist_raw);src_dir=OUT/'kernel_source_snapshot';src_dir.mkdir(exist_ok=True);hm=[]
        for i,text in enumerate(history):
            if not isinstance(text,str) or not text.strip() or len(text.encode())>4*1024**2:continue
            try:compile(text,f'cell_{i}','exec');syntax='COMPILES'
            except SyntaxError:syntax='NOT_RAW_PYTHON_OR_SYNTAX_ERROR'
            name=f'cell_{i:04d}.txt';(src_dir/name).write_text(text,encoding='utf-8')
            hm.append({'cell':i,'file':name,'syntax':syntax,'execution_success_inferred':False})
        pd.DataFrame(hm).to_csv(OUT/'kernel_source_snapshot_manifest.csv',index=False)
        R['kernel_source_snapshot_cells']=len(hm)
    except Exception as error:R['source_snapshot_note']=str(error)
    readme="""PRIVATE DEVELOPMENT SNAPSHOT — NOT A SUBMISSION-READY RELEASE

This archive preserves completed current evidence, models, input references, and audit results.
Read P0_P5_status.csv and claim_evidence_matrix.csv before using any claim.
Six planned packet-aware target captures remain unevaluated in this framework.
The capture-48 fresh cohort/models and capture-1 fresh injection control are amendments.
The legacy conflicting AUROC table is not reconciled and must not support paper claims.
Fresh-process checking covers the historical detector/view predictions, not every replay.
Raw PCAPs and large public datasets are not embedded; original mounts remain needed for replay.
Point-pipeline timings do not include extraction, lineage, or CBPE distribution calculations.
Kernel history may contain failed/diagnostic cells and private information. Do not publish it blindly.
No significance, independent confirmation, malware-functionality, physical-edge, or energy claim is made.
"""
    (OUT/'READ_ME_FIRST.txt').write_text(readme,encoding='utf-8')
    js(OUT/'receipt.json',R)
    # Include adjacent source/repair roots needed for provenance, without reading backups.
    for pattern in ['ZEEK_DEPENDENCY_REPAIR_*','ZEEK_HEX_SEPARATOR_FIX_*','BATCH5_SCOPE_REPAIR_*']:
        roots.extend(p for p in W.glob(pattern) if p.is_dir())
    roots=list(dict.fromkeys(roots))
    try:
        R['archive']=create_archive(roots)
        R['archive_verified']=not R['archive']['hash_mismatches']
        if not R['archive_verified']:R['status']='P5_ARCHIVE_HASH_VERIFICATION_FAILED'
    except Exception as error:R['archive_error']=str(error);R['archive_verified']=False
    js(OUT/'receipt.json',R)
    print('\nP5 RECEIPT\n'+json.dumps(R,indent=2),flush=True)
