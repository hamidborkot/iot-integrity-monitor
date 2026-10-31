# Five-seed fixed-target application: grouped arm, row-control arm, monitors.
# No fitting, resampling, threshold tuning, or PCAP replay.
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from collections import Counter
import gzip, hashlib, io, json, os, shutil, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');PRIMARY=Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')
OWNER=Path('/kaggle/input/datasets/mdhamidborkottulla')
ROOTS=[PRIMARY,W]+[OWNER/n for n in ['zeek-new','the-last-days-backup','full-backup','all-kaggle-work','complete-backup','one-last','last-day-backup','the-last-update','whole-in-one','ran-files']]
OUT=W/('FIVE_SEED_FIXED_TARGET_APPLICATION_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(parents=True,exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SEEDS=[8101,8102,8103,8104,8105];POLICIES=['GROUP_DISJOINT','ROW_FIT_CAL_CONTROL'];THRESHOLD=.05
R={'status':'STARTED','new_model_fits':0,'new_calibrator_fits':0,'new_PCAP_replays':0,'target_resampling':False,
   'legacy_and_new_banks_pooled':False,'independent_confirmation':False,'six_remaining_packet_captures_completed':False,
   'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()
def read_bytes(path,member=''):
    if member:
        with zipfile.ZipFile(path) as z,z.open(member) as f:b=f.read(128*1024**2+1)
    else:
        with open(path,'rb') as f:b=f.read(128*1024**2+1)
    if len(b)>128*1024**2:raise Stop('Bounded metadata read exceeded')
    return b

def csv(path):
    b=read_bytes(path)
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded CSV too large')
    return pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)

def norm(df,labelled=True):
    df=df.copy()
    if not set(F+(['ks','y'] if labelled else [])).issubset(df.columns):raise Stop('Required table fields missing')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid feature '+c)
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    if labelled:
        y=pd.to_numeric(df.y,errors='raise')
        if not y.isin([0,1]).all():raise Stop('Invalid binary labels')
        df['y']=y.astype(int)
    return df

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def logit(p):
    p=np.clip(p,1e-6,1-1e-6);return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)
def semantic_sample(df):
    d=norm(df);h=hashlib.sha256()
    for row in d.sort_values('ks',kind='stable')[['ks','y']+F].itertuples(index=False,name=None):
        k,y,*v=row;canonical=[str(k),str(int(y)),*[float(x).hex() for x in v[:-1]],str(v[-1])]
        h.update(json.dumps(canonical,separators=(',',':')).encode());h.update(b'\n')
    return h.hexdigest()

class Files:
    def __init__(self):self.used=[];self._index=None
    def record(self,request,path,note='direct or run-local alias'):
        item={'request':request,'path':str(path),'sha256':sha(path),'bytes':Path(path).stat().st_size,'note':note}
        if item not in self.used:self.used.append(item)
        return Path(path)
    def get(self,run,name):
        run=Path(run);variants=[name]
        if name.endswith('.gz'):variants.append(name[:-3])
        elif name.endswith('.csv'):variants.append(name+'.gz')
        for value in variants:
            p=run/value
            if p.is_file():return self.record(run.name+'/'+name,p)
        candidates=[]
        for value in variants:candidates.extend(p for p in run.rglob(value) if p.is_file())
        if not candidates:raise Stop('Required saved file missing: '+str(run/name))
        # Multiple transport copies are allowed only when decoded contents agree.
        signatures={}
        for p in candidates:
            b=read_bytes(p)
            if b[:2]==b'\x1f\x8b':b=gzip.decompress(b)
            signatures.setdefault(hashlib.sha256(b).hexdigest(),[]).append(p)
        if len(signatures)!=1:raise Stop('Conflicting saved copies: '+str(run/name))
        p=min(next(iter(signatures.values())),key=lambda x:(len(x.parts),str(x)))
        return self.record(run.name+'/'+name,p,'identical decoded transport copies')
    def successful(self,pattern,status):
        found=[]
        for root in ROOTS:
            if not root.is_dir():continue
            for p in root.glob(pattern):
                if not p.is_dir():continue
                try:rp=self.get(p,'receipt.json');r=json.loads(rp.read_text())
                except (Stop,OSError,ValueError):continue
                if r.get('status')==status:found.append((p,r))
        if not found:raise Stop('Completed stage not found: '+status)
        # Keep the original timestamp choice; prefer batch5 for equivalent names.
        newest=max(p.name for p,r in found)
        choices=[(p,r) for p,r in found if p.name==newest]
        return min(choices,key=lambda x:(not str(x[0]).startswith(str(PRIMARY)+'/'),len(str(x[0]))))
    def run(self,old):
        p=Path(str(old))
        if p.is_dir():return p
        for root in ROOTS:
            q=root/p.name
            if q.is_dir():return q
        raise Stop('Referenced run directory missing: '+p.name)
    def index(self):
        if self._index is not None:return self._index
        paths=[]
        # Reuse the metadata inventory already produced, avoiding another broad scan.
        inventories=sorted(W.glob('CONTROLLED_FIT_CAL_SPLIT_RESTART_*/archive_inventory.csv'),reverse=True)
        if inventories:
            inventory=pd.read_csv(inventories[0],dtype=str,keep_default_na=False)
            for col in ['origin','logical']:
                if col in inventory:
                    paths.extend(Path(x) for x in inventory[col] if '::' not in x and Path(x).is_file())
        self._index=list(dict.fromkeys(paths));return self._index
    def asset(self,a,label,expected=None):
        expected=expected or a.get('sha256');logical=a.get('member') or a['path'];name=PurePosixPath(logical).name
        candidates=[]
        if Path(a['path']).is_file():
            try:
                b=read_bytes(a['path'],a.get('member',''))
                candidates.append((a['path']+('::'+a['member'] if a.get('member') else ''),b))
            except (OSError,KeyError,zipfile.BadZipFile):pass
        if not a.get('member') and a['path'].endswith('.gz') and Path(a['path'][:-3]).is_file():
            candidates.append((a['path'][:-3],read_bytes(a['path'][:-3])))
        names={name,name[:-3] if name.endswith('.gz') else name+'.gz'}
        if not candidates or (expected and all(hashlib.sha256(b).hexdigest()!=expected for _,b in candidates)):
            indexed=[p for p in self.index() if p.name in names and p.stat().st_size<=128*1024**2]
            old_parts=PurePosixPath(logical).parts
            def suffix(p):
                count=0
                for x,y in zip(reversed(old_parts),reversed(p.parts)):
                    if x!=y:break
                    count+=1
                return count
            indexed.sort(key=lambda p:(-suffix(p),not str(p).startswith(str(PRIMARY)+'/'),len(str(p))))
            for p in indexed:
                if suffix(p)>=2 or expected:candidates.append((str(p),read_bytes(p)))
        chosen=None;note=None
        if expected:
            for origin,b in candidates:
                if hashlib.sha256(b).hexdigest()==expected:chosen=(origin,b);note='original byte SHA-256 verified';break
        elif candidates:chosen=candidates[0];note='no original byte hash supplied; table identities checked'
        if chosen is None and a.get('semantic_sha256'):
            for origin,b in candidates:
                try:
                    content=gzip.decompress(b) if b[:2]==b'\x1f\x8b' else b
                    df=pd.read_csv(io.BytesIO(content),dtype=str,keep_default_na=False)
                    if semantic_sample(df)==a['semantic_sha256']:chosen=(origin,b);note='original sample semantic SHA-256 verified';break
                except Exception:continue
        if chosen is None:
            raise Stop('Manifest asset is missing or does not match its supplied hash: '+label)
        origin,b=chosen;folder=OUT/'resolved_inputs';folder.mkdir(exist_ok=True)
        p=folder/(hashlib.sha256(b).hexdigest()[:20]+'_'+name);p.write_bytes(b)
        return self.record(label,p,note+'; origin='+origin)

L=Files()
try:
    bankdir,bankreceipt=L.successful('CONTROLLED_FIVE_SEED_SOURCE_SPLIT_*','CONTROLLED_FIVE_SEED_SOURCE_SPLIT_BANK_COMPLETE')
    bank_path=L.get(bankdir,'five_seed_models_and_calibrators.joblib');bundle=joblib.load(bank_path)
    models=bundle['models'];calibrators=bundle['calibrators'];protocol=bundle['protocol'];roles=bundle['source_roles']
    expected={(policy,family,seed) for policy in POLICIES for family in ['HGB','LR'] for seed in SEEDS}
    if set(models)!=expected or set(calibrators)!=expected or protocol['model_seeds']!=SEEDS:raise Stop('Five-seed bank contract differs')
    source=norm(csv(L.get(bankdir,'source_panel_with_network_groups.csv.gz')))
    oldval=pd.read_csv(L.get(bankdir,'fixed_outer_validation_results.csv'))
    if not {'source_scenario','source_group'}.issubset(source.columns):raise Stop('Source group metadata missing')
    if set(source.source_scenario)!={f'CTU-IoT-Malware-Capture-{x}-1' for x in [1,3,8]}:raise Stop('Source role changed')
    print('[1/3] Loading the completed five-seed bank and fixed target/UID cohorts.',flush=True)
    a,_=L.successful('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    base,_=L.successful('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    fresh,_=L.successful('FRESH_RAW_CAPTURE48_*','FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE')
    manifest=json.loads(L.get(a,'input_manifest.json').read_text())
    clean49=norm(csv(L.asset(manifest['clean'],'capture49 clean cohort')))
    if clean49.ks.duplicated().any() or len(clean49)!=1024:raise Stop('Capture49 clean cohort invalid')
    mk49=list(clean49.loc[clean49.y.eq(1),'ks'])
    mp0=pd.read_csv(L.get(base,'clean_packet_uid_mapping.csv.gz'),dtype={'original_ks':str,'zeek_uid':str})
    own0=mp0.groupby('original_ks').zeek_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
    if mp0.packet_index.duplicated().any() or set(own0)!=set(mk49) or any(len(v)!=1 for v in own0.values()):raise Stop('Capture49 clean membership differs')
    cf0=clean49.set_index('ks').loc[mk49,F].copy();cf0['uid']=[own0[k][0] for k in mk49];cf0=cf0.reset_index(drop=True)
    targets={'CAPTURE49_LEGACY_COHORT':{'clean':clean49,'states':{0:{'selected':clean49,'records':cf0,'owners':own0,'pure':dict.fromkeys(cf0.uid,True),'complete':dict.fromkeys(mk49,True)}}}}
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds'])
        if delay not in [1,10]:continue
        selected=norm(csv(L.asset(cond['candidate_asset'],f'capture49 {delay}s selected',cond['candidate_sha256'])))
        if selected.ks.duplicated().any() or set(selected.ks)!=set(clean49.ks):raise Stop('Capture49 key set differs')
        selected=selected.set_index('ks').loc[clean49.ks].reset_index()
        d=L.run(cond['validated_result_directory']);rr=json.loads(L.get(d,'receipt.json').read_text())
        if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr.get('historical_transformed_pcap_sha256')!=cond['historical_transformed_pcap_sha256']:raise Stop('Capture49 trace identity differs')
        mm=pd.read_csv(L.get(d,'test2_transformed_membership.csv'),dtype={'ks':str})
        if len(mm)!=512 or not boolean(mm.transformed_membership_validated).all():raise Stop('Capture49 membership not fully validated')
        mp=pd.read_csv(L.get(d,'transformed_packet_uid_mapping.csv.gz'),dtype={'original_ks':str,'transformed_uid':str})
        owners=mp.groupby('original_ks').transformed_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        cf=norm(csv(L.get(d,'transformed_selected_connection_records.csv.gz')),False)
        if mp.packet_index.duplicated().any() or set(owners)!=set(mk49) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.transformed_uid):raise Stop('Capture49 UID coverage differs')
        targets['CAPTURE49_LEGACY_COHORT']['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':dict.fromkeys(cf.uid,True),'complete':dict.fromkeys(mk49,True)}
    clean48=norm(csv(L.get(fresh,'fresh_clean_target_sample.csv.gz')));mk48=list(clean48.loc[clean48.y.eq(1),'ks'])
    target48={'clean':clean48,'states':{}};canonical=None;purity_audit=[]
    baseline_members=pd.read_csv(L.get(fresh,'membership_0s.csv'),dtype={'ks':str})
    if len(baseline_members)!=512 or not boolean(baseline_members.membership_validated).all():raise Stop('Capture48 clean baseline was not fully validated')
    for delay in [0,1,10]:
        selected=norm(csv(L.get(fresh,f'selected_features_{delay}s.csv.gz')))
        if selected.ks.duplicated().any() or set(selected.ks)!=set(clean48.ks):raise Stop('Capture48 key set differs')
        selected=selected.set_index('ks').loc[clean48.ks].reset_index()
        cf=norm(csv(L.get(fresh,f'descendant_features_{delay}s.csv.gz')),False)
        mp=pd.read_csv(L.get(fresh,f'packet_uid_mapping_{delay}s.csv.gz'),dtype={'original_ks':str,'uid':str})
        if mp.packet_index.duplicated().any():raise Stop('Duplicate capture48 packet occurrence')
        current=mp[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True)
        if delay==0:canonical=current
        elif not current.equals(canonical):raise Stop('Capture48 original packet occurrence/owner set changed')
        owners=mp.groupby('original_ks').uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        if set(owners)!=set(mk48) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.uid):raise Stop('Capture48 UID feature coverage differs')
        # Rebuild the existing witness criterion; do not require a separately saved audit directory.
        event_counts=Counter();event_file=L.get(fresh,f'condition_{delay}s_events.txt')
        with open(event_file) as f:
            for line in f:
                if not line.startswith('PACKET|'):continue
                x=line.rstrip('\r\n').split('|')
                if len(x)!=12:raise Stop('Capture48 packet event format differs')
                event_counts[x[2]]+=1
        owner_counts=mp.groupby('uid').original_ks.nunique();packet_counts=mp.groupby('uid').size();rec=cf.set_index('uid');pure={}
        for uid in cf.uid:
            count=int(rec.loc[uid,'orig_pkts']+rec.loc[uid,'resp_pkts'])
            pure[uid]=bool(owner_counts.loc[uid]==1 and count==int(packet_counts.loc[uid])==event_counts[uid])
        purity_audit.append({'delay_seconds':delay,'packet_occurrences':len(mp),'original_units':len(owners),'descendant_UIDs':len(cf),'pure_witness_UIDs':sum(pure.values())})
        target48['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':pure,'complete':dict.fromkeys(mk48,True)}
    targets['CAPTURE48_FRESH_COHORT']=target48
    pd.DataFrame(purity_audit).to_csv(OUT/'capture48_witness_reproduction.csv',index=False)
    for name,t in targets.items():
        clean=t['clean']
        if len(clean)!=1024 or clean.ks.duplicated().any() or int(clean.y.eq(1).sum())!=512 or set(t['states'])!={0,1,10}:raise Stop('Target cohort contract differs: '+name)
        for state in t['states'].values():
            if not np.array_equal(state['selected'].y.to_numpy(),clean.y.to_numpy()):raise Stop('Target labels differ')
    js(OUT/'pre_outcome_protocol.json',{'source_bank':str(bankdir),'source_bank_sha256':sha(bank_path),'model_seeds':SEEDS,
        'source_split_policies':POLICIES,'target_cohorts':list(targets),'conditions_seconds':[0,1,10],
        'estimation_target':'selected-record accuracy; original-unit alarms used as separate outcome',
        'estimators':['AC','DoC','ATC_SOURCE_GE','ATC_FRACTIONAL_TIE_EXPECTATION','CBPE_ACC_POINT'],
        'ATC_fractional_ties':'expected tie contribution, not a new target-selected threshold',
        'warning_threshold':THRESHOLD,'threshold_calibrated_to_FPR':False,'target_labels_used_for_fitting':False,
        'bank_pooling_with_legacy':False,'source_group_holdout_is_not_capture_confirmation':True})
    print('[2/3] Reproducing the 20 saved source validation rows; no fitting.',flush=True)
    val_checks=[];target_rows=[];monitor_rows=[];unit_rows=[]
    with threadpool_limits(limits=2):
        for policy in POLICIES:
            rr=roles[policy];fit=source.iloc[rr['model_fit']];cal=source.iloc[rr['calibration']];validation=source.iloc[rr['validation']]
            for family in ['HGB','LR']:
                for seed in SEEDS:
                    model=models[(policy,family,seed)];calibrator=calibrators[(policy,family,seed)]
                    if list(model.classes_)!=[0,1] or list(calibrator.classes_)!=[0,1]:raise Stop('Unexpected model/calibrator class ordering')
                    pv=model.predict_proba(encode(validation))[:,1];qv=calibrator.predict_proba(logit(pv))[:,1]
                    vm=score_metrics(validation.y,pv);qm=score_metrics(validation.y,qv)
                    previous=oldval[oldval.family.eq(family)&oldval.model_seed.eq(seed)&oldval.split_policy.eq(policy)]
                    if len(previous)!=1:raise Stop('Saved source validation row missing or duplicated')
                    old=previous.iloc[0];ok=all(np.isclose(vm[k],float(old[k]),atol=1e-10,rtol=0) for k in ['accuracy','balanced_accuracy','AUROC','malicious_recall','benign_FPR','Brier','ECE_10_bins'])
                    ok=ok and np.isclose(qm['Brier'],float(old.calibrated_Brier),atol=1e-10,rtol=0) and np.isclose(qm['ECE_10_bins'],float(old.calibrated_ECE_10_bins),atol=1e-10,rtol=0)
                    val_checks.append({'split_policy':policy,'family':family,'model_seed':seed,'source_validation_reproduced':bool(ok)})
                    if not ok:raise Stop('Source validation does not reproduce; no new target result interpreted')
        pd.DataFrame(val_checks).to_csv(OUT/'source_validation_reproduction.csv',index=False)
        print('All 20 saved source validation rows reproduced.',flush=True)
        print('[3/3] Evaluating fixed record/UID cohorts and five point estimators.',flush=True)
        for policy in POLICIES:
            cal=source.iloc[roles[policy]['calibration']]
            for family in ['HGB','LR']:
                for seed in SEEDS:
                    model=models[(policy,family,seed)];calibrator=calibrators[(policy,family,seed)]
                    pc=model.predict_proba(encode(cal))[:,1];dc=pc>=.5;cc=np.maximum(pc,1-pc)
                    cal_accuracy=float((dc==cal.y.to_numpy()).mean());cal_confidence=float(cc.mean());threshold,alpha=atc(cc,dc==cal.y.to_numpy())
                    for target_name,t in targets.items():
                        clean=t['clean'];yy=clean.y.to_numpy(int);mk=list(clean.loc[yy==1,'ks']);N=len(mk);state_results=[]
                        for delay in [0,1,10]:
                            state=t['states'][delay];df=state['selected'];cf=state['records'];p=model.predict_proba(encode(df))[:,1];d=p>=.5
                            confidence=np.maximum(p,1-p);q=calibrator.predict_proba(logit(p))[:,1]
                            alarms=dict(zip(cf.uid,model.predict_proba(encode(cf))[:,1]>=.5));pos=neg=unknown=overlap=0
                            for k in mk:
                                uu=state['owners'][k];has=any(alarms[u] for u in uu);pure=any(alarms[u] and state['pure'].get(u,False) for u in uu)
                                none=state['complete'][k] and not has;classification='PURE_ALARM_WITNESS' if pure else ('NO_RECORD_ALARM' if none else 'UNRESOLVED')
                                pos+=int(pure);neg+=int(none);unknown+=int(classification=='UNRESOLVED');overlap+=int(has)
                                unit_rows.append({'split_policy':policy,'family':family,'model_seed':seed,'target':target_name,'delay_seconds':delay,'ks':k,'classification':classification,'any_overlap_alarm':bool(has)})
                            accuracy=float((d==yy).mean());values={'AC':float(confidence.mean()),'DoC':float(np.clip(cal_accuracy+confidence.mean()-cal_confidence,0,1)),
                                'ATC_SOURCE_GE':float((confidence>=threshold).mean()),'ATC_FRACTIONAL_TIE_EXPECTATION':float(((confidence>threshold).astype(float)+alpha*(confidence==threshold)).mean()),
                                'CBPE_ACC_POINT':float(np.where(d,q,1-q).mean())}
                            tr={'split_policy':policy,'family':family,'model_seed':seed,'target':target_name,'delay_seconds':delay,
                                'record_accuracy':accuracy,'selected_record_recall':float(d[yy==1].mean()),'benign_FPR':float(d[yy==0].mean()),
                                'original_units':N,'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                                'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap}
                            target_rows.append(tr);state_results.append((delay,accuracy,pos/N,(pos+unknown)/N,values))
                        baseline=state_results[0]
                        for delay,truth,lower,upper,values in state_results:
                            for method,value in values.items():
                                estimated_drop=baseline[4][method]-value;loss_lower=baseline[2]-upper;loss_upper=baseline[3]-lower
                                monitor_rows.append({'split_policy':policy,'family':family,'model_seed':seed,'target':target_name,'delay_seconds':delay,'estimator':method,
                                    'record_accuracy':truth,'estimate':value,'absolute_error':abs(value-truth),'overestimation':value-truth,
                                    'record_accuracy_drop':baseline[1]-truth,'estimated_record_accuracy_drop':estimated_drop,
                                    'differential_error':abs(estimated_drop-(baseline[1]-truth)),
                                    'unit_detection_drop_lower':loss_lower,'unit_detection_drop_upper':loss_upper,
                                    'warning_at_5pp':estimated_drop>=THRESHOLD,'definite_unit_damage':loss_lower>=THRESHOLD,
                                    'missed_definite_unit_damage':bool(loss_lower>=THRESHOLD and estimated_drop<THRESHOLD)})
                    pd.DataFrame(target_rows).to_csv(OUT/'five_seed_target_results.csv',index=False)
                    pd.DataFrame(monitor_rows).to_csv(OUT/'five_seed_point_monitor_results.csv',index=False)
                    print('Completed:',policy,family,seed,flush=True)
    tr=pd.DataFrame(target_rows);mr=pd.DataFrame(monitor_rows)
    if len(tr)!=120 or len(mr)!=600:raise Stop('Unexpected final row count')
    pd.DataFrame(unit_rows).to_csv(OUT/'five_seed_original_unit_predictions.csv.gz',index=False,compression='gzip')
    idx=['family','model_seed','target','delay_seconds'];group=tr[tr.split_policy.eq('GROUP_DISJOINT')].set_index(idx)
    row=tr[tr.split_policy.eq('ROW_FIT_CAL_CONTROL')].set_index(idx).reindex(group.index)
    change=group[['record_accuracy','unit_detection_lower','unit_detection_upper','benign_FPR']].copy()
    for c in list(change.columns):change[c+'_ROW_minus_GROUP']=row[c]-group[c]
    change=change.reset_index();change.to_csv(OUT/'paired_target_split_policy_changes.csv',index=False)
    for policy,title in [('GROUP_DISJOINT','EXPERIMENT 1 — FIVE-SEED GROUP-DISJOINT TARGETS'),('ROW_FIT_CAL_CONTROL','EXPERIMENT 2 — FIVE-SEED ROW FIT/CAL CONTROL')]:
        print('\n'+title+'\n'+tr[tr.split_policy.eq(policy)&tr.delay_seconds.eq(10)].to_string(index=False),flush=True)
    summary=mr[mr.delay_seconds.eq(10)].groupby(['split_policy','family','target','estimator'],as_index=False).agg(
        seed_rows=('model_seed','size'),mean_absolute_error=('absolute_error','mean'),mean_overestimation=('overestimation','mean'),
        mean_differential_error=('differential_error','mean'),warning_fraction_over_seed_rows=('warning_at_5pp','mean'),
        missed_definite_damage_fraction=('missed_definite_unit_damage','mean'))
    summary.to_csv(OUT/'five_seed_point_monitor_summary_10s.csv',index=False)
    print('\nEXPERIMENT 3 — POINT-MONITOR COMPARISON AT 10s\n'+summary.to_string(index=False),flush=True)
    print('\nPAIRED SPLIT-POLICY CHANGES AT 10s\n'+change[change.delay_seconds.eq(10)].to_string(index=False),flush=True)
    # Store a compact, directly reusable target fixture and exact source-bank copy.
    fixtures=OUT/'fixed_target_inputs';fixtures.mkdir()
    for name,t in targets.items():
        folder=fixtures/name;folder.mkdir()
        t['clean'].to_csv(folder/'clean.csv.gz',index=False,compression='gzip')
        meta={}
        for delay,state in t['states'].items():
            state['selected'].to_csv(folder/f'selected_{delay}s.csv.gz',index=False,compression='gzip')
            state['records'].to_csv(folder/f'records_{delay}s.csv.gz',index=False,compression='gzip')
            meta[str(delay)]={'owners':state['owners'],'pure':state['pure'],'complete':state['complete']}
        js(folder/'UID_relations.json',meta)
    bankcopy=OUT/'source_bank_inputs';bankcopy.mkdir()
    for filename in ['five_seed_models_and_calibrators.joblib','source_panel_with_network_groups.csv.gz','fixed_source_memberships.csv.gz','pre_outcome_protocol.json','fixed_outer_validation_results.csv']:
        src=L.get(bankdir,filename);shutil.copyfile(src,bankcopy/src.name)
    R.update({'status':'FIVE_SEED_FIXED_TARGET_AND_POINT_MONITOR_APPLICATION_COMPLETE','model_seeds':SEEDS,
        'saved_source_validation_rows_reproduced':len(val_checks),'target_result_rows':len(tr),'point_monitor_rows':len(mr),
        'target_cohorts':list(targets),'point_warning_unit':'one whole fixed 1024-row cohort per seed/condition, not old 128-row windows',
        'legacy_bank_results_not_pooled':True,'original_unit_recall_not_estimated_by_accuracy_methods':True,
        'source_split_control_target_application_complete':True,'remaining_packet_captures':[7,9,33,36,39,43],
        'remaining_work':['Packet-aware six-capture evaluation where feasible','Consistent full-bank/gate/MD3 alignment if extending those comparisons','Final baseline/bibliographic and legacy AUROC audit','Model-backed final reproducibility/resource package'],
        'interpretation':'All seeds, arms, cohorts, and conditions retained. Means over identical seed outputs are not new independent evidence. Comparisons are post-exposure sensitivity results, not causal leakage attribution or confirmatory significance.'})
except Exception as error:
    R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
finally:
    pd.DataFrame(L.used).to_csv(OUT/'input_resolution_and_hashes.csv',index=False);js(OUT/'receipt.json',R)
    package=OUT/'PRIVATE_five_seed_fixed_target_results_and_inputs.zip';entries=[]
    try:
        with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for p in OUT.rglob('*'):
                if p.is_file() and p!=package and p.suffix.lower()!='.zip':
                    rel=str(p.relative_to(OUT));z.write(p,arcname=rel);entries.append({'member':rel,'sha256':sha(p),'bytes':p.stat().st_size})
            z.writestr('ARCHIVE_FILE_MANIFEST.json',json.dumps(entries,indent=2))
        with zipfile.ZipFile(package) as z:
            for entry in entries:
                h=hashlib.sha256()
                with z.open(entry['member']) as f:
                    for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
                if h.hexdigest()!=entry['sha256']:raise Stop('Output archive hash verification failed')
        R['private_archive']={'path':str(package),'bytes':package.stat().st_size,'sha256':sha(package),'members_verified':len(entries),
                              'source_bank_and_target_fixtures_included':R.get('status')=='FIVE_SEED_FIXED_TARGET_AND_POINT_MONITOR_APPLICATION_COMPLETE','final_release':False}
    except Exception as error:R['archive_error']=str(error)
    js(OUT/'receipt.json',R);print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
