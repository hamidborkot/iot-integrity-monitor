# Fixed-target application v2: complete helpers, no earlier Python state required.
# Uses the completed five-seed source bank and preserved target/UID artifacts.
# No training, source split changes, target sampling, or PCAP replay.
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from collections import Counter
import gzip, hashlib, io, json, shutil, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working');PRIMARY=Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')
OWNER=Path('/kaggle/input/datasets/mdhamidborkottulla')
ROOTS=[PRIMARY,W]+[OWNER/n for n in ['zeek-new','the-last-days-backup','full-backup','all-kaggle-work','complete-backup','one-last','last-day-backup','the-last-update','whole-in-one','ran-files']]
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
SEEDS=[8101,8102,8103,8104,8105];POLICIES=['GROUP_DISJOINT','ROW_FIT_CAL_CONTROL'];THRESHOLD=.05
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

def decoded(b):
    if b[:2]==b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:b=f.read(128*1024**2+1)
        if len(b)>128*1024**2:raise Stop('Expanded CSV too large')
    return b

def csv(path):return pd.read_csv(io.BytesIO(decoded(read_bytes(path))),dtype=str,keep_default_na=False)
def norm(df,labelled=True):
    df=df.copy();needed=F+(['ks','y'] if labelled else [])
    if not set(needed).issubset(df.columns):raise Stop('Required columns missing: '+str(set(needed)-set(df.columns)))
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid feature '+c)
    df['proto']=df.proto.astype(str).str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    if labelled:
        y=pd.to_numeric(df.y,errors='raise')
        if not y.isin([0,1]).all():raise Stop('Invalid labels')
        df['y']=y.astype(int);df['ks']=df.ks.astype(str)
    return df

def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def logit(p):
    p=np.clip(np.asarray(p,float),1e-6,1-1e-6);return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)

def score_metrics(y,p):
    y=np.asarray(y,int);p=np.asarray(p,float)
    if y.shape!=p.shape or set(y)!={0,1} or not np.isfinite(p).all() or ((p<0)|(p>1)).any():raise Stop('Invalid binary metric inputs')
    d=p>=.5;bins=np.minimum((p*10).astype(int),9);ece=0.
    for j in range(10):
        mask=bins==j
        if mask.any():ece+=float(mask.mean())*abs(float(p[mask].mean()-y[mask].mean()))
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
        'AUROC':float(roc_auc_score(y,p)),'malicious_recall':float(d[y==1].mean()),'benign_FPR':float(d[y==0].mean()),
        'Brier':float(np.mean((p-y)**2)),'ECE_10_bins':ece}

def atc(conf,correct):
    conf=np.asarray(conf,float);correct=np.asarray(correct,bool)
    if not len(conf) or conf.shape!=correct.shape or not np.isfinite(conf).all():raise Stop('Invalid ATC source inputs')
    n=int(correct.sum())
    if n==0:return float(np.nextafter(conf.max(),np.inf)),0.
    threshold=float(np.sort(conf)[::-1][n-1]);above=int((conf>threshold).sum());ties=int((conf==threshold).sum())
    alpha=(n-above)/ties
    if not 0<=alpha<=1:raise Stop('ATC fractional tie calculation failed')
    return threshold,float(alpha)

def semantic_sample(df):
    d=norm(df);h=hashlib.sha256()
    for row in d.sort_values('ks',kind='stable')[['ks','y']+F].itertuples(index=False,name=None):
        k,y,*v=row;values=[str(k),str(int(y)),*[float(x).hex() for x in v[:-1]],str(v[-1])]
        h.update(json.dumps(values,separators=(',',':')).encode());h.update(b'\n')
    return h.hexdigest()

class Files:
    def __init__(self,out):self.out=Path(out);self.used=[];self._index=None
    def record(self,request,path,note='run-local file or CSV/GZip alias'):
        row={'request':request,'path':str(path),'sha256':sha(path),'bytes':Path(path).stat().st_size,'note':note}
        if row not in self.used:self.used.append(row)
        return Path(path)
    def get(self,run,name):
        run=Path(run);variants=[name]
        if name.endswith('.gz'):variants.append(name[:-3])
        elif name.endswith('.csv'):variants.append(name+'.gz')
        for n in variants:
            p=run/n
            if p.is_file():return self.record(run.name+'/'+name,p)
        candidates=[]
        for n in variants:candidates.extend(p for p in run.rglob(n) if p.is_file())
        if not candidates:raise Stop('Required saved file missing: '+str(run/name))
        groups={}
        for p in candidates:groups.setdefault(hashlib.sha256(decoded(read_bytes(p))).hexdigest(),[]).append(p)
        if len(groups)!=1:raise Stop('Conflicting saved copies: '+str(run/name))
        return self.record(run.name+'/'+name,min(next(iter(groups.values())),key=lambda p:(len(p.parts),str(p))))
    def successful(self,pattern,status):
        found=[]
        for root in ROOTS:
            if not root.is_dir():continue
            for p in root.glob(pattern):
                if not p.is_dir():continue
                try:r=json.loads(self.get(p,'receipt.json').read_text())
                except (Stop,OSError,ValueError):continue
                if r.get('status')==status:found.append((p,r))
        if not found:raise Stop('Completed stage not found: '+status)
        newest=max(p.name for p,r in found)
        return min([(p,r) for p,r in found if p.name==newest],key=lambda x:(not str(x[0]).startswith(str(PRIMARY)+'/'),len(str(x[0]))))
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
        inventories=sorted(W.glob('CONTROLLED_FIT_CAL_SPLIT_RESTART_*/archive_inventory.csv'),reverse=True)
        if inventories:
            data=pd.read_csv(inventories[0],dtype=str,keep_default_na=False)
            for column in ['origin','logical']:
                if column in data:paths.extend(Path(x) for x in data[column] if '::' not in x and Path(x).is_file())
        self._index=list(dict.fromkeys(paths));return self._index
    def asset(self,a,label,expected=None):
        expected=expected or a.get('sha256');logical=a.get('member') or a['path'];name=PurePosixPath(logical).name;candidates=[]
        if Path(a['path']).is_file():
            try:candidates.append((a['path']+('::'+a['member'] if a.get('member') else ''),read_bytes(a['path'],a.get('member',''))))
            except (OSError,KeyError,zipfile.BadZipFile):pass
        if not a.get('member') and a['path'].endswith('.gz') and Path(a['path'][:-3]).is_file():candidates.append((a['path'][:-3],read_bytes(a['path'][:-3])))
        if not candidates or (expected and all(hashlib.sha256(b).hexdigest()!=expected for _,b in candidates)):
            names={name,name[:-3] if name.endswith('.gz') else name+'.gz'};parts=PurePosixPath(logical).parts
            def suffix(p):
                n=0
                for x,y in zip(reversed(parts),reversed(p.parts)):
                    if x!=y:break
                    n+=1
                return n
            indexed=[p for p in self.index() if p.name in names and p.stat().st_size<=128*1024**2]
            indexed.sort(key=lambda p:(-suffix(p),not str(p).startswith(str(PRIMARY)+'/'),len(str(p))))
            for p in indexed:
                if suffix(p)>=2 or expected:candidates.append((str(p),read_bytes(p)))
        chosen=None;note=None
        for origin,b in candidates:
            if expected and hashlib.sha256(b).hexdigest()==expected:chosen=(origin,b);note='original byte SHA-256 verified';break
        if chosen is None and not expected and candidates:chosen=candidates[0];note='no original byte hash supplied'
        if chosen is None and a.get('semantic_sha256'):
            for origin,b in candidates:
                try:
                    df=pd.read_csv(io.BytesIO(decoded(b)),dtype=str,keep_default_na=False)
                    if semantic_sample(df)==a['semantic_sha256']:chosen=(origin,b);note='original sample semantic SHA-256 verified';break
                except Exception:continue
        if chosen is None:raise Stop('Manifest asset missing or hash does not match: '+label)
        origin,b=chosen;folder=self.out/'resolved_inputs';folder.mkdir(exist_ok=True)
        p=folder/(hashlib.sha256(b).hexdigest()[:20]+'_'+name);p.write_bytes(b)
        return self.record(label,p,note+'; origin='+origin)

def targets_load(L):
    a,_=L.successful('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    base,_=L.successful('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    fresh,_=L.successful('FRESH_RAW_CAPTURE48_*','FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE')
    manifest=json.loads(L.get(a,'input_manifest.json').read_text())
    c49=norm(csv(L.asset(manifest['clean'],'capture49 clean cohort')))
    if len(c49)!=1024 or c49.ks.duplicated().any():raise Stop('Invalid capture49 clean cohort')
    mk49=list(c49.loc[c49.y.eq(1),'ks']);mp0=pd.read_csv(L.get(base,'clean_packet_uid_mapping.csv.gz'),dtype={'original_ks':str,'zeek_uid':str})
    owners0=mp0.groupby('original_ks').zeek_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
    if mp0.packet_index.duplicated().any() or set(owners0)!=set(mk49) or any(len(v)!=1 for v in owners0.values()):raise Stop('Capture49 clean membership differs')
    cf0=c49.set_index('ks').loc[mk49,F].copy();cf0['uid']=[owners0[k][0] for k in mk49];cf0=cf0.reset_index(drop=True)
    targets={'CAPTURE49_LEGACY_COHORT':{'clean':c49,'states':{0:{'selected':c49,'records':cf0,'owners':owners0,'pure':dict.fromkeys(cf0.uid,True),'complete':dict.fromkeys(mk49,True)}}}}
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds'])
        if delay not in [1,10]:continue
        selected=norm(csv(L.asset(cond['candidate_asset'],f'capture49 {delay}s selected',cond['candidate_sha256'])))
        if selected.ks.duplicated().any() or set(selected.ks)!=set(c49.ks):raise Stop('Capture49 key set differs')
        selected=selected.set_index('ks').loc[c49.ks].reset_index();root=L.run(cond['validated_result_directory']);r=json.loads(L.get(root,'receipt.json').read_text())
        if r.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or r.get('historical_transformed_pcap_sha256')!=cond['historical_transformed_pcap_sha256']:raise Stop('Capture49 trace identity differs')
        mm=pd.read_csv(L.get(root,'test2_transformed_membership.csv'),dtype={'ks':str})
        if len(mm)!=512 or not boolean(mm.transformed_membership_validated).all():raise Stop('Capture49 membership not fully validated')
        mp=pd.read_csv(L.get(root,'transformed_packet_uid_mapping.csv.gz'),dtype={'original_ks':str,'transformed_uid':str})
        owners=mp.groupby('original_ks').transformed_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict();cf=norm(csv(L.get(root,'transformed_selected_connection_records.csv.gz')),False)
        if mp.packet_index.duplicated().any() or set(owners)!=set(mk49) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.transformed_uid):raise Stop('Capture49 UID coverage differs')
        targets['CAPTURE49_LEGACY_COHORT']['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':dict.fromkeys(cf.uid,True),'complete':dict.fromkeys(mk49,True)}
    c48=norm(csv(L.get(fresh,'fresh_clean_target_sample.csv.gz')));mk48=list(c48.loc[c48.y.eq(1),'ks']);t48={'clean':c48,'states':{}};canonical=None;purity_rows=[]
    baseline=pd.read_csv(L.get(fresh,'membership_0s.csv'),dtype={'ks':str})
    if len(baseline)!=512 or not boolean(baseline.membership_validated).all():raise Stop('Capture48 clean membership invalid')
    for delay in [0,1,10]:
        selected=norm(csv(L.get(fresh,f'selected_features_{delay}s.csv.gz')))
        if selected.ks.duplicated().any() or set(selected.ks)!=set(c48.ks):raise Stop('Capture48 selected keys differ')
        selected=selected.set_index('ks').loc[c48.ks].reset_index();cf=norm(csv(L.get(fresh,f'descendant_features_{delay}s.csv.gz')),False)
        mp=pd.read_csv(L.get(fresh,f'packet_uid_mapping_{delay}s.csv.gz'),dtype={'original_ks':str,'uid':str})
        if mp.packet_index.duplicated().any():raise Stop('Duplicate capture48 packet occurrence')
        current=mp[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True)
        if delay==0:canonical=current
        elif not current.equals(canonical):raise Stop('Capture48 packet occurrence/owner identities changed')
        owners=mp.groupby('original_ks').uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        if set(owners)!=set(mk48) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.uid):raise Stop('Capture48 UID coverage differs')
        event_counts=Counter()
        with open(L.get(fresh,f'condition_{delay}s_events.txt')) as f:
            for line in f:
                if line.startswith('PACKET|'):
                    v=line.rstrip('\r\n').split('|')
                    if len(v)!=12:raise Stop('Capture48 packet-event format differs')
                    event_counts[v[2]]+=1
        owner_counts=mp.groupby('uid').original_ks.nunique();packet_counts=mp.groupby('uid').size();rec=cf.set_index('uid');pure={}
        for uid in cf.uid:pure[uid]=bool(owner_counts.loc[uid]==1 and int(rec.loc[uid,'orig_pkts']+rec.loc[uid,'resp_pkts'])==int(packet_counts.loc[uid])==event_counts[uid])
        purity_rows.append({'delay_seconds':delay,'packet_occurrences':len(mp),'original_units':len(owners),'descendant_UIDs':len(cf),'pure_witness_UIDs':sum(pure.values())})
        t48['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':pure,'complete':dict.fromkeys(mk48,True)}
    targets['CAPTURE48_FRESH_COHORT']=t48
    for name,t in targets.items():
        if len(t['clean'])!=1024 or t['clean'].ks.duplicated().any() or int(t['clean'].y.eq(1).sum())!=512 or set(t['states'])!={0,1,10}:raise Stop('Target contract differs: '+name)
        for state in t['states'].values():
            if not np.array_equal(state['selected'].y.to_numpy(),t['clean'].y.to_numpy()):raise Stop('Target labels differ')
    return targets,purity_rows

def save_target_fixtures(out,targets):
    root=out/'fixed_target_inputs';root.mkdir(exist_ok=True)
    for name,t in targets.items():
        folder=root/name;folder.mkdir(exist_ok=True);t['clean'].to_csv(folder/'clean.csv.gz',index=False,compression='gzip');meta={}
        for delay,state in t['states'].items():
            state['selected'].to_csv(folder/f'selected_{delay}s.csv.gz',index=False,compression='gzip')
            state['records'].to_csv(folder/f'records_{delay}s.csv.gz',index=False,compression='gzip')
            meta[str(delay)]={k:state[k] for k in ['owners','pure','complete']}
        js(folder/'UID_relations.json',meta)

def main():
    out=W/('FIVE_SEED_FIXED_TARGET_APPLICATION_V2_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir(parents=True,exist_ok=False)
    r={'status':'STARTED','new_model_fits':0,'new_calibrator_fits':0,'new_PCAP_replays':0,'target_resampling':False,
       'legacy_and_new_banks_pooled':False,'independent_confirmation':False,'six_remaining_packet_captures_completed':False,'output_directory':str(out)}
    loader=Files(out)
    try:
        # Run the omitted-helper checks before any dataset work.
        if not callable(score_metrics) or not callable(atc):raise Stop('Internal helper check failed')
        test=score_metrics(np.array([0,1]),np.array([.1,.9]))
        if not np.isclose(test['Brier'],.01) or test['accuracy']!=1.:raise Stop('Internal binary-metric self-check failed')
        th,al=atc(np.array([.6,.6,.9,.9]),np.array([1,1,1,0]))
        if not np.isclose(((np.array([.6,.6,.9,.9])>th)+al*(np.array([.6,.6,.9,.9])==th)).mean(),.75):raise Stop('Internal ATC tie self-check failed')
        bankdir,_=loader.successful('CONTROLLED_FIVE_SEED_SOURCE_SPLIT_*','CONTROLLED_FIVE_SEED_SOURCE_SPLIT_BANK_COMPLETE')
        bank_path=loader.get(bankdir,'five_seed_models_and_calibrators.joblib');bundle=joblib.load(bank_path)
        models=bundle['models'];calibrators=bundle['calibrators'];protocol=bundle['protocol'];roles=bundle['source_roles']
        expected={(policy,family,seed) for policy in POLICIES for family in ['HGB','LR'] for seed in SEEDS}
        if set(models)!=expected or set(calibrators)!=expected or protocol['model_seeds']!=SEEDS:raise Stop('Five-seed bank contract differs')
        source=norm(csv(loader.get(bankdir,'source_panel_with_network_groups.csv.gz')));oldval=pd.read_csv(loader.get(bankdir,'fixed_outer_validation_results.csv'))
        if not {'source_scenario','source_group'}.issubset(source.columns):raise Stop('Source grouping metadata missing')
        if set(source.source_scenario)!={f'CTU-IoT-Malware-Capture-{x}-1' for x in [1,3,8]}:raise Stop('Source role differs')
        print('[1/3] Loading the completed bank and fixed target/UID cohorts; helpers are defined.',flush=True)
        targets,purity_rows=targets_load(loader);pd.DataFrame(purity_rows).to_csv(out/'capture48_witness_reproduction.csv',index=False)
        # Persist the restored inputs before validation/evaluation so another disconnect
        # does not leave only a small error archive.
        save_target_fixtures(out,targets);bankcopy=out/'source_bank_inputs';bankcopy.mkdir(exist_ok=True)
        for name in ['five_seed_models_and_calibrators.joblib','source_panel_with_network_groups.csv.gz','fixed_source_memberships.csv.gz','pre_outcome_protocol.json','fixed_outer_validation_results.csv']:
            src=loader.get(bankdir,name);shutil.copyfile(src,bankcopy/src.name)
        r['input_checkpoint_written']=True
        js(out/'pre_outcome_protocol.json',{'source_bank':str(bankdir),'source_bank_sha256':sha(bank_path),'model_seeds':SEEDS,'split_policies':POLICIES,
            'target_cohorts':list(targets),'conditions_seconds':[0,1,10],
            'estimators':['AC','DoC','ATC_SOURCE_GE','ATC_FRACTIONAL_TIE_EXPECTATION','CBPE_ACC_POINT'],
            'warning_threshold':THRESHOLD,'FPR_calibrated_threshold':False,'target_labels_used_for_fitting':False,
            'point_estimation_target':'selected-record accuracy; original-unit detection is a separate outcome',
            'warning_unit':'whole fixed 1024-row cohort; not earlier 128-row windows','legacy_bank_pooled':False})
        validation_rows=[];target_rows=[];monitor_rows=[];unit_rows=[]
        print('[2/3] Reproducing all 20 saved source-validation rows; no fitting.',flush=True)
        with threadpool_limits(limits=2):
            for policy in POLICIES:
                val=source.iloc[roles[policy]['validation']]
                for family in ['HGB','LR']:
                    for seed in SEEDS:
                        model=models[(policy,family,seed)];calibrator=calibrators[(policy,family,seed)]
                        if list(model.classes_)!=[0,1] or list(calibrator.classes_)!=[0,1]:raise Stop('Unexpected class ordering')
                        p=model.predict_proba(encode(val))[:,1];q=calibrator.predict_proba(logit(p))[:,1]
                        vm=score_metrics(val.y,p);qm=score_metrics(val.y,q)
                        previous=oldval[oldval.family.eq(family)&oldval.model_seed.eq(seed)&oldval.split_policy.eq(policy)]
                        if len(previous)!=1:raise Stop('Saved source-validation row not unique')
                        old=previous.iloc[0];ok=all(np.isclose(vm[k],float(old[k]),atol=1e-10,rtol=0) for k in ['accuracy','balanced_accuracy','AUROC','malicious_recall','benign_FPR','Brier','ECE_10_bins'])
                        ok=ok and np.isclose(qm['Brier'],float(old.calibrated_Brier),atol=1e-10,rtol=0) and np.isclose(qm['ECE_10_bins'],float(old.calibrated_ECE_10_bins),atol=1e-10,rtol=0)
                        validation_rows.append({'split_policy':policy,'family':family,'model_seed':seed,'source_validation_reproduced':bool(ok)})
                        pd.DataFrame(validation_rows).to_csv(out/'source_validation_reproduction.csv',index=False)
                        if not ok:raise Stop('Source validation does not reproduce; no target interpretation accepted')
            print('All 20 source-validation rows reproduced.',flush=True)
            print('[3/3] Applying grouped/control banks and five point estimators to both fixed cohorts.',flush=True)
            for policy in POLICIES:
                cal=source.iloc[roles[policy]['calibration']]
                for family in ['HGB','LR']:
                    for seed in SEEDS:
                        model=models[(policy,family,seed)];calibrator=calibrators[(policy,family,seed)]
                        pc=model.predict_proba(encode(cal))[:,1];dc=pc>=.5;cc=np.maximum(pc,1-pc)
                        ca=float((dc==cal.y.to_numpy()).mean());cm=float(cc.mean());threshold,alpha=atc(cc,dc==cal.y.to_numpy())
                        for target_name,t in targets.items():
                            clean=t['clean'];yy=clean.y.to_numpy(int);mk=list(clean.loc[yy==1,'ks']);N=len(mk);states=[]
                            for delay in [0,1,10]:
                                state=t['states'][delay];df=state['selected'];cf=state['records'];p=model.predict_proba(encode(df))[:,1];d=p>=.5
                                confidence=np.maximum(p,1-p);q=calibrator.predict_proba(logit(p))[:,1];alarms=dict(zip(cf.uid,model.predict_proba(encode(cf))[:,1]>=.5))
                                pos=neg=unknown=overlap=0
                                for k in mk:
                                    uu=state['owners'][k];has=any(alarms[u] for u in uu);pure=any(alarms[u] and state['pure'].get(u,False) for u in uu);none=state['complete'][k] and not has
                                    label='PURE_ALARM_WITNESS' if pure else ('NO_RECORD_ALARM' if none else 'UNRESOLVED')
                                    pos+=int(pure);neg+=int(none);unknown+=int(label=='UNRESOLVED');overlap+=int(has)
                                    unit_rows.append({'split_policy':policy,'family':family,'model_seed':seed,'target':target_name,'delay_seconds':delay,'ks':k,'classification':label,'any_overlap_alarm':bool(has)})
                                truth=float((d==yy).mean());values={'AC':float(confidence.mean()),'DoC':float(np.clip(ca+confidence.mean()-cm,0,1)),
                                    'ATC_SOURCE_GE':float((confidence>=threshold).mean()),'ATC_FRACTIONAL_TIE_EXPECTATION':float(((confidence>threshold).astype(float)+alpha*(confidence==threshold)).mean()),
                                    'CBPE_ACC_POINT':float(np.where(d,q,1-q).mean())}
                                target_rows.append({'split_policy':policy,'family':family,'model_seed':seed,'target':target_name,'delay_seconds':delay,
                                    'record_accuracy':truth,'selected_record_recall':float(d[yy==1].mean()),'benign_FPR':float(d[yy==0].mean()),
                                    'original_units':N,'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                                    'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap})
                                states.append((delay,truth,pos/N,(pos+unknown)/N,values))
                            baseline=states[0]
                            for delay,truth,lower,upper,values in states:
                                for method,value in values.items():
                                    drop=baseline[4][method]-value;loss_lower=baseline[2]-upper;loss_upper=baseline[3]-lower
                                    monitor_rows.append({'split_policy':policy,'family':family,'model_seed':seed,'target':target_name,'delay_seconds':delay,'estimator':method,
                                        'record_accuracy':truth,'estimate':value,'absolute_error':abs(value-truth),'overestimation':value-truth,
                                        'record_accuracy_drop':baseline[1]-truth,'estimated_record_accuracy_drop':drop,'differential_error':abs(drop-(baseline[1]-truth)),
                                        'unit_detection_drop_lower':loss_lower,'unit_detection_drop_upper':loss_upper,
                                        'warning_at_5pp':drop>=THRESHOLD,'definite_unit_damage':loss_lower>=THRESHOLD,'missed_definite_unit_damage':bool(loss_lower>=THRESHOLD and drop<THRESHOLD)})
                        pd.DataFrame(target_rows).to_csv(out/'five_seed_target_results.csv',index=False);pd.DataFrame(monitor_rows).to_csv(out/'five_seed_point_monitor_results.csv',index=False)
                        print('Completed:',policy,family,seed,flush=True)
        tr=pd.DataFrame(target_rows);mr=pd.DataFrame(monitor_rows)
        if len(tr)!=120 or len(mr)!=600:raise Stop('Unexpected final result row counts')
        pd.DataFrame(unit_rows).to_csv(out/'five_seed_original_unit_predictions.csv.gz',index=False,compression='gzip')
        idx=['family','model_seed','target','delay_seconds'];group=tr[tr.split_policy.eq('GROUP_DISJOINT')].set_index(idx);row=tr[tr.split_policy.eq('ROW_FIT_CAL_CONTROL')].set_index(idx).reindex(group.index)
        change=group[['record_accuracy','unit_detection_lower','unit_detection_upper','benign_FPR']].copy()
        for field in list(change):change[field+'_ROW_minus_GROUP']=row[field]-group[field]
        change=change.reset_index();change.to_csv(out/'paired_target_split_policy_changes.csv',index=False)
        for policy,title in [('GROUP_DISJOINT','EXPERIMENT 1 — GROUP-DISJOINT TARGET RESULTS'),('ROW_FIT_CAL_CONTROL','EXPERIMENT 2 — ROW FIT/CAL CONTROL TARGET RESULTS')]:
            print('\n'+title+'\n'+tr[tr.split_policy.eq(policy)&tr.delay_seconds.eq(10)].to_string(index=False),flush=True)
        summary=mr[mr.delay_seconds.eq(10)].groupby(['split_policy','family','target','estimator'],as_index=False).agg(
            seed_rows=('model_seed','size'),mean_absolute_error=('absolute_error','mean'),mean_overestimation=('overestimation','mean'),
            mean_differential_error=('differential_error','mean'),warning_fraction_over_seed_rows=('warning_at_5pp','mean'),missed_definite_damage_fraction=('missed_definite_unit_damage','mean'))
        summary.to_csv(out/'five_seed_point_monitor_summary_10s.csv',index=False)
        print('\nEXPERIMENT 3 — FIVE POINT ESTIMATORS AT 10s\n'+summary.to_string(index=False),flush=True)
        print('\nPAIRED TARGET CHANGES AT 10s\n'+change[change.delay_seconds.eq(10)].to_string(index=False),flush=True)
        r.update({'status':'FIVE_SEED_FIXED_TARGET_AND_POINT_MONITOR_APPLICATION_COMPLETE','model_seeds':SEEDS,
            'saved_source_validation_rows_reproduced':len(validation_rows),'target_result_rows':len(tr),'point_monitor_rows':len(mr),
            'target_cohorts':list(targets),'point_warning_unit':'whole fixed 1024-row cohort; not earlier 128-row windows',
            'source_split_control_target_application_complete':True,'remaining_packet_captures':[7,9,33,36,39,43],
            'remaining_work':['Six-capture packet-aware evaluation where feasible','Consistent full-bank/gate/MD3 alignment if extended','Final baseline/bibliography and legacy AUROC audit','Final reproducibility/resource package'],
            'interpretation':'Both arms, all seeds and conditions retained. Repeated identical seed outputs are not independent target evidence. This does not identify a unique causal leakage mechanism.'})
    except Exception as error:
        r['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';r['reason']=str(error)
        (out/'error.txt').write_text(traceback.format_exc());print('\n'+r['status']+': '+str(error),flush=True)
    finally:
        pd.DataFrame(loader.used).to_csv(out/'input_resolution_and_hashes.csv',index=False);js(out/'receipt.json',r)
        package=out/'PRIVATE_five_seed_fixed_target_results_and_inputs.zip';entries=[]
        try:
            with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
                for p in out.rglob('*'):
                    if p.is_file() and p!=package and p.suffix.lower()!='.zip':
                        rel=str(p.relative_to(out));z.write(p,arcname=rel);entries.append({'member':rel,'sha256':sha(p),'bytes':p.stat().st_size})
                z.writestr('ARCHIVE_FILE_MANIFEST.json',json.dumps(entries,indent=2))
            with zipfile.ZipFile(package) as z:
                for entry in entries:
                    h=hashlib.sha256()
                    with z.open(entry['member']) as f:
                        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
                    if h.hexdigest()!=entry['sha256']:raise Stop('Archive hash mismatch')
            r['private_archive']={'path':str(package),'bytes':package.stat().st_size,'sha256':sha(package),'members_verified':len(entries),
                'source_bank_and_target_fixtures_included':r.get('input_checkpoint_written',False),'final_release':False}
        except Exception as error:r['archive_error']=str(error)
        js(out/'receipt.json',r);print('\nRECEIPT\n'+json.dumps(r,indent=2),flush=True)

if __name__=='__main__':main()
