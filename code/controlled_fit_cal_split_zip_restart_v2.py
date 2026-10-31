# ZIP RESTART v2: self-contained controlled fit/cal split ablation.
# Audits batch5, lazily restores only required inputs, verifies grouped results,
# and checkpoints every new row-control model/calibrator pair.
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from contextlib import contextmanager
from collections import defaultdict, Counter
import fnmatch, gzip, hashlib, io, json, os, shutil, traceback, warnings, zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from threadpoolctl import threadpool_limits

PRIMARY=Path('/kaggle/input/datasets/mdhamidborkottulla/batch5')
OWNER=Path('/kaggle/input/datasets/mdhamidborkottulla')
AUX=[OWNER/n for n in ['zeek-new','all-kaggle-work','complete-backup','full-backup','last-day-backup','one-last','ran-files','the-last-update','whole-in-one','the-last-days-backup']]
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
MODEL_SEED=8101;THRESHOLD=.05
MAX_FILE=256*1024**2;MAX_NESTED=1024**3;MAX_CONTAINER_CACHE=2*1024**3
RUN_PREFIXES=('GROUP_VALIDITY_AND_FIVE_FOLD_EXTENSION_','LINEAGE_MONITOR_BATCH_A_',
 'LINEAGE_PACKET_BASELINE_','FRESH_RAW_CAPTURE48_','CAPTURE48_MERGE_WITNESS_AUDIT_',
 'LINEAGE_TRANSFORM_BATCH3_','LINEAGE_BATCH4_PACE_','LINEAGE_TIMING_PACE_',
 'CONTROLLED_FIT_CAL_SPLIT_ABLATION_')
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def file_sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()

def semantic_receipt(x):
    ignored={'archive','archive_verified','archive_error','evidence_checkpoint','files','package','packagebytes',
             'packagesha256','archive_sha256','archive_bytes','output_directory','checkpoint_error'}
    return {k:v for k,v in x.items() if k not in ignored}

class Run:
    def __init__(self,registry,name):self.registry=registry;self.name=name
    def has(self,name):return name in self.registry.runs.get(self.name,{})
    def file(self,name,optional=False):
        if not self.has(name):
            if optional:return None
            self.registry.missing.append({'request':self.name+'/'+name,'reason':'run member missing'})
            raise Stop('Required run member missing: '+self.name+'/'+name)
        assets=self.registry.runs[self.name][name]
        asset=self.registry.choose(assets,self.name+'/'+name,receipt=name=='receipt.json')
        destination=self.registry.cache/'runs'/self.name/name
        return self.registry.materialize(asset,destination,self.name+'/'+name)
    def __truediv__(self,name):
        p=self.file(str(name),optional=True)
        return p if p is not None else self.registry.cache/'runs'/self.name/str(name)
    def __str__(self):return str(self.registry.cache/'runs'/self.name)

class Registry:
    def __init__(self,primary,aux,cache):
        self.primary=Path(primary);self.aux=list(aux);self.cache=Path(cache);self.cache.mkdir(parents=True,exist_ok=True)
        self.assets=[];self.runs=defaultdict(lambda:defaultdict(list));self.pending=[];self.errors=[];self.used=[];self.missing=[]
        self._seen=set();self._hash={};self._hint_seen=set();self.hints=defaultdict(list);self.aux_scanned=False;self.container_bytes=0
        if not self.primary.is_dir():raise Stop('batch5 mount missing: '+str(self.primary))
        self.scan_tree(self.primary,True)
    def add(self,a):
        identity=(a['path'],a.get('member',''))
        if identity in self._seen:return
        self._seen.add(identity);a=dict(a);a['id']=len(self.assets);self.assets.append(a)
        parts=PurePosixPath(a['logical'].replace('\\','/')).parts
        for i,part in enumerate(parts):
            if part.startswith(RUN_PREFIXES):
                rel='/'.join(parts[i+1:])
                if rel and '..' not in PurePosixPath(rel).parts:self.runs[part][rel].append(a)
        if a['logical'].lower().endswith('.zip') and a['depth']<3:self.pending.append(a)
    def scan_tree(self,root,primary):
        root=Path(root)
        if not root.is_dir():return
        for current,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if d not in ['.git','__pycache__','scratch','temporary_replay'] and (Path(current)/d).resolve()!=self.cache.parent.resolve()]
            for name in files:
                p=Path(current)/name
                if p.is_symlink():continue
                suffix=p.suffix.lower()
                if suffix not in ['.zip','.json','.csv','.gz','.joblib','.npz']:continue
                try:size=p.stat().st_size
                except OSError:continue
                if suffix=='.zip':self.scan_zip(p,primary,0,str(p))
                elif size<=MAX_FILE:self.add({'path':str(p),'member':'','logical':str(p),'origin':str(p),'bytes':size,'primary':primary,'depth':0})
    def scan_zip(self,p,primary,depth,origin):
        try:
            with zipfile.ZipFile(p) as z:
                infos=z.infolist();duplicates={n for n,c in Counter(m.filename for m in infos if not m.is_dir()).items() if c>1}
                for m in infos:
                    if m.is_dir():continue
                    if m.filename in duplicates:
                        self.errors.append({'origin':origin,'member':m.filename,'error':'duplicate member name; not selected'});continue
                    suffix=PurePosixPath(m.filename).suffix.lower()
                    if suffix not in ['.zip','.json','.csv','.gz','.joblib','.npz']:continue
                    bound=MAX_NESTED if suffix=='.zip' else MAX_FILE
                    if m.file_size>bound:continue
                    self.add({'path':str(p),'member':m.filename,'logical':m.filename,'origin':origin+'::'+m.filename,
                              'bytes':m.file_size,'primary':primary,'depth':depth,'CRC':m.CRC})
        except (OSError,zipfile.BadZipFile) as e:self.errors.append({'origin':origin,'error':repr(e)})
    @contextmanager
    def opened(self,a):
        if a.get('member'):
            with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f:yield f
        else:
            with open(a['path'],'rb') as f:yield f
    def read(self,a):
        if a['bytes']>MAX_FILE:raise Stop('Input exceeds bounded metadata read: '+a['origin'])
        with self.opened(a) as f:b=f.read(MAX_FILE+1)
        if len(b)>MAX_FILE:raise Stop('Input exceeds read limit')
        digest=hashlib.sha256(b).hexdigest();self._hash[a['id']]=digest
        return b
    def digest(self,a):
        if a['id'] not in self._hash:self.read(a)
        return self._hash[a['id']]
    def expand(self):
        while self.pending:
            a=self.pending.pop(0)
            if a['bytes']>MAX_NESTED:continue
            if self.container_bytes+a['bytes']>MAX_CONTAINER_CACHE:
                self.errors.append({'origin':a['origin'],'error':'nested-container cache budget; not expanded'});continue
            if shutil.disk_usage(self.cache).free<a['bytes']+1024**3:
                self.errors.append({'origin':a['origin'],'error':'insufficient nested-container reserve'});continue
            folder=self.cache/'containers';folder.mkdir(exist_ok=True)
            temp=folder/('pending_'+str(a['id'])+'.zip');h=hashlib.sha256()
            try:
                with self.opened(a) as src,open(temp,'wb') as dst:
                    for b in iter(lambda:src.read(4*1024**2),b''):h.update(b);dst.write(b)
                final=folder/(h.hexdigest()+'.zip')
                if final.exists():temp.unlink();continue
                temp.rename(final);self.container_bytes+=a['bytes']
                self.scan_zip(final,a['primary'],a['depth']+1,a['origin'])
                return True
            except Exception as e:self.errors.append({'origin':a['origin'],'error':repr(e)})
        return False
    def scan_aux(self):
        if self.aux_scanned:return False
        self.aux_scanned=True
        for root in self.aux:self.scan_tree(root,False)
        return True
    def advance(self):return self.expand() or self.scan_aux()
    def choose(self,candidates,label,expected=None,receipt=False):
        candidates=sorted(candidates,key=lambda a:(not a['primary'],bool(a.get('member')),len(a['origin']),a['origin']))
        variants=defaultdict(list)
        for a in candidates:
            try:
                digest=self.digest(a)
                if expected:
                    if digest==expected:return a
                    continue
                if receipt:
                    obj=json.loads(self.read(a));signature=json.dumps(semantic_receipt(obj),sort_keys=True,default=str)
                else:signature=digest
                variants[signature].append(a)
            except Exception as e:self.errors.append({'request':label,'origin':a['origin'],'error':repr(e)})
        if expected:raise Stop('No copy matches expected SHA-256: '+label)
        if len(variants)!=1:
            self.missing.append({'request':label,'reason':f'{len(variants)} distinct readable contents'})
            raise Stop('Missing or content-conflicting input: '+label)
        return next(iter(variants.values()))[0]
    def materialize(self,a,destination,label,expected=None):
        rel=Path(destination).resolve().relative_to(self.cache.parent.resolve())
        if '..' in rel.parts:raise Stop('Unsafe cache path')
        b=self.read(a);digest=hashlib.sha256(b).hexdigest()
        if expected and digest!=expected:raise Stop('Hash mismatch: '+label)
        destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.exists():
            if file_sha(destination)!=digest:raise Stop('Conflicting materialization: '+label)
        else:
            part=destination.with_name(destination.name+'.part');part.write_bytes(b);part.replace(destination)
        row={'request':label,'origin':a['origin'],'sha256':digest,'bytes':len(b),'from_batch5':a['primary'],'restored_path':str(destination)}
        if not any(x['request']==label and x['sha256']==digest for x in self.used):self.used.append(row)
        return destination
    def find_complete_run(self,pattern,files):
        while True:
            names=sorted((name for name,m in self.runs.items() if fnmatch.fnmatchcase(name,pattern) and all(f in m for f in files)),reverse=True)
            if names:return Run(self,names[0])
            if not self.advance():
                self.missing.append({'request':pattern,'reason':'complete required run not present','required':files})
                raise Stop('No complete run: '+pattern+'; missing prerequisite files are listed in input_audit_missing.json')
    def successful_run(self,pattern,status):
        while True:
            found=[]
            for name,files in self.runs.items():
                if not fnmatch.fnmatchcase(name,pattern) or 'receipt.json' not in files:continue
                copies=[]
                for a in files['receipt.json']:
                    try:
                        r=json.loads(self.read(a))
                        if r.get('status')==status:copies.append(a)
                    except Exception:continue
                if copies:
                    a=self.choose(copies,name+'/receipt.json',receipt=True);found.append((name,a))
            if found:
                name,a=max(found,key=lambda x:x[0]);run=Run(self,name)
                p=self.materialize(a,self.cache/'runs'/name/'receipt.json',name+'/receipt.json')
                return run,json.loads(p.read_text())
            if not self.advance():
                self.missing.append({'request':pattern,'reason':'successful stage receipt missing','status':status})
                raise Stop('Required stage missing: '+status)
    def run_named(self,old_path):
        name=PurePosixPath(str(old_path).replace('\\','/')).name
        while True:
            if name in self.runs:return Run(self,name)
            if not self.advance():raise Stop('Referenced run directory missing: '+name)
    def hash_hints(self):
        for a in list(self.assets):
            if a['id'] in self._hint_seen:continue
            if PurePosixPath(a['logical']).name not in ['ARCHIVE_FILE_MANIFEST.json','CHECKPOINT_MANIFEST.json']:continue
            self._hint_seen.add(a['id'])
            try:
                body=json.loads(self.read(a));rows=body if isinstance(body,list) else body.get('files',[])
                members={x['member']:x for x in self.assets if x.get('member') and x['path']==a['path']}
                for row in rows:
                    if row.get('sha256') and row.get('member') in members:self.hints[row['sha256']].append(members[row['member']])
            except Exception:pass
    def asset_file(self,old,expected=None,label='manifest asset'):
        expected=expected or old.get('sha256');logical=old.get('member') or old['path'];basename=PurePosixPath(logical).name
        while True:
            self.hash_hints()
            candidates=[a for a in self.assets if PurePosixPath(a['logical']).name==basename and a['bytes']<=MAX_FILE]
            if expected:candidates=list(self.hints.get(expected,[]))+candidates
            # Prefer the longest matching suffix, then primary-mount copies.
            parts=PurePosixPath(logical).parts
            def suffix(a):
                other=PurePosixPath(a['logical']).parts;n=0
                for x,y in zip(reversed(parts),reversed(other)):
                    if x!=y:break
                    n+=1
                return n
            candidates=sorted({a['id']:a for a in candidates}.values(),key=lambda a:(not a['primary'],-suffix(a),len(a['origin'])))
            if candidates:
                if expected:
                    matches=[]
                    for a in candidates:
                        try:
                            if self.digest(a)==expected:matches.append(a)
                        except Exception:pass
                    if matches:
                        a=self.choose(matches,label,expected=expected)
                        return self.materialize(a,self.cache/'external'/expected/basename,label,expected)
                else:
                    best=max(suffix(a) for a in candidates)
                    if best>=2:
                        a=self.choose([a for a in candidates if suffix(a)==best],label)
                        return self.materialize(a,self.cache/'external'/self.digest(a)/basename,label)
            if not self.advance():break
        # A manifest may refer to a still-mounted auxiliary file not indexed by stage name.
        p=Path(old['path'])
        if p.is_file():
            try:
                if old.get('member'):
                    with zipfile.ZipFile(p) as z:sz=z.getinfo(old['member']).file_size
                else:sz=p.stat().st_size
                a={'path':str(p),'member':old.get('member',''),'logical':logical,'origin':str(p)+('::'+old['member'] if old.get('member') else ''),'bytes':sz,'primary':str(p).startswith(str(self.primary)+'/'),'depth':0}
                self.add(a);a=a
                candidates=[x for x in self.assets if x['path']==str(p) and x.get('member','')==old.get('member','')]
                a=self.choose(candidates,label,expected=expected)
                return self.materialize(a,self.cache/'external'/self.digest(a)/basename,label,expected)
            except Exception as e:self.errors.append({'request':label,'error':repr(e)})
        self.missing.append({'request':label,'old_asset':old,'expected_sha256':expected,'reason':'not found in indexed archives or available mounts'})
        raise Stop('Required manifest asset missing: '+label)
    def dump(self,out):
        pd.DataFrame([{k:a.get(k) for k in ['origin','logical','bytes','primary','depth']} for a in self.assets]).to_csv(out/'archive_inventory.csv',index=False)
        pd.DataFrame(self.used).to_csv(out/'resolved_input_audit.csv',index=False)
        js(out/'input_audit_missing.json',self.missing);js(out/'input_audit_errors.json',self.errors)

def norm(df,labelled=True):
    df=df.copy();required=F+(['ks','y'] if labelled else [])
    if not set(required).issubset(df.columns):raise Stop('Required columns missing: '+str(set(required)-set(df.columns)))
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid predictor '+c)
    df['proto']=df.proto.astype(str).str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Unexpected protocol')
    if labelled:
        y=pd.to_numeric(df.y,errors='raise')
        if not y.isin([0,1]).all():raise Stop('Invalid labels')
        df['y']=y.astype(int);df['ks']=df.ks.astype(str)
    return df

def table(path):
    with open(path,'rb') as f:compressed=f.read(2)==b'\x1f\x8b'
    return pd.read_csv(path,compression='gzip' if compressed else None,dtype=str,keep_default_na=False)
def encode(df):return np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),*[df.proto.eq(p).to_numpy(float) for p in ['tcp','udp','icmp']]])
def boolean(s):
    x=s.astype(str).str.lower()
    if not x.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return x.isin(['true','1']).to_numpy(bool)
def logit(p):
    p=np.clip(p,1e-6,1-1e-6);return (np.log(p)-np.log1p(-p)).reshape(-1,1)
def score_metrics(y,p):
    y=np.asarray(y,int);p=np.asarray(p,float)
    if set(y)!={0,1} or not np.isfinite(p).all():raise Stop('Metric/calibration set lacks both classes or finite probabilities')
    d=p>=.5;bins=np.minimum((p*10).astype(int),9);ece=0.
    for j in range(10):
        m=bins==j
        if m.any():ece+=float(m.mean())*abs(float(p[m].mean()-y[m].mean()))
    return {'accuracy':float(accuracy_score(y,d)),'balanced_accuracy':float(balanced_accuracy_score(y,d)),
        'AUROC':float(roc_auc_score(y,p)),'malicious_recall':float(d[y==1].mean()),'benign_FPR':float(d[y==0].mean()),
        'Brier':float(np.mean((p-y)**2)),'ECE_10_bins':ece}
def atc(conf,correct):
    conf=np.asarray(conf,float);n=int(np.asarray(correct,bool).sum())
    if n==0:return float(np.nextafter(conf.max(),np.inf)),0.
    t=float(np.sort(conf)[::-1][n-1]);above=int((conf>t).sum());ties=int((conf==t).sum());alpha=(n-above)/ties
    if not 0<=alpha<=1:raise Stop('ATC tie calculation failed')
    return t,float(alpha)

def targets_load(reg):
    a,_=reg.successful_run('LINEAGE_MONITOR_BATCH_A_*','P4_AC_AGREEMENT_BATCH_COMPLETE')
    base,_=reg.successful_run('LINEAGE_PACKET_BASELINE_*','CLEAN_BASELINE_VALIDATED')
    fresh,_=reg.successful_run('FRESH_RAW_CAPTURE48_*','FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE')
    merge,mr=reg.successful_run('CAPTURE48_MERGE_WITNESS_AUDIT_*','CAPTURE48_MERGE_AND_ALARM_WITNESS_AUDIT_COMPLETE')
    if PurePosixPath(str(mr['source_run'])).name!=fresh.name:raise Stop('Capture48 witness/cohort run identities differ')
    manifest=json.loads((a/'input_manifest.json').read_text())
    c49=norm(table(reg.asset_file(manifest['clean'],label='capture49 clean cohort')))
    if len(c49)!=1024 or c49.ks.duplicated().any():raise Stop('Invalid capture49 cohort')
    mk49=list(c49.loc[c49.y.eq(1),'ks']);mp0=pd.read_csv(base/'clean_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'zeek_uid':str})
    if mp0.packet_index.duplicated().any():raise Stop('Duplicate clean capture49 occurrence')
    own0=mp0.groupby('original_ks').zeek_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
    if set(own0)!=set(mk49) or any(len(v)!=1 for v in own0.values()):raise Stop('Capture49 clean membership differs')
    positive=c49.set_index('ks').loc[mk49,F].copy();positive['uid']=[own0[k][0] for k in mk49];positive=positive.reset_index(drop=True)
    targets={'CAPTURE49_LEGACY_COHORT':{'clean':c49,'states':{0:{'selected':c49,'records':positive,'owners':own0,'pure':dict.fromkeys(positive.uid,True),'complete':dict.fromkeys(mk49,True)}}}}
    for cond in manifest['conditions']:
        delay=int(cond['delay_seconds'])
        if delay not in [1,10]:continue
        selected=norm(table(reg.asset_file(cond['candidate_asset'],cond['candidate_sha256'],f'capture49 {delay}s selected features')))
        if selected.ks.duplicated().any() or set(selected.ks)!=set(c49.ks):raise Stop('Capture49 selected membership differs')
        selected=selected.set_index('ks').loc[c49.ks].reset_index();p=reg.run_named(cond['validated_result_directory'])
        rr=json.loads((p/'receipt.json').read_text())
        if rr.get('status')!='TRANSFORMED_PACKET_MEMBERSHIP_VALIDATED' or rr.get('historical_transformed_pcap_sha256')!=cond['historical_transformed_pcap_sha256']:raise Stop('Capture49 trace binding differs')
        mm=pd.read_csv(p/'test2_transformed_membership.csv',dtype={'ks':str})
        if len(mm)!=512 or not boolean(mm.transformed_membership_validated).all():raise Stop('Capture49 membership not fully validated')
        mp=pd.read_csv(p/'transformed_packet_uid_mapping.csv.gz',dtype={'original_ks':str,'transformed_uid':str})
        if mp.packet_index.duplicated().any():raise Stop('Duplicate capture49 transformed occurrence')
        owners=mp.groupby('original_ks').transformed_uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        cf=norm(table(p/'transformed_selected_connection_records.csv.gz'),False)
        if set(owners)!=set(mk49) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.transformed_uid):raise Stop('Capture49 UID coverage differs')
        targets['CAPTURE49_LEGACY_COHORT']['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':dict.fromkeys(cf.uid,True),'complete':dict.fromkeys(mk49,True)}
    c48=norm(table(fresh/'fresh_clean_target_sample.csv.gz'));mk48=list(c48.loc[c48.y.eq(1),'ks'])
    target48={'clean':c48,'states':{}};canonical=None
    baseline_members=pd.read_csv(fresh/'membership_0s.csv',dtype={'ks':str})
    if len(baseline_members)!=512 or not boolean(baseline_members.membership_validated).all():raise Stop('Fresh capture48 baseline not fully validated')
    for delay in [0,1,10]:
        selected=norm(table(fresh/f'selected_features_{delay}s.csv.gz'))
        if selected.ks.duplicated().any() or set(selected.ks)!=set(c48.ks):raise Stop('Capture48 selected membership differs')
        selected=selected.set_index('ks').loc[c48.ks].reset_index()
        cf=norm(table(fresh/f'descendant_features_{delay}s.csv.gz'),False)
        mp=pd.read_csv(fresh/f'packet_uid_mapping_{delay}s.csv.gz',dtype={'original_ks':str,'uid':str})
        current=mp[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True)
        if mp.packet_index.duplicated().any():raise Stop('Repeated capture48 packet occurrence')
        if delay==0:canonical=current
        elif not current.equals(canonical):raise Stop('Capture48 packet occurrence/owner identity differs')
        purity=pd.read_csv(merge/f'UID_contributions_{delay}s.csv',dtype={'uid':str})
        if purity.uid.duplicated().any():raise Stop('Duplicate capture48 purity UID')
        pure=dict(zip(purity.uid,boolean(purity.pure_selected_original_witness_record)))
        owners=mp.groupby('original_ks').uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
        if set(owners)!=set(mk48) or cf.uid.duplicated().any() or set(cf.uid)!=set(mp.uid) or set(pure)!=set(cf.uid):raise Stop('Capture48 UID coverage differs')
        target48['states'][delay]={'selected':selected,'records':cf,'owners':owners,'pure':pure,'complete':dict.fromkeys(mk48,True)}
    targets['CAPTURE48_FRESH_COHORT']=target48
    for name,t in targets.items():
        if len(t['clean'])!=1024 or t['clean'].ks.duplicated().any() or int(t['clean'].y.eq(1).sum())!=512 or set(t['states'])!={0,1,10}:raise Stop('Target contract failed: '+name)
        for state in t['states'].values():
            if not np.array_equal(state['selected'].y.to_numpy(),t['clean'].y.to_numpy()):raise Stop('Target labels differ')
    return targets

def main():
    W=Path('/kaggle/working');OUT=W/('CONTROLLED_FIT_CAL_SPLIT_RESTART_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(parents=True,exist_ok=False)
    R={'status':'STARTED','new_primary_model_fits':0,'new_probability_calibrator_fits':0,'row_control_pairs_reused':0,
       'new_PCAP_replays':0,'target_cohorts_changed':False,'outer_validation_changed':False,
       'historical_outputs_overwritten':False,'five_initialization_seeds_claimed':False,'independent_confirmation':False,
       'six_remaining_packet_captures_completed':False,'manuscript_submission_ready':False,'archive_integrity_scope':'CRC and SHA-256 of required read inputs; not all unused archive members or raw datasets','output_directory':str(OUT)}
    reg=None;val_rows=[];target_rows=[];monitor_rows=[];reproduction=[];new_models={};new_calibrators={}
    try:
        if shutil.disk_usage(W).free<1024**3:raise Stop('At least 1 GiB free is required')
        reg=Registry(PRIMARY,[W]+AUX,OUT/'recovered_inputs')
        needed=['five_fold_models_and_calibrators.joblib','source_panel_with_groups.csv.gz','five_fold_source_membership.csv.gz',
                'source_outer_validation.csv','five_fold_common_model_target_results.csv','pre_outcome_protocol.json']
        print('[1/3] Auditing batch5 ZIP contents and resolving only the ablation dependency closure.',flush=True)
        base=reg.find_complete_run('GROUP_VALIDITY_AND_FIVE_FOLD_EXTENSION_*',needed)
        paths={n:base.file(n) for n in needed}
        source=norm(table(paths['source_panel_with_groups.csv.gz']))
        if not {'source_scenario','source_group'}.issubset(source.columns) or source.duplicated(['source_scenario','ks']).any():raise Stop('Source grouping/original-key schema differs')
        membership=pd.read_csv(paths['five_fold_source_membership.csv.gz'],dtype={'ks':str,'source_group':str})
        original_validation=pd.read_csv(paths['source_outer_validation.csv']);original_targets=pd.read_csv(paths['five_fold_common_model_target_results.csv'])
        targets=targets_load(reg)
        stored=joblib.load(paths['five_fold_models_and_calibrators.joblib'])
        grouped_models=stored['models'];grouped_calibrators=stored['calibrators'];expected={(fold,family) for fold in range(1,6) for family in ['HGB','LR']}
        if set(grouped_models)!=expected or set(grouped_calibrators)!=expected or int(stored['model_seed'])!=MODEL_SEED:raise Stop('Grouped model contract differs')
        input_hashes={n:file_sha(p) for n,p in paths.items()};js(OUT/'grouped_input_hashes.json',input_hashes)
        R['required_input_closure_verified']=True
        R['all_used_inputs_found_in_batch5']=all(x['from_batch5'] for x in reg.used)
        R['auxiliary_input_dependencies']=[x for x in reg.used if not x['from_batch5']]
        R['whole_research_archive_completeness_assessed']=False
        reg.dump(OUT)
        print('\nINPUT AUDIT\n'+pd.DataFrame(reg.used)[['request','bytes','from_batch5']].to_string(index=False),flush=True)
        print('Required input closure verified. All required inputs in batch5:',R['all_used_inputs_found_in_batch5'],flush=True)
        source_ids=pd.MultiIndex.from_frame(source[['source_scenario','ks']]);groups=source.source_group.astype(str).to_numpy()
        strata=(source.source_scenario+'|'+source.y.astype(str)).to_numpy();split_roles={};audit_rows=[];allocation_rows=[]
        for fold in range(1,6):
            m=membership[membership.fold.eq(fold)]
            if m.duplicated(['source_scenario','ks']).any() or len(m)!=len(source):raise Stop('Grouped membership population invalid')
            mi=pd.MultiIndex.from_frame(m[['source_scenario','ks']]);pos=source_ids.get_indexer(mi)
            if (pos<0).any() or len(set(pos))!=len(source):raise Stop('Grouped membership identities differ')
            if not np.array_equal(m.source_group.astype(str).to_numpy(),groups[pos]):raise Stop('Recorded source group identifiers differ')
            roles={role:pos[m.role.eq(role).to_numpy()] for role in ['model_fit','calibration','validation']}
            if sum(map(len,roles.values()))!=len(source):raise Stop('Unknown grouped role')
            gsets={role:set(groups[v]) for role,v in roles.items()}
            if gsets['model_fit']&gsets['calibration'] or gsets['model_fit']&gsets['validation'] or gsets['calibration']&gsets['validation']:raise Stop('Original grouped roles overlap')
            development=np.sort(np.concatenate([roles['model_fit'],roles['calibration']]))
            rng=np.random.default_rng(95000+fold);row_fit=[];row_cal=[]
            for stratum in sorted(set(strata[development])):
                pool=rng.permutation(development[strata[development]==stratum]);nfit=int((strata[roles['model_fit']]==stratum).sum())
                row_fit.extend(pool[:nfit]);row_cal.extend(pool[nfit:])
            row_roles={'model_fit':np.sort(np.asarray(row_fit,int)),'calibration':np.sort(np.asarray(row_cal,int)),'validation':roles['validation'].copy()}
            if set(row_roles['model_fit'])&set(row_roles['calibration']) or set(np.concatenate([row_roles['model_fit'],row_roles['calibration']]))!=set(development):raise Stop('Row allocation failed')
            for role in roles:
                if not pd.Series(strata[roles[role]]).value_counts().sort_index().equals(pd.Series(strata[row_roles[role]]).value_counts().sort_index()):raise Stop('Class/capture budgets were not matched')
            if not np.array_equal(row_roles['validation'],roles['validation']):raise Stop('Outer validation changed')
            for policy,rr in [('GROUP_DISJOINT',roles),('ROW_FIT_CAL_CONTROL',row_roles)]:
                gs={role:set(groups[idx]) for role,idx in rr.items()}
                if gs['validation']&(gs['model_fit']|gs['calibration']):raise Stop('Outer validation-group leakage')
                audit_rows.append({'fold':fold,'split_policy':policy,'fit_rows':len(rr['model_fit']),'calibration_rows':len(rr['calibration']),'validation_rows':len(rr['validation']),
                    'fit_cal_shared_groups':len(gs['model_fit']&gs['calibration']),'validation_shared_groups':len(gs['validation']&(gs['model_fit']|gs['calibration'])),
                    'same_outer_validation':True,'matched_class_capture_counts':True})
                for role,idx in rr.items():allocation_rows.extend({'fold':fold,'split_policy':policy,'role':role,'ks':source.iloc[i].ks,'source_scenario':source.iloc[i].source_scenario,'source_group':groups[i]} for i in idx)
            split_roles[fold]=(roles,row_roles)
        pd.DataFrame(audit_rows).to_csv(OUT/'matched_allocation_audit.csv',index=False)
        pd.DataFrame(allocation_rows).to_csv(OUT/'matched_source_memberships.csv.gz',index=False,compression='gzip')
        protocol={'grouped_extension':base.name,'fixed_outer_validation':True,'matched_fit_calibration_sizes_and_class_capture_counts':True,
            'changed_factor':'fit/calibration grouping policy within fixed outer development pool','model_seed':MODEL_SEED,
            'row_control_allocation_seed':'95000+fold','families':['HGB','LR'],
            'HGB':{'max_iter':150,'learning_rate':.08,'early_stopping':False},'LR':{'C':1.,'solver':'lbfgs','max_iter':5000},
            'calibrator':{'C':1.,'solver':'lbfgs','max_iter':2000,'random_state':94501},'target_cohorts':list(targets),'conditions':[0,1,10],
            'target_labels_used_for_fitting':False,'row_control_recommended_final_protocol':False,
            'interpretation':'Controlled split-policy sensitivity, not proof of a unique causal mechanism or independent target confirmation'}
        js(OUT/'pre_outcome_protocol.json',protocol)
        def evaluate(fold,family,policy,roles,model,calibrator):
            fit=source.iloc[roles['model_fit']];cal=source.iloc[roles['calibration']];validation=source.iloc[roles['validation']]
            if list(model.classes_)!=[0,1] or list(calibrator.classes_)!=[0,1]:raise Stop('Unexpected model/calibrator class order')
            pc=model.predict_proba(encode(cal))[:,1];dc=pc>=.5;cc=np.maximum(pc,1-pc);ca=float((dc==cal.y.to_numpy()).mean());cm=float(cc.mean());threshold,alpha=atc(cc,dc==cal.y.to_numpy())
            pv=model.predict_proba(encode(validation))[:,1];qv=calibrator.predict_proba(logit(pv))[:,1]
            raw_metrics=score_metrics(validation.y,pv);cal_metrics=score_metrics(validation.y,qv)
            vr={'fold':fold,'family':family,'split_policy':policy,'validation_rows':len(validation),**raw_metrics,
                'calibrated_Brier':cal_metrics['Brier'],'calibrated_ECE':cal_metrics['ECE_10_bins'],'calibration_accuracy':ca,'calibration_mean_confidence':cm,
                'ATC_GE_matching_error':float((cc>=threshold).mean()-ca),'ATC_fractional_matching_error':float(((cc>threshold).astype(float)+alpha*(cc==threshold)).mean()-ca)}
            if policy=='GROUP_DISJOINT':
                old=original_validation[original_validation.fold.eq(fold)&original_validation.family.eq(family)]
                if len(old)!=1:raise Stop('Original grouped validation row not unique')
                ok=all(np.isclose(raw_metrics[n],float(old.iloc[0][n]),atol=1e-10,rtol=0) for n in ['accuracy','balanced_accuracy','AUROC','malicious_recall','benign_FPR'])
                reproduction.append({'fold':fold,'family':family,'group_validation_reproduced':bool(ok)})
                if not ok:raise Stop('Grouped validation does not reproduce; no new row model will be fitted before resolving it')
            tr_out=[];mr_out=[]
            for target_name,t in targets.items():
                clean=t['clean'];yy=clean.y.to_numpy();mk=list(clean.loc[yy==1,'ks']);N=len(mk);states=[]
                for delay in [0,1,10]:
                    state=t['states'][delay];frame=state['selected'];cf=state['records'];p=model.predict_proba(encode(frame))[:,1];d=p>=.5
                    confidence=np.maximum(p,1-p);q=calibrator.predict_proba(logit(p))[:,1];alarms=dict(zip(cf.uid,model.predict_proba(encode(cf))[:,1]>=.5))
                    pos=neg=unknown=overlap=0
                    for k in mk:
                        uu=state['owners'][k];has=any(alarms[u] for u in uu);pure=any(alarms[u] and state['pure'].get(u,False) for u in uu);none=state['complete'][k] and not has
                        pos+=int(pure);neg+=int(none);unknown+=int(not pure and not none);overlap+=int(has)
                    accuracy=float((d==yy).mean());values={'AC':float(confidence.mean()),'DoC':float(np.clip(ca+confidence.mean()-cm,0,1)),
                        'ATC_SOURCE_GE':float((confidence>=threshold).mean()),'ATC_FRACTIONAL_TIE_EXPECTATION':float(((confidence>threshold).astype(float)+alpha*(confidence==threshold)).mean()),
                        'CBPE_ACC_POINT':float(np.where(d,q,1-q).mean())}
                    tr={'fold':fold,'family':family,'split_policy':policy,'target':target_name,'delay_seconds':delay,'record_accuracy':accuracy,
                        'selected_record_recall':float(d[yy==1].mean()),'benign_FPR':float(d[yy==0].mean()),'original_units':N,
                        'pure_alarm_witness_units':pos,'no_record_alarm_units':neg,'attribution_unresolved':unknown,
                        'unit_detection_lower':pos/N,'unit_detection_upper':(pos+unknown)/N,'any_overlap_alarm_units':overlap}
                    tr_out.append(tr);states.append((delay,accuracy,pos/N,(pos+unknown)/N,values))
                    if policy=='GROUP_DISJOINT':
                        old=original_targets[original_targets.fold.eq(fold)&original_targets.family.eq(family)&original_targets.target.eq(target_name)&original_targets.delay_seconds.eq(delay)]
                        if len(old)!=1 or not all(np.isclose(float(old.iloc[0][n]),float(tr[n]),atol=1e-12,rtol=0) for n in ['record_accuracy','unit_detection_lower','unit_detection_upper']):raise Stop('Grouped target outcomes do not reproduce; no new row fits accepted')
                baseline=states[0]
                for delay,truth,lower,upper,values in states:
                    for name,value in values.items():
                        drop=baseline[4][name]-value;loss_lower=baseline[2]-upper;loss_upper=baseline[3]-lower
                        mr_out.append({'fold':fold,'family':family,'split_policy':policy,'target':target_name,'delay_seconds':delay,'estimator':name,
                            'record_accuracy':truth,'estimate':value,'absolute_error':abs(value-truth),'overestimation':value-truth,
                            'record_accuracy_drop':baseline[1]-truth,'estimated_record_accuracy_drop':drop,'differential_error':abs(drop-(baseline[1]-truth)),
                            'original_unit_detection_drop_lower':loss_lower,'original_unit_detection_drop_upper':loss_upper,
                            'warning_at_5pp':drop>=THRESHOLD,'definite_damage_present':loss_lower>=THRESHOLD,'missed_definite_damage':bool(loss_lower>=THRESHOLD and drop<THRESHOLD)})
            return vr,tr_out,mr_out
        def save_progress():
            pd.DataFrame(val_rows).to_csv(OUT/'common_validation_results.csv',index=False)
            pd.DataFrame(target_rows).to_csv(OUT/'common_target_results.csv',index=False)
            pd.DataFrame(monitor_rows).to_csv(OUT/'common_monitor_results.csv',index=False)
            pd.DataFrame(reproduction).to_csv(OUT/'grouped_result_reproduction.csv',index=False)
            js(OUT/'receipt.json',R)
        print('[2/3] Verifying ALL ten grouped models on original validation and fixed targets before fitting row controls.',flush=True)
        with threadpool_limits(limits=2):
            for fold,(roles,_) in split_roles.items():
                for family in ['HGB','LR']:
                    vr,tr,mr=evaluate(fold,family,'GROUP_DISJOINT',roles,grouped_models[(fold,family)],grouped_calibrators[(fold,family)])
                    val_rows.append(vr);target_rows.extend(tr);monitor_rows.extend(mr);save_progress()
        R['all_grouped_validation_and_target_results_reproduced']=True
        print('[3/3] Fit or resume only the ten row-control model/calibrator pairs; checkpoint after every pair.',flush=True)
        job_folder=OUT/'model_checkpoints';job_folder.mkdir(exist_ok=True)
        with threadpool_limits(limits=2):
            for fold,(_,roles) in split_roles.items():
                fit=source.iloc[roles['model_fit']];cal=source.iloc[roles['calibration']]
                for family in ['HGB','LR']:
                    binding={'inputs':input_hashes,'protocol':protocol,'fold':fold,'family':family,
                             'fit_indices':roles['model_fit'].tolist(),'cal_indices':roles['calibration'].tolist()}
                    sig=hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                    jobname=f'row_control_fold_{fold}_{family}_{sig[:16]}.joblib';job_path=job_folder/jobname
                    cached=None
                    # Existing partial restart checkpoints can be resumed from working files or batch5 archives.
                    options=[a for a in reg.assets if PurePosixPath(a['logical']).name==jobname]
                    for asset in options:
                        try:
                            payload=joblib.load(reg.materialize(asset,job_path,'resume '+jobname))
                            if payload.get('input_signature')==sig:cached=payload;break
                        except Exception:continue
                    if cached is not None:
                        model=cached['model'];calibrator=cached['calibrator'];R['row_control_pairs_reused']+=1
                    else:
                        model=(HistGradientBoostingClassifier(max_iter=150,learning_rate=.08,early_stopping=False,random_state=MODEL_SEED) if family=='HGB' else Pipeline([('scale',StandardScaler()),('lr',LogisticRegression(C=1.,solver='lbfgs',max_iter=5000,random_state=MODEL_SEED))]))
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always',ConvergenceWarning);model.fit(encode(fit),fit.y)
                            if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed row-control primary model did not converge')
                        R['new_primary_model_fits']+=1;calibrator=LogisticRegression(C=1.,solver='lbfgs',max_iter=2000,random_state=94501)
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always',ConvergenceWarning);calibrator.fit(logit(model.predict_proba(encode(cal))[:,1]),cal.y)
                            if any(issubclass(w.category,ConvergenceWarning) for w in caught):raise Stop('Fixed row-control calibrator did not converge')
                        R['new_probability_calibrator_fits']+=1
                        joblib.dump({'model':model,'calibrator':calibrator,'input_signature':sig},job_path,compress=3)
                    new_models[(fold,family)]=model;new_calibrators[(fold,family)]=calibrator
                    vr,tr,mr=evaluate(fold,family,'ROW_FIT_CAL_CONTROL',roles,model,calibrator)
                    val_rows.append(vr);target_rows.extend(tr);monitor_rows.extend(mr);save_progress()
                    print('Completed:',fold,family,'(restored)' if cached is not None else '(new source-only fit)',flush=True)
        joblib.dump({'models':new_models,'calibrators':new_calibrators,'model_seed':MODEL_SEED},OUT/'row_control_models_and_calibrators.joblib',compress=3)
        val=pd.DataFrame(val_rows);tv=pd.DataFrame(target_rows)
        if len(val)!=20 or len(tv)!=120 or len(monitor_rows)!=600:raise Stop('Final controlled-ablation row counts differ')
        idx=['fold','family','target','delay_seconds'];grouped=tv[tv.split_policy.eq('GROUP_DISJOINT')].set_index(idx)
        row=tv[tv.split_policy.eq('ROW_FIT_CAL_CONTROL')].set_index(idx).reindex(grouped.index)
        changes=grouped[['record_accuracy','unit_detection_lower','unit_detection_upper','benign_FPR']].copy()
        for name in list(changes):changes[name+'_ROW_minus_GROUP']=row[name]-grouped[name]
        changes=changes.reset_index();changes.to_csv(OUT/'paired_split_policy_changes.csv',index=False)
        for family,title in [('HGB','EXPERIMENT 1 — HGB MATCHED SPLIT POLICIES'),('LR','EXPERIMENT 2 — LR MATCHED SPLIT POLICIES')]:
            print('\n'+title+'\n'+tv[tv.family.eq(family)&tv.delay_seconds.eq(10)].to_string(index=False),flush=True)
        print('\nEXPERIMENT 3 — FIXED OUTER VALIDATION AND CALIBRATION AUDIT\n'+val.to_string(index=False),flush=True)
        print('\nALLOCATION CONTROL CHECKS\n'+pd.DataFrame(audit_rows).to_string(index=False),flush=True)
        print('\nPAIRED TARGET CHANGES, 10s\n'+changes[changes.delay_seconds.eq(10)].to_string(index=False),flush=True)
        gaps=[{'package':'P0','status':'CONTROLLED_SPLIT_COMPUTED','remaining':'Legacy AUROC and final method/bibliography review'},
              {'package':'P1','status':'CAPTURE49_ACCOUNTING_AND_REPORTED_HORIZONS_PRESENT','remaining':'Final policy wording audit'},
              {'package':'P2','status':'FRESH_INJECTION_AMENDMENT_REPORTED_SEPARATELY','remaining':'No historical numerical-replication claim'},
              {'package':'P3','status':'SOURCE_SPLIT_AND_COMMON_MODEL_SENSITIVITY_COMPUTED','remaining':'Packet-aware captures 7,9,33,36,39,43 remain'},
              {'package':'P4','status':'FIVE_POINT_ESTIMATORS_ON_TWO_FIXED_COHORTS','remaining':'Broader captures and full-bank/gate/MD3 information-setting alignment'},
              {'package':'P5','status':'PRIVATE_INPUT_AND_RESULT_CHECKPOINT','remaining':'End-to-end clean replay, resource/novelty/manuscript audit'}]
        pd.DataFrame(gaps).to_csv(OUT/'P0_P5_remaining_work.csv',index=False)
        R.update({'status':'CONTROLLED_FIT_CAL_SPLIT_ABLATION_COMPLETE','source_grouped_models_reused':10,
            'outer_validation_identical_between_policies':True,'fit_calibration_sizes_and_class_capture_composition_matched':True,
            'row_control_retains_group_disjoint_outer_validation':True,'row_control_is_recommended_final_split':False,
            'source_fold_count':5,'remaining_packet_target_captures':[7,9,33,36,39,43],
            'does_not_prove_leakage_caused_original_failure':True,
            'interpretation':'All folds/policies retained. Five source folds are not five initializations or independent target captures. A split-policy contrast does not identify a unique causal mechanism.'})
    except Exception as error:
        R['status']='BLOCKED' if isinstance(error,Stop) else 'FAILED';R['reason']=str(error)
        (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(error),flush=True)
    finally:
        if reg is not None:
            reg.dump(OUT);R['resolved_input_files']=len(reg.used)
            R['all_used_inputs_found_in_batch5']=bool(reg.used) and all(x['from_batch5'] for x in reg.used)
        js(OUT/'receipt.json',R)
        # Preserve only restored dependency files and model checkpoints, not nested-container cache or PCAPs.
        package=OUT/'PRIVATE_controlled_split_inputs_and_results.zip';entries=[]
        try:
            with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
                for current,dirs,files in os.walk(OUT,followlinks=False):
                    dirs[:]=[d for d in dirs if d!='containers']
                    for name in files:
                        p=Path(current)/name
                        if p==package or p.suffix.lower()=='.zip' or p.is_symlink():continue
                        if p.stat().st_size>MAX_FILE:continue
                        rel=str(p.relative_to(OUT));h=file_sha(p);z.write(p,arcname=rel);entries.append({'member':rel,'sha256':h,'bytes':p.stat().st_size})
                z.writestr('ARCHIVE_FILE_MANIFEST.json',json.dumps(entries,indent=2))
            with zipfile.ZipFile(package) as z:
                for entry in entries:
                    h=hashlib.sha256()
                    with z.open(entry['member']) as f:
                        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
                    if h.hexdigest()!=entry['sha256']:raise Stop('Output archive hash mismatch')
            R['result_archive']={'path':str(package),'bytes':package.stat().st_size,'sha256':file_sha(package),'members_verified':len(entries),'model_files_included':any(x['member'].endswith('.joblib') for x in entries),'private_only':True}
        except Exception as error:R['archive_error']=str(error)
        js(OUT/'receipt.json',R)
        print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)

if __name__=='__main__':main()
