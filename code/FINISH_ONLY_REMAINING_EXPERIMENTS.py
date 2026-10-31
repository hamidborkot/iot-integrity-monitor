# Finish only the remaining executable work. No model fitting or PCAP replay.
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import gzip, hashlib, io, json, os, shutil, traceback, zipfile
import numpy as np
import pandas as pd

TARGET_RUN = 'EXPERIMENTAL_COMPLETION_20261028T082656379467Z'
EXPECTED_PREVIOUS_ZIP_SHA256 = '3ef69c8f15ee0f572bad5159a1eb3c951f8098e1fe0d17ad24f6a39092fef19e'
WINDOW_GROUP = 'LINEAGE_WINDOW_ORDER_RECONCILIATION_20261015T204807283205Z'
WORK = Path('/kaggle/working')
OUT = WORK / ('FINISH_SAVED_EXPERIMENTS_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(parents=True, exist_ok=False)
ASSETS=[]; USED=[]; LEDGER=[]

class Blocked(Exception): pass

def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''): h.update(b)
    return h.hexdigest()

def js(p,x):
    Path(p).write_text(json.dumps(x,indent=2,default=str,allow_nan=False),encoding='utf-8')

def origin(a): return str(a['path']) + ('::'+a['member'] if a.get('member') else '')
def read(a):
    if a.get('member'):
        with zipfile.ZipFile(a['path']) as z,z.open(a['member']) as f: b=f.read(128*1024**2+1)
    else:
        with open(a['path'],'rb') as f: b=f.read(128*1024**2+1)
    if len(b)>128*1024**2: raise Blocked('Bounded input limit: '+origin(a))
    return b

def table(a):
    b=read(a)
    if b[:2]==b'\x1f\x8b': b=gzip.decompress(b)
    return pd.read_csv(io.BytesIO(b),keep_default_na=False)

def checkpoint(stage):
    js(OUT/'ledger.json',LEDGER);js(OUT/'used_inputs.json',USED)
    files=[]
    for p in sorted(OUT.rglob('*')):
        if p.is_file() and p.name not in {'FINAL_PACKAGE.zip','FINAL_PACKAGE.zip.tmp','PACKAGE.sha256','manifest.json'}:
            files.append({'file':p.relative_to(OUT).as_posix(),'bytes':p.stat().st_size,'sha256':sha_file(p)})
    js(OUT/'manifest.json',{'stage':stage,'files':files})
    tmp=OUT/'FINAL_PACKAGE.zip.tmp'
    with zipfile.ZipFile(tmp,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as z:
        for x in files:z.write(OUT/x['file'],arcname=x['file'])
        z.write(OUT/'manifest.json',arcname='manifest.json')
    with zipfile.ZipFile(tmp) as z:
        bad=z.testzip()
        if bad:raise RuntimeError('ZIP failed integrity check: '+bad)
    os.replace(tmp,OUT/'FINAL_PACKAGE.zip')
    digest=sha_file(OUT/'FINAL_PACKAGE.zip');(OUT/'PACKAGE.sha256').write_text(digest+'\n')
    print('\nCHECKPOINT:',stage,'\nZIP:',OUT/'FINAL_PACKAGE.zip','\nSHA256:',digest,flush=True)
    try:
        from IPython.display import FileLink,display
        display(FileLink(str(OUT/'FINAL_PACKAGE.zip')))
    except Exception:pass

def stage(name,fn):
    d=OUT/name;d.mkdir(exist_ok=True)
    try:
        result=fn(d) or {}
        result={'task':name,'status':result.pop('status','COMPLETED_FOR_DECLARED_SCOPE'),**result}
    except Exception as e:
        (d/'error.txt').write_text(traceback.format_exc())
        result={'task':name,'status':'BLOCKED' if isinstance(e,Blocked) else 'FAILED','reason':str(e)}
        print(name,result['status'],str(e),flush=True)
    LEDGER.append(result);js(d/'receipt.json',result);checkpoint(name)
    return result

def discover(d):
    needed={
      'MD3_matched_window_outputs.csv','historical_stream_reproduction.csv',
      'reference_reproduction_checks.csv','source_holdout_reproduction.json',
      'initialized_state.json','matched_protocol_before_scoring.json',
      'ALL_COHORT_descendant_summary.csv','ALL_COHORT_unit_outcomes.csv.gz',
      'all_order_monitor_windows.csv','window_membership.csv',
      'clean_reproduction.json','clean_score_reproduction.csv','source_ownership_audit.csv',
      'all_cohort_membership_0s.csv','all_cohort_membership_1s.csv','all_cohort_membership_10s.csv',
      'independent_annotation_TEMPLATE.csv','independent_reference_status.json',
      'SCIENTIFIC_SCOPE.json','receipt.json','used_inputs.json','ledger.json',
    }
    roots=[WORK,Path('/kaggle/input')];archives=[]
    for root in roots:
        if not root.exists():continue
        for base,dirs,files in os.walk(root):
            bp=Path(base)
            dirs[:]=[n for n in dirs if bp/n!=OUT and n not in {'.git','__pycache__','site-packages'}
                     and not n.startswith('.zeek') and 'iot-2023-dataset-full' not in n]
            for name in files:
                p=bp/name
                if p.suffix.lower()=='.zip':archives.append(p)
                elif name in needed and p.stat().st_size<=128*1024**2:
                    ASSETS.append({'path':str(p),'member':None,'leaf':name,'size':p.stat().st_size,'verified_previous_archive':False})
    verified=0
    for p in archives:
        try:
            with zipfile.ZipFile(p) as z:
                infos=[n for n in z.infolist() if not n.is_dir() and Path(n.filename).name in needed and n.file_size<=128*1024**2]
                if not infos:continue
                is_previous=(p.name=='CHECKPOINT.zip' or TARGET_RUN in str(p))
                exact=bool(is_previous and sha_file(p)==EXPECTED_PREVIOUS_ZIP_SHA256)
                if exact:verified+=1
                for n in infos:
                    ASSETS.append({'path':str(p),'member':n.filename,'leaf':Path(n.filename).name,'size':n.file_size,'verified_previous_archive':exact})
        except (OSError,zipfile.BadZipFile):continue
    pd.DataFrame(ASSETS).to_csv(d/'candidate_assets.csv',index=False)
    js(d/'execution_scope.json',{'new_PCAP_replays':0,'model_fits':0,'MD3_reference_CV_repeated':False,
       'original_run':TARGET_RUN,'expected_previous_zip_sha256':EXPECTED_PREVIOUS_ZIP_SHA256,
       'exact_previous_archive_copies_found':verified,'only_missing_join_and_saved_output_audits':True})
    if not ASSETS:raise Blocked('Attach the previous CHECKPOINT.zip/output directory and original batch5 backup.')
    return {'candidate_assets':len(ASSETS),'exact_previous_archive_copies_found':verified}

def select(name,scope,source='previous'):
    options=[a for a in ASSETS if a['leaf']==name and scope in origin(a)]
    if source=='previous':
        options=[a for a in options if TARGET_RUN in origin(a) or a['verified_previous_archive']]
    hashes=defaultdict(list)
    for a in options:hashes[sha_bytes(read(a))].append(a)
    if len(hashes)!=1:
        js(OUT/(scope.replace('/','_')+'_'+name.replace('.','_')+'_candidates.json'),
           {'name':name,'scope':scope,'different_contents':len(hashes),'candidates':[origin(a) for a in options]})
        raise Blocked(f'{scope}/{name}: expected one distinct input, found {len(hashes)}. No latest-file guessing.')
    a=sorted(next(iter(hashes.values())),key=origin)[0]
    USED.append({'role':scope+'/'+name,'origin':origin(a),'sha256':sha_bytes(read(a))})
    return a

def boolean(s):
    x=s.astype(str).str.strip().str.lower()
    if not x.isin(['true','false','1','0']).all():raise Blocked('Invalid Boolean column: '+str(s.name))
    return x.isin(['true','1'])

def finish_md3_tables(md,truth):
    full=['variant','ordering','delay_seconds','window']
    md=md.copy();truth=truth.copy()
    if not set(full+['available','warning'])<=set(md):raise Blocked('MD3 raw window schema missing')
    for c in ['delay_seconds','window']:md[c]=pd.to_numeric(md[c],errors='raise').astype(int)
    md['available']=boolean(md.available)
    if md.duplicated(full).any():raise Blocked('Duplicate MD3 row including variant; not a join-cardinality repair case')
    expected_variants={'CONTINUOUS_FIRST_REQUEST','WINDOW_RESET_DIAGNOSTIC'}
    if set(md.variant)!=expected_variants:raise Blocked('Unexpected MD3 variants')
    if len(md)!=192 or set(md.delay_seconds)!={0,1,3,10}:raise Blocked('Expected192MD3 rows:2variants*3orders*4conditions*8windows')
    for v in expected_variants:
        z=md[md.variant.eq(v)]
        if len(z)!=96 or z.groupby(['ordering','delay_seconds']).size().ne(8).any():raise Blocked('Incomplete MD3 window grid')
    available=md.available
    if not md.loc[available,'warning'].astype(str).str.lower().isin(['true','false','0','1']).all():raise Blocked('Available MD3 warning missing')
    if md.loc[~available,'warning'].astype(str).str.lower().isin(['true','false','0','1']).any():raise Blocked('Unavailable continuous windows were filled as decisions')
    raw_warning=md.warning.astype(str).str.lower()
    md['warning']=pd.array([x in ['true','1'] if a else pd.NA for x,a in zip(raw_warning,available)],dtype='boolean')
    if not md.loc[md.variant.eq('WINDOW_RESET_DIAGNOSTIC'),'available'].all():raise Blocked('Window-reset diagnostic has missing coverage')
    for _,z in md[md.variant.eq('CONTINUOUS_FIRST_REQUEST')].groupby(['ordering','delay_seconds']):
        z=z.sort_values('window');flags=z.available.to_numpy(bool)
        if np.any(np.diff(flags.astype(int))>0):raise Blocked('Continuous stream resumes after an oracle request')
        warning=z.warning.fillna(False).to_numpy(bool)
        if warning.sum()>1:raise Blocked('More than one continuous first-request warning')
        if (~flags).any() and not warning.any():raise Blocked('Censored continuous windows lack first-request warning')
        if warning.any():
            i=np.flatnonzero(warning)[0]
            if not flags[:i+1].all() or flags[i+1:].any():raise Blocked('Continuous oracle-censoring sequence inconsistent')
    columns=['ordering','delay_seconds','seed','window','original_unit_detection_drop']
    if not set(columns)<=set(truth):raise Blocked('Saved external unit-damage truth schema missing')
    truth=truth[columns].copy()
    for c in ['delay_seconds','seed','window']:truth[c]=pd.to_numeric(truth[c],errors='raise').astype(int)
    truth['original_unit_detection_drop']=pd.to_numeric(truth.original_unit_detection_drop.replace('',np.nan),errors='raise')
    tkey=['ordering','delay_seconds','seed','window']
    if truth.groupby(tkey).original_unit_detection_drop.nunique(dropna=False).gt(1).any():raise Blocked('Conflicting external unit-damage values')
    truth=truth.drop_duplicates(tkey)
    if len(truth)!=288 or set(truth.seed)!={8101,8102,8103}:raise Blocked('Expected288distinct external truth rows')
    if set(truth.ordering)!=set(md.ordering):raise Blocked('MD3/truth order sets differ')
    # The old join omitted variant. Expand truth explicitly, then use a checked one-to-many join.
    variants=pd.DataFrame({'variant':sorted(expected_variants)})
    expanded_truth=truth.merge(variants,how='cross')
    if expanded_truth.duplicated(full+['seed']).any():raise Blocked('Duplicate truth after explicit variant expansion')
    joined=md.merge(expanded_truth,on=full,how='outer',validate='one_to_many',indicator=True)
    if not joined['_merge'].eq('both').all():raise Blocked('Unmatched MD3/truth window keys')
    joined=joined.drop(columns='_merge')
    if len(joined)!=576 or joined.duplicated(full+['seed']).any():raise Blocked('Joined window/seed population is not576unique rows')
    baseline=md[md.delay_seconds.eq(0)][['variant','ordering','window','available','warning']].rename(
        columns={'available':'clean_available','warning':'clean_warning'})
    if baseline.duplicated(['variant','ordering','window']).any():raise Blocked('Duplicate clean baseline')
    joined=joined.merge(baseline,on=['variant','ordering','window'],how='left',validate='many_to_one')
    joined['paired_available']=joined.available & joined.clean_available
    joined['unit_harm']=joined.original_unit_detection_drop.ge(.05)
    rows=[]
    for (variant,ordering,delay),g in joined.groupby(['variant','ordering','delay_seconds']):
        eligible=g.original_unit_detection_drop.notna();paired=eligible & g.paired_available
        for rule in ['CONDITION_WARNING','CONDITION_ONLY_WARNING']:
            alarm=g.warning.fillna(False).astype(bool)
            if rule=='CONDITION_ONLY_WARNING':alarm=alarm & ~g.clean_warning.fillna(False).astype(bool)
            harmed=paired & g.unit_harm;no_harm=paired & ~g.unit_harm
            tp=int((harmed & alarm).sum());fn=int((harmed & ~alarm).sum())
            fp=int((no_harm & alarm).sum());tn=int((no_harm & ~alarm).sum())
            rows.append({'variant':variant,'ordering':ordering,'delay_seconds':int(delay),'warning_rule':rule,
              'eligible_appearances':int(eligible.sum()),'paired_evaluable_appearances':int(paired.sum()),
              'paired_coverage':float(paired.sum()/eligible.sum()) if eligible.sum() else np.nan,
              'TP':tp,'FN':fn,'FP':fp,'TN':tn,
              'conditional_warning_TPR':tp/(tp+fn) if tp+fn else np.nan,
              'conditional_warning_FPR':fp/(fp+tn) if fp+tn else np.nan})
    return joined,pd.DataFrame(rows),truth

def task_md3(d):
    scope='02_MATCHED_MD3'
    md_asset=select('MD3_matched_window_outputs.csv',scope)
    streams_asset=select('historical_stream_reproduction.csv',scope)
    reference_asset=select('reference_reproduction_checks.csv',scope)
    old_protocol=select('matched_protocol_before_scoring.json',scope)
    holdout=select('source_holdout_reproduction.json',scope)
    streams=table(streams_asset);reference=table(reference_asset)
    if len(streams)!=8 or not boolean(streams.matches).all():raise Blocked('Historical eight-stream MD3 reproduction not all passed')
    if reference.empty or not boolean(reference.matches).all():raise Blocked('MD3 reference-statistic reproduction failed')
    for a,name in [(md_asset,'original_raw_MD3_windows.csv'),(streams_asset,'historical_stream_reproduction.csv'),
                   (reference_asset,'reference_reproduction_checks.csv'),(old_protocol,'original_matched_protocol.json'),
                   (holdout,'source_holdout_reproduction.json')]:
        (d/name).write_bytes(read(a))
    truth_asset=select('all_order_monitor_windows.csv',WINDOW_GROUP,source='historical')
    joined,summary,truth=finish_md3_tables(table(md_asset),table(truth_asset))
    joined.to_csv(d/'MD3_matched_unit_damage_windows_FIXED.csv',index=False)
    truth.to_csv(d/'external_unit_damage_truth_deduplicated.csv',index=False)
    summary.to_csv(d/'MD3_matched_warning_summary_FIXED.csv',index=False)
    js(d/'join_audit.json',{'old_error':'variant was absent from the join key',
       'repair':'explicitly cross-expand external truth by variant; merge on variant+ordering+delay_seconds+window',
       'merge_validation':'one_to_many','raw_MD3_rows':192,'distinct_truth_rows':288,'joined_unique_variant_window_seed_rows':576,
       'new_MD3_predictions':0,'new_reference_fitting':0,'truth_values_changed':False,
       'continuous_first_request_censoring_retained':True,'window_reset_is_separate_diagnostic':True,
       'repeated_seed_window_rows_are_not_independent_trials':True})
    print('\nMATCHED MD3 WARNING RESULTS\n',summary.to_string(index=False),flush=True)
    return {'historical_eight_streams_passed':True,'joined_rows':len(joined),'summary_rows':len(summary),
            'model_fits':0,'PCAP_replays':0,'raw_warning_values_changed':False}

def task_benign(d,scope,expected_families,expected_rows):
    sa=select('ALL_COHORT_descendant_summary.csv',scope);ua=select('ALL_COHORT_unit_outcomes.csv.gz',scope)
    summary=table(sa);units=table(ua)
    key=['capture','cohort','family','seed','delay_seconds','rule','label']
    for c in ['capture','seed','delay_seconds','label','original_units','alarm_units','no_alarm_units','unresolved_units']:
        summary[c]=pd.to_numeric(summary[c],errors='raise').astype(int)
    for c in ['alarm_fraction_lower','alarm_fraction_upper']:
        summary[c]=pd.to_numeric(summary[c],errors='raise')
    for c in ['capture','seed','delay_seconds','label']:units[c]=pd.to_numeric(units[c],errors='raise').astype(int)
    if len(summary)!=expected_rows or set(summary.family)!=expected_families:raise Blocked('Unexpected saved benign/malicious result grid')
    if set(summary.seed)!={8101,8102,8103} or set(summary.delay_seconds)!={0,1,10} or set(summary.rule)!={'MG','PURE_WITNESS'} or set(summary.label)!={0,1}:raise Blocked('Saved grid dimensions differ')
    if summary.duplicated(key).any() or units.duplicated(key+['ks']).any():raise Blocked('Duplicated result/unit identity')
    if not summary.original_units.eq(512).all():raise Blocked('Frozen512denominator changed')
    if not (summary.alarm_units+summary.no_alarm_units+summary.unresolved_units).eq(summary.original_units).all():raise Blocked('Outcome partition differs from denominator')
    if not np.allclose(summary.alarm_fraction_lower,summary.alarm_units/512,atol=1e-12,rtol=0):raise Blocked('Incorrect lower accounting bound')
    if not np.allclose(summary.alarm_fraction_upper,(summary.alarm_units+summary.unresolved_units)/512,atol=1e-12,rtol=0):raise Blocked('Incorrect upper accounting bound')
    if not units.state.isin(['ALARM','NO_ALARM','UNRESOLVED']).all():raise Blocked('Unknown saved outcome state')
    recount=units.groupby(key+['state']).size().unstack(fill_value=0).reindex(columns=['ALARM','NO_ALARM','UNRESOLVED'],fill_value=0).reset_index()
    recount=recount.rename(columns={'ALARM':'recount_alarm','NO_ALARM':'recount_no_alarm','UNRESOLVED':'recount_unresolved'})
    checks=summary.merge(recount,on=key,how='outer',validate='one_to_one',indicator=True)
    if not checks['_merge'].eq('both').all():raise Blocked('Unit-outcome and summary grids do not match')
    for left,right in [('alarm_units','recount_alarm'),('no_alarm_units','recount_no_alarm'),('unresolved_units','recount_unresolved')]:
        if not checks[left].eq(checks[right]).all():raise Blocked('Unit ledger does not reproduce '+left)
    clean=json.loads(read(select('clean_reproduction.json',scope)))
    scores=table(select('clean_score_reproduction.csv',scope))
    if not clean.get('keyed_predictor_check_passed') or scores.empty or not boolean(scores.passes).all():raise Blocked('Clean feature/model reproduction did not pass')
    if not boolean(units.loc[units.rule.eq('MG') & units.state.ne('UNRESOLVED'),'strict_membership']).all():raise Blocked('A resolved MG unit lacks its saved strict-membership flag')
    missing_neg=units[(units.rule.eq('PURE_WITNESS')) & units.state.eq('NO_ALARM')]
    if not boolean(missing_neg.complete).all():raise Blocked('A PW negative lacks saved completeness')
    benign=summary[summary.label.eq(0)].copy()
    benign['lower_percent']=100*benign.alarm_fraction_lower;benign['upper_percent']=100*benign.alarm_fraction_upper
    checks.drop(columns='_merge').to_csv(d/'summary_vs_unit_recount.csv',index=False)
    summary.to_csv(d/'retained_all_cohort_summary.csv',index=False)
    benign.to_csv(d/'BENIGN_ORIGINAL_UNIT_RESULTS_VERIFIED.csv',index=False)
    (d/'clean_reproduction.json').write_text(json.dumps(clean,indent=2))
    scores.to_csv(d/'clean_score_reproduction.csv',index=False)
    unknown=units[(units.label.eq(0)) & units.state.eq('UNRESOLVED')].copy()
    unknown.to_csv(d/'unresolved_benign_unit_rows.csv',index=False)
    dossiers=[]
    if not unknown.empty:
        source=table(select('source_ownership_audit.csv',scope))
        if source.ks.duplicated().any():raise Blocked('Duplicate source-ownership audit keys')
        for delay in [0,1,10]:
            member=table(select('all_cohort_membership_'+str(delay)+'s.csv',scope))
            kset=set(unknown.loc[unknown.delay_seconds.eq(delay),'ks'])
            z=member[member.ks.isin(kset)].copy();z['delay_seconds']=delay
            if set(z.ks)!=kset or z.ks.duplicated().any():raise Blocked('Unresolved case is missing from membership audit')
            z=z.merge(source,on='ks',how='left',validate='one_to_one',suffixes=('','_source'))
            dossiers.append(z)
        pd.concat(dossiers,ignore_index=True).to_csv(d/'unresolved_benign_membership_dossier.csv',index=False)
    print('\n',scope,'BENIGN RESULTS\n',benign[['family','seed','delay_seconds','rule','alarm_units','no_alarm_units','unresolved_units','lower_percent','upper_percent']].to_string(index=False),flush=True)
    return {'status':'COMPLETED_SAVED_RESULT_AUDIT_WITH_RETAINED_BOUNDS' if len(unknown) else 'COMPLETED_SAVED_RESULT_AUDIT',
       'saved_experiment_repeated':False,'unit_rows_recounted':len(units),'benign_summary_rows':len(benign),
       'unique_unresolved_benign_keys':int(unknown.ks.nunique()),'unresolved_rows_not_converted_to_misses_or_false_positives':True,
       'scope':'saved output consistency and frozen512-unit rates; not independent packet-ledger ground truth'}

def remaining_status(d):
    required=['02_FINISH_MD3','05_VERIFY_FRESH48','08_VERIFY_HISTORICAL49']
    closed={r['task']:str(r['status']).startswith('COMPLETED') for r in LEDGER}
    executable_done=all(closed.get(k,False) for k in required)
    js(d/'completion_scope.json',{'all_targeted_code_followups_complete':executable_done,
       'manuscript_work_excluded':True,'new_PCAP_replays':0,'new_model_fits':0,
       'independent_expert_ground_truth_created':False,
       'historical49_exact_point_FPR_not_claimed_when_one_unit_unresolved':True,
       'all_scientific_or_reviewer_requests_automatically_closed':False})
    (d/'REMAINING.md').write_text(
       '# Remaining boundaries\n\n'
       '- Independently formed/adjudicated packet-to-unit reference is not created by a repair script. '
       'The successful shared-evidence decoder check remains distinct.\n'
       '- Historical49 has an observed unresolved benign unit. Its reported interval is a completed accounting result, '
       'not permission to invent a point rate. Resolving that unit needs additional admissible evidence.\n'
       '- Manuscript compilation and bibliography work are intentionally outside this batch.\n'
       '- A completed code audit does not itself establish universal guarantees, novelty or submission readiness.\n',encoding='utf-8')
    return {'status':'COMPLETED_SCOPE_REPORT','all_targeted_code_followups_complete':executable_done,
            'independent_expert_reference':'NOT_CREATED'}


def main():
    try:
        source_path=Path(__file__)
        if source_path.is_file():shutil.copyfile(source_path,OUT/'executed_finish_code.py')
    except NameError:
        try:
            source=get_ipython().history_manager.input_hist_raw[-1]
            (OUT/'executed_finish_cell.py').write_text(source)
        except Exception:pass
    print('Only finishing the saved MD3 join and auditing completed output. No Zeek installation or replay.',flush=True)
    r=stage('00_DISCOVERY',discover)
    if str(r['status']).startswith('COMPLETED'):
        stage('02_FINISH_MD3',task_md3)
        stage('05_VERIFY_FRESH48',lambda d:task_benign(d,'05_FRESH48_BENIGN_DESCENDANTS',{'HGB','LR','PROTOCOL_ONLY_LR'},108))
        stage('08_VERIFY_HISTORICAL49',lambda d:task_benign(d,'08_HISTORICAL49_BENIGN_DESCENDANTS',{'HISTORICAL_HGB'},36))
    stage('09_COMPLETION_SCOPE',remaining_status)
    checkpoint('FINAL')
    print('\nFINAL CONTINUATION LEDGER\n'+pd.DataFrame(LEDGER).to_string(index=False),flush=True)
    print('\nDownload FINAL_PACKAGE.zip or Save Version with outputs. /kaggle/working is temporary.',flush=True)

if __name__=='__main__':
    main()
