# NF-ToN-IoT-v2 SAVED-RESULTS EXPORTER
# Read-only: no training, model loading, prediction, calibration, or PCAP work.
# Cold-start: no old Python variables or IPython history required.
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import gzip, hashlib, io, json, os, re, sys, traceback, zipfile
import numpy as np
import pandas as pd

ROOT=Path('/kaggle/input/datasets/mdhamidborkottulla/complete-backup')
PRIVATE=ROOT/'PRIVATE_NF_COMPLETED_STUDY_20261010T194004199583Z'
REL='nf_step5_locked_evaluation_v1'
SOURCE_REL='nf_step3_calibration_v1'
OUTPUT=Path('/kaggle/working')/('NF_SAVED_RESULTS_EXPORT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUTPUT.mkdir(parents=True,exist_ok=False)
# If the completed backup is attached under a different dataset mount,
# point ROOT above to that read-only directory; do not select a different version by recency.
EXPECTED_BRANCH='NF_NAMED_STUDY__EXTRACTOR_NOT_ESTABLISHED'
EXPECTED_FAMILIES={'injection','xss','ransomware','backdoor','mitm'}
USED=[]; TABLES={}; RECEIPTS={}

class Stop(Exception):pass

def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for block in iter(lambda:f.read(4*1024**2),b''):h.update(block)
    return h.hexdigest()
def write_json(path,obj):
    Path(path).write_text(json.dumps(obj,indent=2,default=str),encoding='utf-8')
def asset_bytes(path,limit=128*1024**2):
    if isinstance(path,tuple):
        archive,member=path
        with zipfile.ZipFile(archive) as z:b=z.read(member)
    else:
        p=Path(path)
        if p.suffix.lower()=='.zip':
            raise Stop('Archive member must be identified, not guessed: '+str(p))
        b=p.read_bytes()
    if len(b)>limit:raise Stop('Read limit exceeded: '+str(path))
    return b
def read_table(path):
    b=asset_bytes(path)
    if b[:2]==b'\x1f\x8b':b=gzip.decompress(b)
    frame=pd.read_csv(io.BytesIO(b),dtype=str,keep_default_na=False)
    USED.append({'path':str(path),'sha256':sha_bytes(asset_bytes(path)),'bytes':len(asset_bytes(path))})
    return frame
def read_json(path):
    obj=json.loads(asset_bytes(path))
    USED.append({'path':str(path),'sha256':sha_bytes(asset_bytes(path)),'bytes':len(asset_bytes(path))})
    return obj

def scan_locations():
    # Accept only the explicitly named study branch and expected filenames.
    # Search input/working and ZIP members, but stop on different data versions.
    wanted={
      'target_classifier_metrics.csv',
      'natural_shift_view_metrics.csv',
      'estimator_summary.csv',
      'target_windows.csv',
      'primary_paired_family_errors.csv',
      'report_constraint_checks.csv',
      'boundary_result.json',
      'evaluation_receipt.json',
      'boundary_contract.json',
      'target_allocation_receipt.json',
      'source_test_metrics.csv',
      'classifier_calibration.csv',
    }
    found=defaultdict(list); archives=[]
    for root in [Path('/kaggle/input'),Path('/kaggle/working')]:
        if not root.exists():continue
        for base,dirs,files in os.walk(root):
            bp=Path(base)
            dirs[:]=[d for d in dirs if d not in {'.git','__pycache__','site-packages','node_modules'}
                     and not d.startswith('.zeek') and bp/d!=OUTPUT]
            for name in files:
                p=bp/name
                if name in wanted and 'nf_step5_locked_evaluation_v1' in str(p):
                    found[name].append(p)
                if name.endswith('.zip') and any(k in str(p) for k in ['PRIVATE_NF_COMPLETED_STUDY','complete-backup','NF']):
                    archives.append(p)
    for archive in archives:
        try:
            with zipfile.ZipFile(archive) as z:
                for info in z.infolist():
                    name=Path(info.filename).name
                    if name in wanted and REL in info.filename and info.file_size<=128*1024**2:
                        found[name].append((archive,info.filename))
        except (OSError,zipfile.BadZipFile):pass
    return found

def load_unique(found,name,required=True):
    options=found.get(name,[])
    if not options:
        if required:raise Stop(f'Missing saved result {name}; attach the completed NF backup.')
        return None
    byhash=defaultdict(list)
    for p in options:
        b=asset_bytes(p);byhash[sha_bytes(b)].append(p)
    if len(byhash)!=1:
        details=[{'path':str(p),'sha256':sha_bytes(asset_bytes(p))} for p in options]
        write_json(OUTPUT/(name.replace('.','_')+'_CONFLICT.json'),{'candidates':details})
        raise Stop(f'Conflicting saved versions of {name}; no latest/favourable file selected.')
    return sorted(next(iter(byhash.values()),[]),key=str)[0]

def numeric(frame,columns):
    for c in columns:
        if c in frame:
            frame[c]=pd.to_numeric(frame[c].replace('',np.nan),errors='coerce')
    return frame

def save_table(frame,name,claim):
    frame.to_csv(OUTPUT/name,index=False)
    TABLES[name]=frame
    print('\n'+claim+'\n'+frame.to_string(index=False,max_rows=None,max_cols=None),flush=True)

def validate_classifier(df):
    needed={'family','condition','rows','accuracy','AUROC','normal_FPR','attack_recall','accepted_coverage','accepted_detector_error'}
    if not needed.issubset(df.columns):raise Stop('Classifier-results schema mismatch.')
    if len(df)!=20 or set(df.family)!=EXPECTED_FAMILIES:raise Stop('Expected20clean/corruption classifier rows across five families.')
    expected={'clean','report_corruption_eps_0.10','report_corruption_eps_0.25','report_corruption_eps_0.50'}
    if set(df.condition)!=expected or df.duplicated(['family','condition']).any():raise Stop('Classifier condition/family grid mismatch.')
    df=numeric(df,['rows','accuracy','AUROC','normal_FPR','attack_recall','accepted_coverage','accepted_detector_error'])
    if not df.rows.eq(2560).all():raise Stop('Unexpected target rows per family/condition.')
    for c in ['accuracy','normal_FPR','attack_recall','accepted_coverage']:
        if df[c].isna().any() or ((df[c]<0)|(df[c]>1)).any():raise Stop('Invalid fraction: '+c)
    return df

def validate_natural_views(df):
    needed={'family','view','rows','clean_accuracy','clean_AUROC'}
    if not needed.issubset(df.columns):raise Stop('Natural-view schema mismatch.')
    if len(df)!=20 or set(df.family)!=EXPECTED_FAMILIES:raise Stop('Expected20 natural-shift view rows.')
    if not df.view.isin(['protocol_service','transport_state','size_volume','timing_rate']).all():raise Stop('Unexpected semantic view.')
    if df.duplicated(['family','view']).any():raise Stop('Duplicate family/view row.')
    return numeric(df,['rows','clean_accuracy','clean_AUROC'])

def validate_receipts(found):
    for name in ['evaluation_receipt.json','boundary_result.json']:
        p=load_unique(found,name)
        RECEIPTS[name]=read_json(p)
    contract=load_unique(found,'boundary_contract.json',required=False)
    if contract is not None:RECEIPTS['boundary_contract.json']=read_json(contract)
    allocation=load_unique(found,'target_allocation_receipt.json',required=False)
    if allocation is not None:RECEIPTS['target_allocation_receipt.json']=read_json(allocation)
    receipt=RECEIPTS['evaluation_receipt.json']
    boundary=RECEIPTS['boundary_result.json']
    if receipt.get('target_predictions_computed') is not True or receipt.get('target_outcomes_now_inspected') is not True:
        raise Stop('Saved receipt does not establish that the target classifier evaluation completed.')
    if receipt.get('source_models_retrained') is not False or receipt.get('classifier_thresholds_changed') is not False:
        raise Stop('Saved receipt indicates model/threshold changes; inspect branch identity.')
    if boundary.get('precommitted_threshold')!=0.8:
        raise Stop('Boundary contract threshold changed from precommitted0.8.')
    if boundary.get('family_panels_proven_independent') is not False:
        raise Stop('Unexpected family independence metadata.')
    for name,obj in RECEIPTS.items():write_json(OUTPUT/name,obj)
    return receipt,boundary

def main():
    if not ROOT.is_dir():raise Stop('Expected attached complete-backup directory: '+str(ROOT))
    found=scan_locations()
    write_json(OUTPUT/'candidate_index.json',{k:[str(p) for p in v] for k,v in found.items()})
    classifier=validate_classifier(read_table(load_unique(found,'target_classifier_metrics.csv')))
    natural=validate_natural_views(read_table(load_unique(found,'natural_shift_view_metrics.csv')))
    source=read_table(load_unique(found,'source_test_metrics.csv',required=False))
    calibration=read_table(load_unique(found,'classifier_calibration.csv',required=False))
    estimator=read_table(load_unique(found,'estimator_summary.csv'))
    windows=read_table(load_unique(found,'target_windows.csv'))
    paired=read_table(load_unique(found,'primary_paired_family_errors.csv'))
    constraints=read_table(load_unique(found,'report_constraint_checks.csv'))
    source,boundary=validate_receipts(found)
    save_table(classifier,'NF_TARGET_CLASSIFIER_RESULTS.csv',
       'NF-ToN-IoT-v2 saved target-family classifier results;family panels are not independent corpora and extractor identity is not established')
    clean=classifier[classifier.condition.eq('clean')].copy()
    save_table(clean,'NF_CLEAN_HELDOUT_FAMILY_RESULTS.csv','Clean held-out-family classifier results')
    save_table(natural,'NF_NATURAL_SHIFT_SEMANTIC_VIEW_RESULTS.csv','Saved natural-shift semantic-view results')
    save_table(estimator,'NF_ESTIMATOR_SUMMARY.csv','Saved estimator summary;do not confuse differential and ordinary accuracy error')
    save_table(windows,'NF_WINDOW_RESULTS_400.csv','All400 saved NF window rows')
    save_table(paired,'NF_PAIRED_FAMILY_ERROR_SUMMARY.csv','Saved paired family-error summary')
    save_table(constraints,'NF_REPORT_CORRUPTION_CONSTRAINT_CHECKS.csv','Saved report-corruption constraint checks')
    if not source.empty:save_table(source,'NF_SOURCE_TEST_RESULTS.csv','Source-test metrics')
    if not calibration.empty:save_table(calibration,'NF_SOURCE_CALIBRATION_RESULTS.csv','Frozen-source classifier calibration')
    boundaryrows=[{'field':k,'value':v} for k,v in boundary.items()]
    save_table(pd.DataFrame(boundaryrows),'NF_BOUNDARY_RESULT_RECEIPT.csv','Boundary receipt;low-competence branch only,not independent-gain confirmation')
    allocation=RECEIPTS.get('target_allocation_receipt.json',{})
    js(OUTPUT/'NF_SCOPE_AND_PROVENANCE.json',{
      'branch':EXPECTED_BRANCH,'dataset':'NF-ToN-IoT-v2 same-parent representation branch',
      'classifier_results':'Record-level holdout attack-family results;20rows',
      'semantic_views':'Four views across five holdout families;20rows',
      'report_corruption_conditions':[0.10,0.25,0.50],
      'models_retrained_in_saved_stage':False,'thresholds_changed_in_saved_stage':False,
      'target_predictions_computed':True,'target_outcomes_inspected':True,
      'source_target_predictor_group_disjointness_verified':allocation.get('source_target_predictor_group_disjointness_verified'),
      'independent_corpus_claim_allowed':False,'extractor':'NOT ESTABLISHED BY THIS NF BRANCH',
      'paired_zeek_nfstream_count_experiment':'SEPARATE STUDY; NOT CLASSIFIER DETECTION',
      'packet_validity_established':False,'NetFlow_cross_field_validity_established':False,
      'attack_contract_status':RECEIPTS.get('boundary_contract.json',{}).get('attack_contract_status',allocation.get('attack_contract_status')),
      'boundary_threshold':0.8,'equal_family_mean_gain':boundary.get('equal_family_mean_gain'),
      'boundary_interpretation':boundary.get('hypothesis_interpretation'),
      'target_family_panels_are_independent':False,
      'claims_not_supported':['NFStream classifier recall','independent-corpus replication','packet-valid evasion','high-competence gain independently confirmed']})
    js(OUTPUT/'NF_EXPORT_RECEIPT.json',{'status':'SAVED_NF_RESULTS_EXPORTED_AND_VALIDATED','input_branch':EXPECTED_BRANCH,
      'classifier_metric_rows':len(classifier),'semantic_view_rows':len(natural),'target_window_rows':len(windows),
      'estimator_summary_rows':len(estimator),'new_training':False,'new_predictions':False,'new_PCAP_replays':False})
    files=[p.name for p in OUTPUT.iterdir() if p.is_file()]
    digestrows=[]
    for name in sorted(files):
        p=OUTPUT/name
        digestrows.append({'file':name,'bytes':p.stat().st_size,'sha256':sha_file(p)})
    pd.DataFrame(digestrows).to_csv(OUTPUT/'EXPORT_MANIFEST.csv',index=False)
    package=OUTPUT/'NF_SAVED_RESULTS_WITH_SCOPE.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUTPUT.iterdir()):
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    with zipfile.ZipFile(package) as z:
        if z.testzip():raise RuntimeError('Export ZIP CRC check failed.')
    print('\nNF BRANCH SCOPE\n'+json.dumps(json.loads((OUTPUT/'NF_SCOPE_AND_PROVENANCE.json').read_text()),indent=2),flush=True)
    print('\nRESULT PACKAGE:',package,'\nSHA256:',sha_file(package),flush=True)
    try:
        from IPython.display import display,FileLink
        display(FileLink(str(package)))
    except Exception:pass

if __name__=='__main__':
    try:main()
    except Exception as e:
        (OUTPUT/'EXPORT_STOP_REASON.txt').write_text(traceback.format_exc())
        print('EXPORT STOPPED WITHOUT CHANGING EXPERIMENTS:',str(e),flush=True)
        print('See:',OUTPUT/'candidate_index.json',flush=True)
        raise
