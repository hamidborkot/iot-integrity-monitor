# COMPLETE SAVED ZEEK-EVIDENCE AUDIT + PAPER TABLE PACKAGE
# Read-only on source/backups. No PCAP replay, model loading/fitting, or attack generation.
# Scans every mounted experiment backup via the prior inventory; exports full selected result tables,
# an all-artifact provenance index, receipts/statuses, deduplicated tables, and an honest closure report.
import os, re, json, csv, hashlib, zipfile, traceback
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
import numpy as np
import pandas as pd

BASE = Path('/kaggle/input/datasets/mdhamidborkottulla')
WORK = Path('/kaggle/working')
BACKUPS = ['all-kaggle-work','full-working-backup','batch5','extractor','complete-backup','full-backup',
           'last-day-backup','one-last','ran-files','the-last-update','whole-in-one','the-last-days-backup','newthing-added']
INDEXES = sorted(WORK.glob('AUDIT_INVENTORY_*/file_index.csv'))
OUT = WORK/('ZEEK_COMPLETE_EVIDENCE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
OUT.mkdir(parents=True, exist_ok=False)
# Include Zeek/packet-lineage, fresh packet, monitor and original-unit result tables.
EXACT_NAMES = {
 'test3_unit_detection.csv','fresh_original_unit_results.csv','experiment1_unit_decisions.csv','experiment1_unit_decisions.csv.gz',
 'test2_transformed_membership.csv','transformed_packet_uid_mapping.csv','transformed_selected_connection_records.csv',
 'test3_detection_summary.csv','test3_historical_feature_reproduction.csv','timing_per_unit.csv','timing_horizon_summary.csv',
 'pacing_boundary_comparison.csv','timing_comparison.csv','timing_per_unit.csv','per_original_flow_counter_reconciliation.csv','MECHANISM_INFORMATION_TABLE.csv',
 'FAILURE_DECOMPOSITION.csv','EXPERIMENT1_SAVED_RESULT_AUDIT.csv','T3_monitor_vs_record_vs_unit.csv','T3_warning_summary_pooled.csv',
 'monitor_record_accuracy_results.csv','warning_target_comparison.csv','four_monitor_warning_comparison.csv',
 'gate_paired_windows.csv','gate_coverage_and_error_summary.csv','MD3_target_stream_results.csv',
 'CBPE_window_results.csv','CBPE_whole_sample_results.csv','order_warning_summary.csv','order_coverage_error_summary.csv',
 'detector_results.csv','scenario_results.csv','pacing_seed_results_with_absolute_errors.csv','pacing_scenario_errors.csv',
 'pacing_paired_scenario_gains.csv','paired_original_unit_and_record_outcomes.csv',
 'M3A_pilot_unit_bounds.csv','M3A_diag_unit_bounds.csv','M3A_detection_drop_d0_to_d10.csv',
 'experiment3_policy_summary.csv','experiment3_policy_schedules.csv','membership_0s.csv','membership_1s.csv','membership_10s.csv',
 'packet_uid_mapping_0s.csv','packet_uid_mapping_1s.csv','packet_uid_mapping_10s.csv',
 'test2_clean_packet_membership.csv','test3_clean_feature_invariance.csv','test3_clean_prediction_invariance.csv',
 'condition_provenance.json','condition_0s_events.txt','condition_1s_events.txt','condition_10s_events.txt',
 'condition_0s_stderr.txt','condition_1s_stderr.txt','condition_10s_stderr.txt','clean_packet_uid_mapping.csv',
 'test2_per_original_unit_predictions.csv','test1_association_audit.csv','input_hash_audit.csv','gap3_zeek_timeout_summary.json','gap4_m4_windows.json',
 'source_model_diagnostics.csv','source_data_manifest.csv'
}
# Avoid copying/reopening raw PCAPs, large linked-record ledgers, model binaries, and base datasets.
RELEVANT = ('LINEAGE_', 'FRESH_RAW_CAPTURE48', 'DIRECT_MOUNT_DIAGNOSTIC', 'RAW_ONLY_REMEASUREMENT',
            'P3_RAW_CAPTURE', 'P3_PAIRED_UNIT', 'E4_', 'E5_', 'CAPTURE49_SYN_TIMEOUT', 'PAPER_LOCK/M3',
            'PAPER_LOCK/M8', 'PAPER_LOCK/M9', 'PAPER_LOCK/M10', 'PAPER-LOCK/M3', 'PAPER-LOCK/M8')
MAX_TABLE_BYTES = 200*1024**2

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(8*1024**2),b''): h.update(b)
    return h.hexdigest()
def safe_json(p):
    try: return json.loads(p.read_text(errors='replace'))
    except Exception as e: return {'_read_error':f'{type(e).__name__}: {str(e)[:180]}'}
def find_files():
    found=[]
    if INDEXES:
        ip=INDEXES[-1]; print('Using existing full inventory:',ip)
        with open(ip,newline='') as fh:
            for r in csv.DictReader(fh):
                b,rel=r['backup'],r['relative_path']
                if b not in BACKUPS: continue
                p=BASE/b/rel
                if p.is_file(): found.append((b,rel,p,p.stat().st_size))
        return found
    print('No saved file index: walking the named mounted backups once.')
    for b in BACKUPS:
        root=BASE/b
        if not root.is_dir(): continue
        for cur,dirs,names in os.walk(root,followlinks=False):
            dirs[:]=[x for x in dirs if x!='.virtual_documents']
            for n in names:
                p=Path(cur)/n
                try: found.append((b,str(p.relative_to(root)),p,p.stat().st_size))
                except OSError: pass
    return found

def is_relevant(rel): return any(x.lower() in rel.lower() for x in RELEVANT)
def is_data_result(name): return name in EXACT_NAMES

def main():
    allfiles=find_files(); print('Indexed mounted files:',len(allfiles))
    # Result and receipt inventories.
    artifact_rows=[]; receipt_rows=[]
    for b,rel,p,size in allfiles:
        relevant=is_relevant(rel)
        if p.name=='receipt.json' and relevant:
            r=safe_json(p)
            receipt_rows.append({'backup':b,'relative_path':rel,'status':r.get('status',''),
                'reason':str(r.get('reason',r.get('interpretation','')))[:240],
                'sha256':sha(p),'bytes':size,'receipt':json.dumps(r,sort_keys=True,default=str)[:12000]})
        if is_data_result(p.name) and relevant:
            try: h=sha(p)
            except OSError: h='HASH_FAILED'
            artifact_rows.append({'backup':b,'relative_path':rel,'basename':p.name,'bytes':size,'sha256':h,
                                  'selected_for_read':size<=MAX_TABLE_BYTES and p.suffix.lower() not in {'.pcap','.pcapng','.joblib'}})
    art=pd.DataFrame(artifact_rows); rec=pd.DataFrame(receipt_rows)
    if art.empty: raise SystemExit('STOP: no matching Zeek result tables in mounted backups; raw inputs were not opened.')
    art.to_csv(OUT/'artifact_inventory_all_copies.csv',index=False)
    if not rec.empty: rec.to_csv(OUT/'receipt_inventory.csv',index=False)
    # Exact-byte duplicates are catalogued; one copy per hash is analyzed. Never count duplicate backup copies as replication.
    selected=art[art.selected_for_read].copy(); selected=selected.sort_values(['backup','relative_path'])
    selected['duplicate_content'] = selected.duplicated('sha256',keep='first')
    unique=selected[~selected.duplicate_content]
    unique.to_csv(OUT/'unique_artifact_read_manifest.csv',index=False)
    print('Matched result tables:',len(art),'| readable-size:',len(selected),'| unique content:',len(unique),'| duplicate copies:',int(selected.duplicate_content.sum()))
    errors=[]; tables=defaultdict(list); schema=[]
    # Read only named result artifacts, never PCAP/log payloads or model objects.
    for _,r in unique.iterrows():
        p=BASE/r.backup/r.relative_path
        try:
            if p.name.endswith('.json'):
                obj=safe_json(p); (OUT/(re.sub(r'[^A-Za-z0-9_.-]+','_',r.basename)+'.json')).write_text(json.dumps(obj,indent=2,default=str))
                continue
            d=pd.read_csv(p,low_memory=False)
            d['_source_backup']=r.backup; d['_source_path']=r.relative_path; d['_source_sha256']=r.sha256
            tables[r.basename].append(d)
            schema.append({'basename':r.basename,'source':r.relative_path,'rows':len(d),'columns':len(d.columns)-3,'column_list':'|'.join(c for c in d.columns if not c.startswith('_source_'))})
        except Exception as e: errors.append({'path':str(p),'error':f'{type(e).__name__}: {str(e)[:240]}'})
    # Export complete concatenated versions for each result filename; source path/hash remain on every row.
    combined=[]
    for name,frames in sorted(tables.items()):
        d=pd.concat(frames,ignore_index=True,sort=False)
        outname=re.sub(r'[^A-Za-z0-9_.-]+','_',name)
        d.to_csv(OUT/f'ALL_{outname}',index=False)
        combined.append({'basename':name,'source_files':len(frames),'rows':len(d),'columns':len(d.columns)-3,
                         'unique_source_hashes':int(d._source_sha256.nunique()),'combined_file':f'ALL_{outname}'})
    pd.DataFrame(schema).to_csv(OUT/'table_schema_and_rows.csv',index=False)
    pd.DataFrame(combined).to_csv(OUT/'combined_table_index.csv',index=False)
    if errors: pd.DataFrame(errors).to_csv(OUT/'read_errors.csv',index=False)
    # Reconcile key archived outcomes where the corresponding original-unit tables exist.
    findings=[]
    def add(k,v,scope): findings.append({'finding':k,'value':v,'scope':scope})
    for name,frames in tables.items():
        if name=='test3_unit_detection.csv':
            d=pd.concat(frames,ignore_index=True,sort=False)
            cols={'capture','delay_seconds','selected_record_detected','any_packet_mapped_descendant_alarm'}
            if cols.issubset(d.columns):
                for (cap,delay),g in d.groupby(['capture','delay_seconds']):
                    add(f'unit_detection_capture{cap}_delay{delay}',
                        {'rows':len(g),'membership_validated_rate':float(g.membership_validated.mean()) if 'membership_validated' in g else None,
                         'start_alarm_rate':float(g.selected_record_detected.mean()),'descendant_alarm_rate':float(g.any_packet_mapped_descendant_alarm.mean())},
                        'saved sampled original units; seeds are not independent captures')
        elif name=='fresh_original_unit_results.csv':
            d=pd.concat(frames,ignore_index=True,sort=False)
            if {'family','delay_seconds','membership_validated','selected_record_detected','any_descendant_alarm'}.issubset(d.columns):
                for (fam,delay),g in d.groupby(['family','delay_seconds']):
                    valid=g.membership_validated.astype(bool); desc=g.any_descendant_alarm.fillna(False).astype(bool)
                    add(f'fresh48_{fam}_delay{delay}',{'units':len(g),'validated':int(valid.sum()),'unresolved':int((~valid).sum()),
                        'start_alarm_rate':float(g.selected_record_detected.astype(bool).mean()),
                        'descendant_alarm_lower_validated_only':float(desc[valid].mean()) if valid.any() else None,
                        'any_descendant_field_missing':int(g.any_descendant_alarm.isna().sum())},
                        'fresh source-trained capture-48 run; unresolved units are not auto-counted as misses')
        elif name=='M3A_detection_drop_d0_to_d10.csv':
            d=pd.concat(frames,ignore_index=True,sort=False)
            for _,r in d.iterrows(): add(f'M3A_capture{r.capture}_{r.family}',{'d0':[r.detect_lower_d0,r.detect_upper_d0],
                'd10':[r.detect_lower_d10,r.detect_upper_d10],'drop_bounds':[r.drop_min,r.drop_max]},'saved unit-level bounds, not record accuracy')
        elif name=='M3A_diag_unit_bounds.csv':
            d=pd.concat(frames,ignore_index=True,sort=False)
            if {'capture','condition_seconds','timeout_seconds','family','mal_lower','mal_upper'}.issubset(d.columns):
                for (cap,delay,fam),g in d.groupby(['capture','condition_seconds','family']):
                    by=g.set_index('timeout_seconds')
                    if 5 in by.index and 15 in by.index:
                        add(f'timeout_compare_capture{cap}_delay{delay}_{fam}',{'mal_bounds_5s':[float(by.loc[5].mal_lower),float(by.loc[5].mal_upper)],
                            'mal_bounds_15s':[float(by.loc[15].mal_lower),float(by.loc[15].mal_upper)],
                            'identical':bool(np.allclose([by.loc[5].mal_lower,by.loc[5].mal_upper],[by.loc[15].mal_lower,by.loc[15].mal_upper]))},
                            'paired timeout sensitivity on tested captures/conditions only')
        elif name=='MECHANISM_INFORMATION_TABLE.csv':
            d=pd.concat(frames,ignore_index=True,sort=False)
            add('mechanism_information_rows',{'rows':len(d),'captures':sorted(d.capture.unique().tolist()) if 'capture' in d else [],
                'changed_feature_rows':int(d.changed_feature_multisets.sum()) if 'changed_feature_multisets' in d else None,
                'changed_probability_rows':int(d.changed_probability_multisets.sum()) if 'changed_probability_multisets' in d else None,
                'definite_flips':int(d.definite_binary_flips.sum()) if 'definite_binary_flips' in d else None},
                'descriptive saved extractor diagnostics; not an alternate-extractor sweep')
    (OUT/'COMPUTED_FINDINGS.json').write_text(json.dumps(findings,indent=2,default=str))
    # Preserve all receipts as a status ledger and explicitly mark experiments absent from saved evidence.
    miss=[]
    for term in ['tcp_attempt_delay','tcp_inactivity_timeout','NFStream','Argus','timing_per_unit.csv','original_unit_results.csv.gz']:
        hits=[r['relative_path'] for r in artifact_rows if term.lower() in r['relative_path'].lower()]
        miss.append({'item':term,'matching_saved_artifacts':len(hits),'paths':' | '.join(hits[:5]),
                     'status':'FOUND' if hits else 'NOT FOUND IN MOUNTED BACKUPS'})
    pd.DataFrame(miss).to_csv(OUT/'explicit_missing_or_unrun.csv',index=False)
    report=['# Complete saved Zeek evidence audit','',
      'Scope: all matching saved result tables and receipts in the listed mounted backups. This cell performs no packet replay, model fitting, model loading, or attack generation.',
      'Duplicate bytes are counted once analytically; every source copy remains in artifact_inventory_all_copies.csv.', '',
      '## Interpretation limits',
      '- Saved result tables may represent different models, cohorts, and split policies; do not pool them as independent replications.',
      '- A result called “validated” means validated under the saved membership rules, not proof of application-level functionality.',
      '- Missing timeout settings or alternate extractors are reported as gaps, not inferred negative results.',
      '- See COMPUTED_FINDINGS.json for result summaries, receipt_inventory.csv for claims/statuses, table_schema_and_rows.csv for schemas, and read_errors.csv for any failures.', '',
      '## Receipt status counts', str(rec.status.value_counts(dropna=False).to_dict() if not rec.empty else {}), '',
      '## Files not found / unrun', pd.DataFrame(miss).to_markdown(index=False), '',
      'No automatic “all Zeek experiments complete” claim is made.']
    (OUT/'ZEek_EVIDENCE_REPORT.md').write_text('\n'.join(report))
    # Private compact package contains derived tables/indexes, not raw PCAPs or huge linked ledgers.
    zpath=OUT/'PRIVATE_ZEEK_EVIDENCE_PACKAGE.zip'
    with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUT.iterdir()):
            if p.is_file() and p!=zpath: z.write(p,p.name)
    with zipfile.ZipFile(zpath) as z:
        bad=z.testzip()
        if bad: raise RuntimeError('ZIP CRC error: '+bad)
    print('\n=== CLOSURE SUMMARY ===')
    print(pd.DataFrame(miss).to_string(index=False))
    print('tables read:',len(schema),'| unique table content hashes:',len(unique),'| receipts:',len(rec),'| read errors:',len(errors))
    print('model_fits=0 | PCAP_replays=0 | output=',OUT,'| zip=',zpath)

main()
