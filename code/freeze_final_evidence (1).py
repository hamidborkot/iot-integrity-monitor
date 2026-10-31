"""FREEZE + PACKAGE the final empirical evidence (no new experiment). Hashes every result table, writes a claim-evidence matrix with numbers read from the result files,
records the analysis chronology/deviations, and builds one verified private ZIP of small result files (no pcaps, no raw conn.log, no model bundles)."""
import glob,hashlib,json,zipfile
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd
WORK=Path('/kaggle/working');MAX_FILE=25*1024**2
OUT=WORK/('FINAL_EVIDENCE_FREEZE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
PREFIXES=['TRACE_SCENARIO_INVENTORY_','TRACE_DESIGN_GATE_','TRACE_BOUNDARY_CLOSING_','TRACE_ATTACK_SURFACE_','TRACE_PACKET_PACING_','TRACE_PACKET_HARNESS_V31_','TRACE_PACKET_INJECTION_1_1_',
 'TRACE_MONITOR_CASE_STUDY_','TRACE_NATURAL_SHIFT_BOUNDARY_','TRACE_TRANSFORMABILITY_CENSUS_','TRACE_CLOSING_PAIR_','TRACE_VERSION_SOURCE_','TRACE_PUBLIC_SOURCE_FIX_','TRACE_CLEAN_REPLAY_','TRACE_LABEL_FIDELITY_','FINAL_STATUS_AUDIT_']
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
dirs={};missing=[]
for pre in PREFIXES:
 found=sorted(d for d in WORK.glob(pre+'*') if d.is_dir())
 if found:dirs[pre]=found
 else:missing.append(pre)
nf=sorted(WORK.glob('resume_verified_*/nf_step5_locked_evaluation_v1'))
manifest=[];package_files=[]
def add(d,label):
 for p in sorted(d.rglob('*')):
  if not p.is_file() or p.is_symlink():continue
  if p.suffix.lower() not in {'.csv','.json','.md','.txt','.py','.yaml','.yml'}:continue
  if p.name=='conn.log' or p.stat().st_size>MAX_FILE:continue
  manifest.append({'group':label,'directory':d.name,'relative_path':str(p.relative_to(d)),'bytes':p.stat().st_size,'sha256':sha(p)});package_files.append((p,f'{d.name}/{p.relative_to(d)}'))
for pre,lst in dirs.items():
 for d in lst:add(d,pre)
for d in nf:add(d,'NF_locked_evaluation')
pd.DataFrame(manifest).to_csv(OUT/'FINAL_EVIDENCE_MANIFEST.csv',index=False)
def latest(pre,pattern):
 for d in reversed(dirs.get(pre,[])):
  f=d/pattern
  if f.is_file():return f
 return None
def val(fn):
 try:return fn()
 except Exception as e:return f'UNAVAILABLE: {type(e).__name__}'
def rd(pre,name):
 f=latest(pre,name);return pd.read_csv(f) if f else None
inj=rd('TRACE_PACKET_INJECTION_1_1_','real_packet_injection_1_1_results.csv');mon=rd('TRACE_MONITOR_CASE_STUDY_','monitor_case_study_results.csv');nat=rd('TRACE_NATURAL_SHIFT_BOUNDARY_','natural_shift_estimator_errors.csv')
nat_t=rd('TRACE_NATURAL_SHIFT_BOUNDARY_','target_level_boundary_variables.csv');h31=rd('TRACE_PACKET_HARNESS_V31_','real_packet_harness_v31_results.csv');sc=rd('TRACE_DESIGN_GATE_','A_shortcut_competence.csv')
inv_receipt=latest('TRACE_SCENARIO_INVENTORY_','receipt.json')
claims=[]
def claim(cid,status,text,evidence):claims.append({'id':cid,'status':status,'claim':text,'evidence':evidence})
claim('C1','ALLOWED_DESCRIPTIVE','On IoT-23 design scenarios, protocol alone separates the classes (a detector using only protocol matches the full detector).',
 val(lambda:'; '.join(f"{r.held_out_target.split('-Capture-')[1]} {r.model} {r.feature_set}: acc={r.accuracy:.4f}" for r in sc[(sc.model=='HGB')&(sc.feature_set.isin(['ALL9','ONLY_PROTO']))].itertuples())))
claim('C2','ALLOWED_DESCRIPTIVE','Feature-space upper bounds overstate real damage when transformations interact with the extractor (pacing beyond ~2 s splits flows in Zeek; split flows stayed detected).',
 val(lambda:'; '.join(f"{r.transformation} {r.parameter:g} {r.detector}: split={r.selected_split_fraction:.2f}, all-flow drop={r.all_flows_recall_drop:.4f}" for r in h31[h31.detector=='LOSO_LR_ALL9'].itertuples())))
claim('C3','ALLOWED_DESCRIPTIVE_SINGLE_DETECTOR','One real injected duplicate header-only packet per eligible flow lowered a within-scenario HGB detector recall on held-out malicious flows (Capture-1-1).',
 val(lambda:'; '.join(f"k={r.injected_packets_per_flow} {r.detector}: recall {r.recall_before:.4f}->{r.recall_after:.4f}, drop={r.real_recall_drop:.4f}, bound={r.upper_bound_reference}" for r in inj.itertuples())))
claim('C4','ALLOWED_DESCRIPTIVE','Confidence estimators (AC/DoC) underestimated the real damage; ATC responded equally with and without damage; agreement tracked it when an unattacked accurate view existed.',
 val(lambda:'; '.join(f"k={r.injected_packets_per_flow} {r.estimator}: est drop={r.mean_estimated_drop:.4f} vs true={r.mean_true_accuracy_drop:.4f}, diff.err={r.mean_differential_error:.4f}" for r in mon.itertuples())))
claim('C5','ALLOWED_AS_LIMITATION','Drift gating (as specified) is not reliable under natural shift: it alarmed on every window and in one scenario retained an uninformative view; mean view accuracy alone is an insufficient boundary variable.',
 val(lambda:'; '.join(f"{r.held_out_target.split('-Capture-')[1]} {r.estimator}: MAE={r.mean_abs_error:.4f}, gate_alarm={r.gate_alarm_rate}, abstain={r.abstain_rate}" for r in nat[nat.estimator.isin(['AC','AGREE','GATED'])].itertuples())))
claim('C6','ALLOWED_AS_LIMITATION','Independent-pair inference was infeasible under the declared screen.',val(lambda:json.loads(inv_receipt.read_text()).get('maximum_disjoint_pairs')))
claim('F1','FORBIDDEN','Any claim that the monitor defeats evasion, is robust, or is confirmed on independent data.','No prospective confirmation; 1 independent pair; design scenarios only.')
claim('F2','FORBIDDEN','Packet-valid, TCP-semantic or application-level validity.','Only byte-preserving, order-preserving transformations re-extracted by Zeek were tested; semantics not tested.')
claim('F3','FORBIDDEN','Generalization of the IoT-23 injection result to other detectors, datasets or CICIoT2023/CICIoMT2024 packet attacks.','CIC PCAP upload is benign-only; CIC studies remain feature-space.')
claim('F4','FORBIDDEN','NF as independent-corpus confirmation or as support for a monitor gain.','Sealed same-parent negative result (equal-family mean gain -0.0260; mean view accuracy 0.562).')
pd.DataFrame(claims).to_csv(OUT/'CLAIM_EVIDENCE_MATRIX.csv',index=False)
chron={'created_utc':datetime.now(timezone.utc).isoformat(),'status':'TRANSPARENCY_RECORD_NOT_A_PREREGISTRATION',
 'sequence':['Development study on five datasets (exploratory, feature-space).','NF same-parent boundary evaluation (locked settings; negative).','Zeek linkage of five IoT-23 scenarios; published labels used, v2 rules diagnostic only.',
 'Scenario inventory under a screen declared before results: at most 1 independent pair (significance infeasible).','Design-set audits on Captures 1-1, 3-1, 8-1 (shortcut, attackability bounds).',
 'Amendment: escalated grid was not a superset of the declared grid; union grid used.','Real-packet harness: first draft ignored flows Zeek split off and had a baseline-reset bug; corrected v3.1 reported.',
 'Real-packet injection on 1-1 (within-scenario detectors), monitor case study, natural-shift boundary check (all descriptive; one pair).'],
 'deviations_from_original_plan':['Six-test Holm confirmatory family not executed.','Trace study used design scenarios; no blind confirmatory targets under the declared screen.','Packet padding validity suite not built (padding eligibility near zero and bound near zero).'],
 'prospective_confirmation':False,'independent_pairs':1}
(OUT/'ANALYSIS_CHRONOLOGY_AND_DEVIATIONS.json').write_text(json.dumps(chron,indent=2))
package=WORK/(OUT.name+'_PRIVATE.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for p,arc in package_files:z.write(p,arc)
 for p in OUT.iterdir():
  if p.is_file():z.write(p,'FREEZE/'+p.name)
with zipfile.ZipFile(package) as z:
 bad=z.testzip()
 if bad:raise RuntimeError('ZIP CRC failure: '+bad)
receipt={'output_directory':str(OUT),'result_directories_found':{k:len(v) for k,v in dirs.items()},'prefixes_missing':missing,'NF_directory_found':bool(nf),'files_hashed':len(manifest),
 'package':str(package),'package_bytes':package.stat().st_size,'package_sha256':sha(package),'CRC_verified':True,'new_experiments_run':False,'raw_pcaps_included':False,'model_bundles_included':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
print('\nCLAIM-EVIDENCE MATRIX');print(pd.DataFrame(claims)[['id','status','claim']].to_string(index=False))
for c in claims:
 if c['id'].startswith('C'):print('\n'+c['id']+' EVIDENCE:',c['evidence'])
