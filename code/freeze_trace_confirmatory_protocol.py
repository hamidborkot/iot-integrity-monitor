"""FROZEN TRACE CONFIRMATION PROTOCOL. Run once BEFORE source-model fitting or target prediction on E1 accepted targets.
Writes only metadata/hashes; does not read target pcap payloads/log rows, train models, generate attacks, or compute outcomes.
The targets are real original PCAP byte slices, not synthetic data. Labels will be used only for the precommitted stratified evaluation and metrics.
"""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd
WORK=Path('/kaggle/working')
E1=sorted([p for p in WORK.glob('E1_BLIND_TARGETS_*') if (p/'receipt.json').is_file()])
if len(E1)!=1:raise RuntimeError('Expected exactly one E1 blind-target directory; do not choose among versions.')
E1=E1[0];OUT=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1'
if OUT.exists():raise RuntimeError('Protocol path already exists; it is immutable. Do not overwrite it.')
manifest=E1/'blind_target_manifest.csv'
if not manifest.is_file():
 candidates=list(E1.glob('*.csv'))
 raise FileNotFoundError('Expected blind_target_manifest.csv. Candidates: '+str(candidates))
targets=pd.read_csv(manifest,keep_default_na=False)
accepted=targets[targets.status.eq('ACCEPTED')].copy()
EXPECTED=['CTU-IoT-Malware-Capture-7-1','CTU-IoT-Malware-Capture-9-1','CTU-IoT-Malware-Capture-33-1','CTU-IoT-Malware-Capture-36-1','CTU-IoT-Malware-Capture-39-1','CTU-IoT-Malware-Capture-43-1','CTU-IoT-Malware-Capture-48-1','CTU-IoT-Malware-Capture-49-1']
if accepted.scenario.tolist()!=EXPECTED:raise RuntimeError('Accepted-target list differs from declared E1 output; no amendment here.')
if len(accepted)!=8 or (accepted[['benign','malicious']].astype(int)<512).any().any():raise RuntimeError('Target class-count gate fails.')
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb')as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
E1R=json.loads((E1/'receipt.json').read_text())
protocol={
 'version':'trace-confirmatory-v1','created_utc':datetime.now(timezone.utc).isoformat(),'status':'FROZEN_BEFORE_TARGET_MODEL_OUTCOMES',
 'e1_directory':str(E1),'e1_receipt_sha256':sha(E1/'receipt.json'),'e1_manifest_sha256':sha(manifest),
 'design_scenarios_source_training_only':['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1'],
 'design_scenarios_not_target_units':True,'target_scenarios':EXPECTED,
 'target_slices':accepted[['scenario','accepted_plan','packets','span_seconds','generated_flows','mapped_flows','mapped_fraction','benign','malicious','core_field_identical_fraction_on_matched']].to_dict('records'),
 'source_detector':{'family':'HistGradientBoostingClassifier','random_seeds':[8101,8102,8103],'primary_features':['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto'],'threshold':0.5},
 'monitor':{'views':{'V_orig':['orig_pkts','orig_bytes','orig_ip_bytes'],'V_resp':['resp_pkts','resp_bytes','resp_ip_bytes','missed_bytes'],'V_time_proto':['duration','proto']},'estimators':['AC','DoC','ATC','AGREE','GATED'],'gate_z':3.0,'sd_floor':0.01,'window_rows':128},
 'evaluation_sampling':{'per_target_per_class_records':512,'selection':'deterministic stratified sample by source record hash; labels are used only for fixed evaluation sampling and metrics','target_outcomes_not_used_for_model_or_protocol_selection':True},
 'primary_family':{'tests':['INJ_k1','INJ_k3','PACE_1s'],'unit':'target capture scenario; one scenario-level effect per seed','targets_per_test':8,'statistic':'paired scenario-level differential absolute accuracy-estimation error gain of AGREE versus AC','one_sided_alternative':'AGREE error < AC error','correction':'Holm over exactly 3 primary tests','inference':'exact paired sign-flip over the 8 target scenarios; report effect size and all target-level results'},
 'real_packet_transformations':{
  'INJ_k1':'Duplicate the last existing header-only originator TCP packet once, timestamp +1 microsecond; preserve original bytes and order; re-extract with Zeek.',
  'INJ_k3':'Same operation, three duplicate packets at +1,+2,+3 microseconds.',
  'PACE_1s':'Delay packets after the first in an eligible malicious TCP flow by 1.0 second; preserve bytes and per-flow order; re-extract with Zeek.'},
 'eligibility':{'injection':'malicious TCP flow with >=2 originator packets and a header-only originator packet','pacing':'malicious TCP flow with total packets >=2','validity_gate':'packet multiset as designed; no original packet advanced; per-flow original packet order preserved; output timestamps nondecreasing; exact or inherited label mapping; mapped fraction >=0.999'},
 'scope_limits':['Original real PCAP bytes are used; no synthetic base traffic or feature fabrication.','Duplicated/injected packets are experimental transformations of real packets, not claimed TCP-semantic or application-valid.','No independent-corpus claim: target scenarios are capture-level units from one IoT-23 corpus.','Design scenarios were inspected and never appear as confirmatory target units.'],
 'models_trained':False,'target_predictions_computed':False,'target_outcomes_inspected_for_model_evaluation':False,'attacks_executed':False,'NF_changed':False}
OUT.mkdir();(OUT/'protocol.json').write_text(json.dumps(protocol,indent=2));accepted.to_csv(OUT/'frozen_target_manifest.csv',index=False)
# A readable exact protocol is useful during review.
md='# Frozen trace confirmatory protocol\n\n'+json.dumps(protocol,indent=2)
(OUT/'PROTOCOL.md').write_text(md)
receipt={'output_directory':str(OUT),'protocol_sha256':sha(OUT/'protocol.json'),'accepted_targets':len(EXPECTED),'primary_tests':3,'primary_unit_count':8,'models_trained':False,'target_predictions_computed':False,'attacks_executed':False,'protocol_frozen':True,'next_step':'Train source models on design scenarios only, validate transformations on all frozen targets, then evaluate exactly this protocol.'}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2));print('\nFROZEN TARGETS');print(accepted[['scenario','accepted_plan','benign','malicious','mapped_fraction']].to_string(index=False));print('\nPRIMARY FAMILY');print(json.dumps(protocol['primary_family'],indent=2))
