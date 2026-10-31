"""FINAL technical resume. Selects the earliest matching original confirmation runner from this kernel's history.
The later wrappers can match their own token literals; they are deliberately ignored. No protocol fields other than the nonexistent key name are changed.
"""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from IPython import get_ipython
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';OLD=WORK/'TRACE_CONFIRMATORY_RESULTS_v1';NEW=WORK/'TRACE_CONFIRMATORY_RESULTS_v1_1'
if not PROTO.is_file() or not OLD.is_dir():raise FileNotFoundError('Frozen protocol or original failed-run directory missing.')
if NEW.exists():raise RuntimeError('Corrected output directory already exists; do not overwrite.')
history=get_ipython().history_manager.input_hist_raw
tokens=['def pcap_read(','def pcap_write(','all_target_seed_estimator_results.csv',"P['protocol_version']","OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'"]
matches=[(i,x) for i,x in enumerate(history) if all(t in x for t in tokens)]
if not matches:raise RuntimeError('Original runner not present in this kernel history. Re-open the executed notebook cell; do not recreate target code manually.')
index,code=min(matches,key=lambda z:z[0])
# Earliest matching cell must be the actual runner, not a resume wrapper.
if 'FROZEN TRACE CONFIRMATORY RUNNER' not in code or 'for ar in A.itertuples' not in code or 'exec(compile(patched' in code:
 raise RuntimeError(f'Earliest match {index} is not the original runner; stop and paste its first 20 source lines.')
patched=code.replace("P['protocol_version']","P['version']").replace("OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'","OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1_1'")
if "P['protocol_version']" in patched:raise RuntimeError('Key-name replacement failed.')
if "OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'" in patched:raise RuntimeError('Output-directory replacement failed.')
fix={'created_utc':datetime.now(timezone.utc).isoformat(),'original_history_index':index,'all_matching_history_indices':[i for i,_ in matches],
 'original_runner_sha256':hashlib.sha256(code.encode()).hexdigest(),'patched_runner_sha256':hashlib.sha256(patched.encode()).hexdigest(),
 'protocol_sha256':hashlib.sha256(PROTO.read_bytes()).hexdigest(),'technical_change':"P['version'] replaces nonexistent P['protocol_version'] only as deterministic target-sample hash salt.",
 'original_failure_stage':'target sample hash before target model prediction, packet transformation, attack execution, or outcome computation',
 'scientific_protocol_changed':False,'new_result_directory':str(NEW)}
(WORK/'TRACE_CONFIRMATORY_EXECUTION_FIX_v1_1.json').write_text(json.dumps(fix,indent=2));(WORK/'run_frozen_trace_confirmation_v1_1.py').write_text(patched)
print(json.dumps(fix,indent=2));print('\nSelected original runner at history index',index,'and executing corrected v1.1 now.')
exec(compile(patched,'run_frozen_trace_confirmation_v1_1.py','exec'),{'__name__':'__main__'})
