"""Corrected technical resume. The previous wrapper matched its own text; this one selects only the original runner body by required functions/output artifact.
Run in the same kernel. No models/targets are touched until the exact original runner is selected and patched.
"""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from IPython import get_ipython
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';OLD=WORK/'TRACE_CONFIRMATORY_RESULTS_v1';NEW=WORK/'TRACE_CONFIRMATORY_RESULTS_v1_1'
if not PROTO.is_file() or not OLD.is_dir():raise FileNotFoundError('Frozen protocol or failed-run directory missing.')
if NEW.exists():raise RuntimeError('Corrected run directory already exists; do not overwrite.')
history=get_ipython().history_manager.input_hist_raw
# These tokens occur only in the original full runner, not in either resume wrapper.
tokens=['def pcap_read(','def pcap_write(','all_target_seed_estimator_results.csv',"P['protocol_version']","OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'"]
candidates=[x for x in history if all(t in x for t in tokens)]
if len(candidates)!=1:raise RuntimeError(f'Expected one full original runner, found {len(candidates)}. Matching-cell indices: {[i for i,x in enumerate(history) if all(t in x for t in tokens)]}. Do not execute a target run.')
code=candidates[0]
patched=code.replace("P['protocol_version']","P['version']").replace("OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'","OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1_1'")
if "P['protocol_version']" in patched or "TRACE_CONFIRMATORY_RESULTS_v1'" in patched:raise RuntimeError('Patch validation failed.')
fix={'created_utc':datetime.now(timezone.utc).isoformat(),'original_runner_sha256':hashlib.sha256(code.encode()).hexdigest(),'patched_runner_sha256':hashlib.sha256(patched.encode()).hexdigest(),
 'protocol_sha256':hashlib.sha256(PROTO.read_bytes()).hexdigest(),'technical_change':"Existing frozen protocol field P['version'] replaces nonexistent P['protocol_version'] only in deterministic sample-hash salt.",
 'original_failure_stage':'target sample hash before model prediction/transformation/outcome','scientific_protocol_changed':False,'new_result_directory':str(NEW)}
(WORK/'TRACE_CONFIRMATORY_EXECUTION_FIX_v1_1.json').write_text(json.dumps(fix,indent=2));(WORK/'run_frozen_trace_confirmation_v1_1.py').write_text(patched)
print(json.dumps(fix,indent=2));print('\nOriginal full runner selected exactly once. Executing corrected v1.1 now.')
exec(compile(patched,'run_frozen_trace_confirmation_v1_1.py','exec'),{'__name__':'__main__'})
