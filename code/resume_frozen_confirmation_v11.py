"""Technical execution correction for the frozen confirmation. Run in the SAME kernel that contains the failed runner cell.
The original failed before sampling, model prediction, PCAP transformation or target outcome computation because it referenced a nonexistent protocol key.
This reuses the exact prior runner source, changes only protocol_version -> version and the output directory RESULTS_v1 -> RESULTS_v1_1, records the correction, then executes.
"""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from IPython import get_ipython
WORK=Path('/kaggle/working');PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json';OLD=WORK/'TRACE_CONFIRMATORY_RESULTS_v1';NEW=WORK/'TRACE_CONFIRMATORY_RESULTS_v1_1'
if not PROTO.is_file() or not OLD.is_dir():raise FileNotFoundError('Frozen protocol or failed-run directory missing.')
if NEW.exists():raise RuntimeError('Corrected run directory already exists; do not overwrite.')
old_fail=OLD/'failures.csv'
if not old_fail.is_file():raise RuntimeError('Expected original failures.csv absent.')
try:
 failures=json.loads((OLD/'dummy.json').read_text())
except Exception:failures=None
# The prior runner must be the latest exact runner source in input history, not any diagnostic cell.
history=get_ipython().history_manager.input_hist_raw
candidates=[x for x in history if 'FROZEN TRACE CONFIRMATORY RUNNER' in x and "TRACE_CONFIRMATORY_RESULTS_v1'" in x and "protocol_version" in x]
if len(candidates)!=1:raise RuntimeError(f'Expected exactly one original runner source in this kernel, found {len(candidates)}. Do not reconstruct manually; restore the notebook cell first.')
code=candidates[0]
if "P['protocol_version']" not in code or "OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'" not in code:raise RuntimeError('Original source differs from the audited failure.')
patched=code.replace("P['protocol_version']","P['version']").replace("OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1'","OUT=WORK/'TRACE_CONFIRMATORY_RESULTS_v1_1'")
if 'protocol_version' in patched:raise RuntimeError('Unexpected residual protocol_version reference.')
fix={'created_utc':datetime.now(timezone.utc).isoformat(),'original_runner_sha256':hashlib.sha256(code.encode()).hexdigest(),'patched_runner_sha256':hashlib.sha256(patched.encode()).hexdigest(),
 'protocol_sha256':hashlib.sha256(PROTO.read_bytes()).hexdigest(),'technical_change':"Use existing frozen protocol field P['version'] rather than nonexistent P['protocol_version'] as deterministic sample-hash salt.",
 'unchanged_protocol_content':['eight target scenarios','three source scenarios','seeds','models','views','sampling size','attacks','validity gates','statistics'],
 'original_failure_stage':'deterministic target-sample hash calculation','models_trained_in_failed_run':False,'target_predictions_in_failed_run':False,'target_outcomes_in_failed_run':False,'attacks_in_failed_run':False,
 'new_result_directory':str(NEW)}
(WORK/'TRACE_CONFIRMATORY_EXECUTION_FIX_v1_1.json').write_text(json.dumps(fix,indent=2))
(Path('/kaggle/working')/'run_frozen_trace_confirmation_v1_1.py').write_text(patched)
print(json.dumps(fix,indent=2))
print('\nExecuting corrected frozen runner now. It will create TRACE_CONFIRMATORY_RESULTS_v1_1.')
exec(compile(patched,'run_frozen_trace_confirmation_v1_1.py','exec'),{'__name__':'__main__'})
