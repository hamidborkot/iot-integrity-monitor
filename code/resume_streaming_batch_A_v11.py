"""Technical retry for streaming Batch A. Run in same kernel. Original Batch A failed before target outcome computation because `bisect` was not imported.
Selects earliest original streaming Batch-A cell, adds `import bisect`, changes only output directory v1 -> v1_1, and executes.
"""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from IPython import get_ipython
WORK=Path('/kaggle/working');OLD=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1';NEW=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1_1';PROTO=WORK/'TRACE_CONFIRMATORY_PROTOCOL_v1/protocol.json'
if not OLD.is_dir() or not PROTO.is_file():raise FileNotFoundError('Original batch output or frozen protocol missing.')
if NEW.exists():raise RuntimeError('Retry directory exists; do not overwrite.')
history=get_ipython().history_manager.input_hist_raw
tokens=['MEMORY-BOUNDED CONFIRMATORY BATCH A','sampled_features(','ATTACKS=[(\'INJ_k1\',1),(\'INJ_k3\',3)]',"OUT=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1'"]
matches=[(i,x) for i,x in enumerate(history) if all(t in x for t in tokens)]
if not matches:raise RuntimeError('Original Batch A cell not in this kernel history. Restore/reopen that exact cell; do not change target settings.')
index,code=min(matches,key=lambda z:z[0])
if 'exec(compile(patched' in code:raise RuntimeError('Earliest match is not original Batch A source.')
patched=code.replace('import csv,gzip,hashlib,heapq,json,os,struct,subprocess,traceback','import bisect,csv,gzip,hashlib,heapq,json,os,struct,subprocess,traceback').replace("OUT=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1'","OUT=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1_1'")
if 'import bisect,' not in patched or "OUT=WORK/'TRACE_CONFIRMATORY_STREAM_RESULTS_v1'" in patched:raise RuntimeError('Patch validation failed.')
fix={'created_utc':datetime.now(timezone.utc).isoformat(),'original_history_index':index,'matching_history_indices':[i for i,_ in matches],
 'original_sha256':hashlib.sha256(code.encode()).hexdigest(),'patched_sha256':hashlib.sha256(patched.encode()).hexdigest(),'protocol_sha256':hashlib.sha256(PROTO.read_bytes()).hexdigest(),
 'technical_change':'Add missing Python standard-library import bisect for interval lookup only.','original_failure_stage':'PCAP first-pass selected-flow interval lookup before transformation, Zeek, model prediction, or target outcome computation.',
 'scientific_protocol_changed':False,'new_output_directory':str(NEW)}
(WORK/'TRACE_CONFIRMATORY_STREAM_EXECUTION_FIX_v1_1.json').write_text(json.dumps(fix,indent=2));(WORK/'run_streaming_confirmatory_batch_A_v1_1.py').write_text(patched)
print(json.dumps(fix,indent=2));print('\nExecuting corrected streaming Batch A now.')
exec(compile(patched,'run_streaming_confirmatory_batch_A_v1_1.py','exec'),{'__name__':'__main__'})
