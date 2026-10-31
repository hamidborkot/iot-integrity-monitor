import ast, csv, gc, gzip, hashlib, json, re, time
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
import pandas as pd

INVENTORY = Path('/kaggle/working/CLOSING_E0A_INVENTORY_20261015T054350674918Z')
EXPECTED_TRACE_SHA = 'b340bb3289e95996007f4b7b31d6d379cfa79e03ece7f09860f82680c80a7774'
MAX_HASH_BYTES = 1024**3
MAX_SINGLE_HASH = 64 * 1024**2
MAX_SOURCE_BYTES = 2 * 1024**2
MAX_JSON_BYTES = 512 * 1024
HASH_CATEGORIES = ['TRACE_SOURCE_MODELS', 'SOURCE_REFERENCE', 'SOURCE_PREDICTIONS',
                   'SOURCE_CALIBRATION', 'TABULAR_BUNDLE']


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(4 * 1024**2), b''):
            h.update(block)
    return h.hexdigest()


def write_csv(rows, path, fields):
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader(); w.writerows(rows)


def rank_path(path):
    text = str(path)
    return ('PRIVATE_' in text, len(Path(text).parts), len(text), text)


def read_header(path):
    opener = gzip.open if path.name.endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8-sig', newline='') as f:
        line = f.readline(65537)
    if len(line) > 65536:
        raise ValueError('Header exceeds bounded read')
    return next(csv.reader([line]))


def npz_headers(path):
    import zipfile
    rows = []
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) > 100:
            raise ValueError('Unexpectedly large NPZ member count')
        for info in z.infolist():
            if not info.filename.endswith('.npy'):
                continue
            with z.open(info) as f:
                version = np.lib.format.read_magic(f)
                if version == (1, 0):
                    shape, order, dtype = np.lib.format.read_array_header_1_0(f)
                elif version == (2, 0):
                    shape, order, dtype = np.lib.format.read_array_header_2_0(f)
                else:
                    raise ValueError(f'NPY header version {version} needs explicit handling')
            rows.append({'path': str(path), 'member': info.filename, 'shape': str(shape),
                         'dtype': str(dtype), 'object_dtype': dtype.hasobject})
    return rows


def main():
    started = time.monotonic()
    for name in ['inventory_receipt.json', 'file_inventory.csv', 'artifact_candidates.csv']:
        if not (INVENTORY / name).is_file():
            raise FileNotFoundError(f'Missing E0-A output: {INVENTORY / name}')
    prior = json.loads((INVENTORY / 'inventory_receipt.json').read_text())
    if prior.get('uncompleted_root_scans'):
        raise RuntimeError('E0-A root scan incomplete; do not assume discovery is exhaustive')
    out = Path('/kaggle/working') / ('CLOSING_E0B_C_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(exist_ok=False)
    files = pd.read_csv(INVENTORY / 'file_inventory.csv', dtype=str, keep_default_na=False)
    candidates = pd.read_csv(INVENTORY / 'artifact_candidates.csv', dtype=str, keep_default_na=False)
    candidates = candidates[candidates.source.eq('direct_file')].copy()
    errors, fingerprints, groups, metadata_rows, arrays, model_rows, code_rows = [], [], [], [], [], [], []
    hashed_bytes = 0
    hash_cache = {}
    for category in HASH_CATEGORIES:
        paths = sorted(set(candidates.loc[candidates.category.eq(category), 'location']), key=rank_path)
        for text in paths:
            path = Path(text)
            row = {'category': category, 'logical_name': path.name, 'path': text,
                   'bytes': None, 'sha256': '', 'status': 'UNVERIFIED'}
            try:
                size = path.stat().st_size; row['bytes'] = size
                if size > MAX_SINGLE_HASH or hashed_bytes + size > MAX_HASH_BYTES:
                    row['status'] = 'DEFERRED_HASH_BUDGET'
                else:
                    if text not in hash_cache:
                        hash_cache[text] = sha(path); hashed_bytes += size
                    row['sha256'] = hash_cache[text]; row['status'] = 'HASHED'
            except Exception as e:
                row['status'] = 'FAILED'; errors.append({'stage': 'hash', 'path': text, 'error': str(e)})
            fingerprints.append(row)
    fp = pd.DataFrame(fingerprints)
    if not fp.empty:
        for (category, name), frame in fp.groupby(['category', 'logical_name'], sort=True):
            hashes = sorted(set(frame.loc[frame.status.eq('HASHED'), 'sha256']))
            groups.append({'category': category, 'logical_name': name, 'copies': len(frame),
                           'hashed_copies': int(frame.status.eq('HASHED').sum()),
                           'unique_hashes': len(hashes),
                           'resolution': 'BYTE_IDENTICAL' if len(hashes) == 1 and frame.status.eq('HASHED').all()
                           else 'CONFLICT_OR_INCOMPLETE', 'hashes': '|'.join(hashes)})
    resolved = {}
    trace_rows = fp[fp.category.eq('TRACE_SOURCE_MODELS') & fp.status.eq('HASHED')] if not fp.empty else pd.DataFrame()
    if not trace_rows.empty:
        matches = trace_rows[trace_rows.sha256.eq(EXPECTED_TRACE_SHA)]
        if not matches.empty:
            resolved['trace_source_model'] = sorted(matches.path.tolist(), key=rank_path)[0]
    for category, key in [('SOURCE_REFERENCE', 'source_reference'), ('SOURCE_PREDICTIONS', 'source_predictions')]:
        frame = fp[fp.category.eq(category)] if not fp.empty else pd.DataFrame()
        if not frame.empty and frame.status.eq('HASHED').all() and frame.sha256.nunique() == 1:
            resolved[key] = sorted(frame.path.tolist(), key=rank_path)[0]
    frame = fp[(fp.category.eq('SOURCE_CALIBRATION')) & (fp.logical_name.eq('calibration_contract.json'))] if not fp.empty else pd.DataFrame()
    if not frame.empty and frame.status.eq('HASHED').all() and frame.sha256.nunique() == 1:
        resolved['source_calibration_contract'] = sorted(frame.path.tolist(), key=rank_path)[0]
    contract = {}
    if 'source_calibration_contract' in resolved:
        path = Path(resolved['source_calibration_contract'])
        try:
            contract = json.loads(path.read_text())
            if not isinstance(contract, dict):
                raise ValueError('Calibration contract must be an object')
            selected_fields = {k: contract[k] for k in ['version', 'features', 'views', 'reference_rows',
                              'source_model_bundle_sha256', 'md3_halfwidth', 'blind_target_rows_read',
                              'target_predictions_computed', 'calibration_contract_sha256'] if k in contract}
            metadata_rows.append({'kind': 'SOURCE_CALIBRATION_CONTRACT', 'path': str(path),
                                  'details': json.dumps(selected_fields, sort_keys=True)})
        except Exception as e:
            errors.append({'stage': 'source_contract', 'path': str(path), 'error': str(e)})
    if 'source_reference' in resolved:
        try:
            path = Path(resolved['source_reference'])
            metadata_rows.append({'kind': 'SOURCE_REFERENCE_HEADER', 'path': str(path),
                                  'details': json.dumps(read_header(path))})
        except Exception as e:
            errors.append({'stage': 'source_header', 'path': resolved['source_reference'], 'error': str(e)})
    if 'source_predictions' in resolved:
        try: arrays = npz_headers(Path(resolved['source_predictions']))
        except Exception as e:
            errors.append({'stage': 'source_npz_header', 'path': resolved['source_predictions'], 'error': str(e)})
    contract_link_verified = bool(contract.get('source_model_bundle_sha256') == EXPECTED_TRACE_SHA)
    model_schema_ok = False
    if 'trace_source_model' in resolved and contract_link_verified:
        try:
            import joblib
            from threadpoolctl import threadpool_limits
            path = Path(resolved['trace_source_model'])
            if sha(path) != EXPECTED_TRACE_SHA:
                raise ValueError('Model changed after fingerprinting')
            with threadpool_limits(limits=2):
                bundle = joblib.load(path)
            if not isinstance(bundle, dict) or not isinstance(bundle.get('models'), dict):
                raise ValueError('Unexpected source-model bundle structure')
            metadata_rows.append({'kind': 'TRACE_BUNDLE_TOP_LEVEL_KEYS', 'path': str(path),
                                  'details': json.dumps(sorted(map(str, bundle.keys())))})
            for seed, bank in bundle['models'].items():
                if not isinstance(bank, dict): raise ValueError('Model seed bank must be a dictionary')
                for name, model in bank.items():
                    classes = np.asarray(getattr(model, 'classes_', [])).tolist()
                    model_rows.append({'seed': str(seed), 'model': str(name),
                        'python_type': type(model).__name__, 'classes': json.dumps(classes),
                        'n_features_in': getattr(model, 'n_features_in_', None),
                        'feature_names_in': json.dumps(np.asarray(getattr(model, 'feature_names_in_', [])).astype(str).tolist()),
                        'has_predict_proba': callable(getattr(model, 'predict_proba', None)),
                        'binary_01': classes == [0, 1]})
            model_schema_ok = bool(model_rows) and all(r['binary_01'] and r['has_predict_proba'] for r in model_rows)
            del bundle; gc.collect()
        except Exception as e:
            errors.append({'stage': 'verified_source_model_load', 'path': resolved['trace_source_model'], 'error': str(e)})
    result_pattern = re.compile(r'full[_-]?[345]|v[345]_main_table|paper_table_all_attacks|results_.*seed', re.I)
    result_files = files[files.relative_path.map(lambda p: bool(result_pattern.search(p))) & files.path.str.contains(r'\.csv(?:\.gz)?$', regex=True)].copy()
    result_files.to_csv(out / 'development_result_candidates.csv', index=False)
    suite_files = files[files.root_label.isin(['research-closing-code', 'research-experiment-suite']) & files.path.str.endswith('.py')]
    for row in suite_files.itertuples(index=False):
        path = Path(row.path)
        rec = {'path': str(path), 'bytes': int(row.bytes), 'sha256': '', 'status': '',
               'functions': '', 'classes': '', 'imports': '', 'top_level_call_lines': ''}
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                rec['status'] = 'DEFERRED_SIZE'
            else:
                raw = path.read_bytes(); text = raw.decode('utf-8-sig'); tree = ast.parse(text)
                rec.update(sha256=hashlib.sha256(raw).hexdigest(), status='STATIC_PARSE_ONLY',
                    functions='|'.join(n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
                    classes='|'.join(n.name for n in tree.body if isinstance(n, ast.ClassDef)),
                    imports='|'.join(ast.unparse(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))),
                    top_level_call_lines='|'.join(str(n.lineno) for n in tree.body
                        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                        and any(isinstance(x, ast.Call) for x in ast.walk(n))))
        except Exception as e:
            rec['status'] = 'FAILED'; errors.append({'stage': 'static_code', 'path': str(path), 'error': str(e)})
        code_rows.append(rec)
    corpus_files = files[files.root_label.isin(['IoT_named_corpus_VERIFY_IDENTITY', 'pcaps-of-ciciot-23-and-24'])].copy()
    corpus_files.to_csv(out / 'corpus_layout_metadata.csv', index=False)
    for prefix in ['E4_PROTOCOL_ELIGIBLE_INJECTIONS', 'FULL_GATE_POST_EXPOSURE_EVALUATION',
                   'E5_EXPLORATORY_REAL_PCAP', 'MD3_LINEAR_SVM', 'MD3_PROBABILITY_MARGIN',
                   'GATE_REVERSALS', 'CURRENT_STUDY', 'freeze_current']:
        selected = files[files.path.str.contains(prefix, regex=False)]
        metadata_rows.append({'kind': 'LATE_STAGE_PATH_COUNT', 'path': prefix, 'details': str(len(selected))})
    write_csv(fingerprints, out / 'fingerprints.csv', ['category','logical_name','path','bytes','sha256','status'])
    write_csv(groups, out / 'duplicate_groups.csv', ['category','logical_name','copies','hashed_copies','unique_hashes','resolution','hashes'])
    write_csv(metadata_rows, out / 'source_metadata.csv', ['kind','path','details'])
    write_csv(arrays, out / 'source_npz_headers.csv', ['path','member','shape','dtype','object_dtype'])
    write_csv(model_rows, out / 'source_model_schema.csv', ['seed','model','python_type','classes','n_features_in','feature_names_in','has_predict_proba','binary_01'])
    write_csv(code_rows, out / 'suite_static_index.csv', ['path','bytes','sha256','status','functions','classes','imports','top_level_call_lines'])
    write_csv(errors, out / 'errors.csv', ['stage','path','error'])
    registry = {'registry_scope': 'Historical artifacts only; not the new final experimental freeze',
                'inventory_directory': str(INVENTORY), 'resolved_paths': resolved,
                'trace_model_expected_sha256': EXPECTED_TRACE_SHA,
                'calibration_to_model_hash_link_verified': contract_link_verified,
                'source_model_schema_ok': model_schema_ok,
                'source_prediction_alignment_verified': False,
                'reference_training_disjointness_verified': False}
    (out / 'artifact_registry.json').write_text(json.dumps(registry, indent=2))
    receipt = {'stage':'E0-B/C', 'status':'RECOVERY_FINGERPRINT_AND_SCHEMA_RECORDED',
        'output_directory':str(out), 'elapsed_seconds':round(time.monotonic()-started,2),
        'hashed_bytes':hashed_bytes, 'hashed_files':len(hash_cache), 'explicit_errors':len(errors),
        'resolved_roles':sorted(resolved), 'historical_trace_model_hash_found':'trace_source_model' in resolved,
        'calibration_to_model_hash_link_verified':contract_link_verified, 'source_model_schema_ok':model_schema_ok,
        'development_result_candidates':len(result_files), 'code_files_statically_inspected':len(code_rows),
        'source_npz_array_headers':len(arrays), 'files_copied':0, 'input_files_modified':False,
        'models_trained':False, 'predictions_computed':False, 'new_target_records_read':False,
        'pcap_payloads_read':False, 'source_prediction_alignment_verified':False,
        'installed_packages_changed':False, 'scientific_experiments_completed':[],
        'next_step':'Source prediction reproduction and explicit source allocation/exposure contract'}
    (out / 'receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\n=== E0-B/C RECEIPT ===\n'+json.dumps(receipt,indent=2))
    print('\n=== RESOLVED HISTORICAL SOURCE ARTIFACTS ===\n'+json.dumps(registry,indent=2))
    print('\n=== DUPLICATE GROUP SUMMARY ===')
    print(pd.DataFrame(groups).drop(columns=['hashes'],errors='ignore').to_string(index=False))
    print('\n=== SOURCE METADATA ===')
    for r in metadata_rows: print(r['kind'],r['details'])
    print('\n=== SOURCE ARRAY HEADERS ===')
    print(pd.DataFrame(arrays).drop(columns=['path'],errors='ignore').to_string(index=False))
    print('\n=== SOURCE MODEL SCHEMA ===')
    print(pd.DataFrame(model_rows).to_string(index=False))
    print('\n=== DEVELOPMENT RESULT CANDIDATES (first 12) ===')
    print(result_files[['root_label','path','bytes']].head(12).to_string(index=False))
    print('\n=== CODE SUITES ===')
    print(pd.DataFrame(code_rows)[['path','status','functions','classes']].to_string(index=False) if code_rows else 'No direct Python files found')
    print('\n=== RAW CORPUS LAYOUT (first 12 per mount; filenames only) ===')
    for label, frame in corpus_files.groupby('root_label'):
        print(label); print(frame[['relative_path','bytes']].head(12).to_string(index=False))
    print('\n=== ERRORS ===')
    for e in errors: print(json.dumps(e))
    if not errors: print('None recorded')
    return str(out)

E0BC_OUTPUT_DIRECTORY = main()
