# ============================================================================
# PHASE 1 -- Semantic telemetry/provenance audit for the IoT-J paper
# Run this FIRST after attaching TON_IoT or NF-ToN-IoT-V2 to a Kaggle notebook.
# It creates reviewable files in /kaggle/working/semantic_audit/.
# No model is trained and no result is claimed. Human review of the generated
# feature_provenance_review.csv is required before semantic-view experiments.
# ============================================================================
import os, re, json, hashlib
from pathlib import Path
import numpy as np
import pandas as pd

OUT = Path('/kaggle/working/semantic_audit')
OUT.mkdir(parents=True, exist_ok=True)
MAX_FILES = 40
SAMPLE_ROWS = 5000

# Candidate sources already attached in the current notebook plus any newly attached TON/NF-ToN source.
ROOTS = [
    '/kaggle/input/datasets/himadri07/ciciot2023',
    '/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024',
    '/kaggle/input/datasets/dhoogla/csecicids2018',
    '/kaggle/input/datasets/shamstahzib/nsl-kdd-dataset',
    '/kaggle/input',
]

LABEL_PAT = re.compile(r'^(label|class|attack|attack[_ ]?type|type|category|target|binary[_ ]?label)$', re.I)
ID_PAT = re.compile(r'(flow[_ ]?id|timestamp|time[_ ]?stamp|src[_ ]?ip|dst[_ ]?ip|source[_ ]?ip|destination[_ ]?ip|id$)', re.I)

# These are CANDIDATE rules. Review and correct before use in final experiments.
VIEW_RULES = [
    ('protocol_state', r'(protocol|port|service|flag|syn|ack|fin|rst|psh|urg|header|ttl|icmp|tcp|udp)'),
    ('timing', r'(iat|inter.?arrival|duration|idle|active|time|rate|packets?/s|bytes?/s|flow.?rate)'),
    ('directionality', r'(fwd|bwd|forward|backward|downstream|upstream|inbound|outbound)'),
    ('size_volume', r'(byte|packet|length|size|payload|volume|total)'),
    ('count_burst', r'(count|burst|window|subflow|bulk|mean|std|min|max|variance)'),
]

DERIVED_PAT = re.compile(r'(mean|std|min|max|variance|rate|/s|per.?sec|avg|average|ratio|iat|flow)', re.I)
INTEGER_PAT = re.compile(r'(count|packet|byte|port|flag|protocol|ttl|header|window|subflow|bulk)', re.I)


def read_sample(path):
    try:
        if path.suffix.lower() == '.parquet':
            return pd.read_parquet(path).head(SAMPLE_ROWS)
        if path.suffix.lower() == '.csv':
            return pd.read_csv(path, nrows=SAMPLE_ROWS, low_memory=False)
    except Exception as e:
        return e
    return None


def candidate_view(c):
    for name, pat in VIEW_RULES:
        if re.search(pat, c, re.I):
            return name
    return 'unassigned'


def candidate_mutability(c, view):
    if ID_PAT.search(c):
        return 'immutable_or_exclude'
    if view == 'protocol_state':
        return 'constrained'
    if view == 'timing':
        return 'constrained'
    if view in ('size_volume', 'directionality', 'count_burst'):
        return 'review_required'
    return 'review_required'


def discover_files():
    found = []
    seen = set()
    for root in ROOTS:
        if not os.path.exists(root):
            continue
        for dp, _, fs in os.walk(root):
            for f in fs:
                p = Path(dp) / f
                if p.suffix.lower() in {'.csv', '.parquet'} and str(p) not in seen:
                    seen.add(str(p)); found.append(p)
    # Prioritize TON / NF-TON paths, then named IoT datasets, then smaller files.
    found.sort(key=lambda p: (0 if ('ton' in str(p).lower() or 'nft' in str(p).lower()) else 1, p.stat().st_size))
    return found[:MAX_FILES]

files = discover_files()
if not files:
    raise RuntimeError('No CSV or Parquet files found under /kaggle/input.')

manifest, schema_rows, provenance_rows = [], [], []
for path in files:
    sample = read_sample(path)
    if isinstance(sample, Exception):
        manifest.append({'file': str(path), 'status': 'read_error', 'detail': repr(sample)})
        continue
    if sample is None or sample.empty:
        manifest.append({'file': str(path), 'status': 'empty_or_unsupported'})
        continue
    cols = sample.columns.astype(str).tolist()
    labels = [c for c in cols if LABEL_PAT.match(c.strip())]
    manifest.append({
        'file': str(path), 'status': 'ok', 'rows_sampled': len(sample), 'n_columns': len(cols),
        'candidate_label_columns': '|'.join(labels), 'file_bytes': path.stat().st_size,
        'sha256_path': hashlib.sha256(str(path).encode()).hexdigest()
    })
    for c in cols:
        s = sample[c]
        nuniq = int(s.nunique(dropna=True))
        numeric = bool(pd.api.types.is_numeric_dtype(s))
        schema_rows.append({
            'file': str(path), 'feature': c, 'dtype': str(s.dtype), 'numeric': numeric,
            'missing_fraction': float(s.isna().mean()), 'unique_in_sample': nuniq,
            'candidate_label': c in labels, 'candidate_identifier': bool(ID_PAT.search(c))
        })
        if c in labels or ID_PAT.search(c):
            continue
        view = candidate_view(c)
        provenance_rows.append({
            'file': str(path), 'feature': c, 'dtype': str(s.dtype), 'numeric': numeric,
            'candidate_semantic_view': view,
            'candidate_primitive_or_derived': 'derived' if DERIVED_PAT.search(c) else 'primitive_or_unknown',
            'candidate_mutability': candidate_mutability(c, view),
            'candidate_integer': bool(numeric and (INTEGER_PAT.search(c) is not None or np.allclose(pd.to_numeric(s, errors="coerce").dropna() % 1, 0))),
            'candidate_action': 'REVIEW_REQUIRED',
            'validity_rule': 'REVIEW_REQUIRED',
            'notes': ''
        })

pd.DataFrame(manifest).to_csv(OUT / 'dataset_manifest.csv', index=False)
pd.DataFrame(schema_rows).to_csv(OUT / 'schema_inventory.csv', index=False)
prov = pd.DataFrame(provenance_rows)
prov.to_csv(OUT / 'feature_provenance_review.csv', index=False)

summary = pd.DataFrame(schema_rows)
summary = summary[~summary.candidate_label & ~summary.candidate_identifier]
view_summary = prov.groupby('candidate_semantic_view').feature.count().rename('candidate_features').reset_index()
view_summary.to_csv(OUT / 'candidate_view_summary.csv', index=False)

protocol = {
    'study': 'IoTJ-integrity-monitoring-confirmatory-v1',
    'rule': 'Do not train final semantic experiments until feature_provenance_review.csv has been manually completed.',
    'primary_metric': 'differential absolute accuracy-estimation error',
    'primary_datasets_after_review': ['CICIoMT2024', 'CICIoT2023', 'TON_IoT_or_NF-ToN-IoT'],
    'semantic_views_required': ['size_volume', 'timing', 'directionality', 'protocol_state', 'count_burst'],
    'forbidden_actions': ['directly perturb derived features', 'modify protocol/service identity without a valid trace-level rule', 'tune parameters on held-out fifth dataset'],
    'required_attack_checks': ['range', 'integer', 'categorical', 'protocol invariance', 'derived-feature recomputation', 'validity rate'],
    'confirmatory_seeds': [10, 11, 12],
    'pool_seed': 1,
}
with open(OUT / 'protocol_confirmatory_v1.json', 'w') as f:
    json.dump(protocol, f, indent=2)

print('Semantic audit completed.')
print('Output directory:', OUT)
print('\nFiles written:')
for p in sorted(OUT.iterdir()):
    print('-', p.name)
print('\nCandidate data files:')
print(pd.DataFrame(manifest)[['file', 'status', 'n_columns', 'candidate_label_columns']].to_string(index=False))
print('\nCandidate semantic groups:')
print(view_summary.to_string(index=False))
print('\nNEXT REQUIRED HUMAN ACTION:')
print('1. Open feature_provenance_review.csv in Kaggle output.')
print('2. Complete candidate_action and validity_rule for every feature in the chosen TON/NF-ToN dataset.')
print('3. Paste the rows for the chosen dataset back into the chat. Do not run final attacks yet.')
