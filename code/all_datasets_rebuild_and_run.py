"""Standalone fresh-development rebuild and E9/E10 suite.
Derived input paths and IoT/TON schemas from notebookc031a591b0.ipynb.
CSE/NSL channel schemas below are NEW explicit development configurations.
Not restoration of the old frozen models; outputs must not be pooled with old runs.
Not a packet-validity or confirmatory experiment. See completion_ledger.csv.
"""
import gc
import hashlib
import json
import re
import time
import traceback
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import KFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

OUTPUT_ROOT = Path('/kaggle/working/fresh_all_datasets_v1')
DATASETS = ['CICIoT2023', 'CICIoMT2024', 'CSE', 'NSL', 'TONIoT']
POOL_SEED = 1
MODEL_SEED = 10
ATTACK_SEEDS = [10, 11, 12]
PARTITION_SEEDS = [201, 202, 203]
EPSILONS = [0.10, 0.25, 0.50]
SPARSE_K = 3
SURROGATE_FRACTION = 0.50
WINDOW_SIZE = 128
REFERENCE_WINDOWS = 128
DOMAIN_ROWS = 5000
COVERAGES = [0.25, 0.50, 0.75, 0.85, 1.00]
MARGIN_WIDTH = 0.10
TARGET_FPR = 0.05
CAP_BENIGN = 30000
CAP_ATTACK_PER_FAMILY = 3000
MAX_ATTACK_TOTAL = 24000
MIN_FAMILY_ROWS = 500
SOURCE_FRACTION = 0.60
FORCE_REBUILD = False
RUN_EXPERIMENTS = True
RESUME_COMPLETED_DATASETS = True

PATHS = {
 'CICIoT2023': '/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23',
 'CICIoMT2024': '/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024',
 'CSE': '/kaggle/input/datasets/dhoogla/csecicids2018',
 'NSL': '/kaggle/input/datasets/shamstahzib/nsl-kdd-dataset/nsl-kdd-dataset',
 'TONIoT': '/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network',
}
DATASET_MARKERS = {
 'CICIoT2023': ['ciciot2023', 'ciciot23'],
 'CICIoMT2024': ['cic-iomt-dataset-2024'],
 'CSE': ['csecicids2018'],
 'NSL': ['nsl-kdd-dataset'],
 'TONIoT': ['ton-iot-train-test-network'],
}
IOT_SCHEMAS = {'CICIoT2023': {'protocol_state': ['protocoltype',
                                   'finflagnumber',
                                   'synflagnumber',
                                   'rstflagnumber',
                                   'pshflagnumber',
                                   'ackflagnumber',
                                   'eceflagnumber',
                                   'cwrflagnumber',
                                   'tcp',
                                   'udp',
                                   'icmp'],
                'volume_size': ['headerlength',
                                'totsum',
                                'totsize',
                                'number',
                                'min',
                                'max',
                                'avg',
                                'std'],
                'count_burst': ['ackcount',
                                'syncount',
                                'fincount',
                                'urgcount',
                                'rstcount',
                                'magnitue',
                                'magnitude',
                                'radius',
                                'covariance',
                                'variance',
                                'weight']},
 'CICIoMT2024': {'protocol_state': ['protocoltype',
                                    'finflagnumber',
                                    'synflagnumber',
                                    'rstflagnumber',
                                    'pshflagnumber',
                                    'ackflagnumber',
                                    'eceflagnumber',
                                    'cwrflagnumber',
                                    'tcp',
                                    'udp',
                                    'icmp'],
                 'timing_rate': ['duration',
                                 'flowduration',
                                 'rate',
                                 'srate',
                                 'drate',
                                 'iat'],
                 'count_burst': ['ackcount',
                                 'syncount',
                                 'fincount',
                                 'urgcount',
                                 'rstcount',
                                 'magnitue',
                                 'magnitude',
                                 'radius',
                                 'covariance',
                                 'variance',
                                 'weight']}}
TON_SCHEMA = {'context_state': ['proto', 'service', 'conn_state'],
 'volume': ['src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts', 'dst_pkts'],
 'timing': ['duration'],
 'dns_codes': ['dns_qclass',
               'dns_qtype',
               'dns_rcode',
               'dns_AA',
               'dns_RD',
               'dns_RA',
               'dns_rejected'],
 'tls_state': ['ssl_version', 'ssl_cipher', 'ssl_resumed', 'ssl_established'],
 'http_state': ['http_trans_depth',
                'http_method',
                'http_version',
                'http_request_body_len',
                'http_response_body_len',
                'http_status_code',
                'http_orig_mime_types',
                'http_resp_mime_types'],
 'zeek_anomaly_state': ['weird_name', 'weird_notice']}
NSL_COLUMNS = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty']
NSL_FAMILIES = {'DoS': ['neptune', 'back', 'land', 'pod', 'smurf', 'teardrop', 'mailbomb', 'apache2', 'processtable', 'udpstorm', 'worm'], 'Probe': ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint'], 'R2L': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy', 'warezclient', 'warezmaster', 'sendmail', 'named', 'snmpgetattack', 'snmpguess', 'xlock', 'xsnoop', 'httptunnel'], 'U2R': ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'ps', 'sqlattack', 'xterm']}

NSL_SCHEMA = {
 'protocol_state': ['protocol_type', 'service', 'flag', 'land', 'logged_in',
                    'root_shell', 'su_attempted', 'is_host_login', 'is_guest_login'],
 'volume_size': ['src_bytes', 'dst_bytes'],
 'timing': ['duration'],
 'count_burst': ['count', 'srv_count', 'dst_host_count', 'dst_host_srv_count'],
 'error_rates': ['serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'],
}
CSE_SCHEMA = {
 'protocol_state': ['Protocol', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
                    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
                    'CWE Flag Count', 'ECE Flag Cnt', 'Fwd PSH Flags', 'Bwd PSH Flags'],
 'volume_size': ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean',
                 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
                 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
                 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
                 'Pkt Len Var', 'Pkt Size Avg'],
 'timing_rate': ['Flow Duration', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
                 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
                 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
                 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std',
                 'Bwd IAT Max', 'Bwd IAT Min', 'Active Mean', 'Idle Mean'],
}
MUTABLE_ALIASES = {
 'CICIoT2023': IOT_SCHEMAS['CICIoT2023']['volume_size'],
 'CICIoMT2024': IOT_SCHEMAS['CICIoMT2024']['timing_rate'],
 'CSE': ['TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
         'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
         'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std'],
 'NSL': ['src_bytes', 'dst_bytes', 'duration'],
 'TONIoT': ['src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts'],
}
CSE_ALTERNATE_NAMES = {
 'totfwdpkts': ['totalfwdpackets'], 'totbwdpkts': ['totalbackwardpackets'],
 'totlenfwdpkts': ['totallengthoffwdpackets'],
 'totlenbwdpkts': ['totallengthofbwdpackets'],
 'fwdpktlenmax': ['fwdpacketlengthmax'], 'fwdpktlenmin': ['fwdpacketlengthmin'],
 'fwdpktlenmean': ['fwdpacketlengthmean'], 'fwdpktlenstd': ['fwdpacketlengthstd'],
 'bwdpktlenmax': ['bwdpacketlengthmax'], 'bwdpktlenmin': ['bwdpacketlengthmin'],
 'bwdpktlenmean': ['bwdpacketlengthmean'], 'bwdpktlenstd': ['bwdpacketlengthstd'],
 'pktlenmin': ['minpacketlength'], 'pktlenmax': ['maxpacketlength'],
 'pktlenmean': ['packetlengthmean'], 'pktlenstd': ['packetlengthstd'],
 'pktlenvar': ['packetlengthvariance'], 'pktsizeavg': ['averagepacketsize'],
 'finflagcnt': ['finflagcount'], 'synflagcnt': ['synflagcount'],
 'rstflagcnt': ['rstflagcount'], 'pshflagcnt': ['pshflagcount'],
 'ackflagcnt': ['ackflagcount'], 'urgflagcnt': ['urgflagcount'],
 'eceflagcnt': ['eceflagcount'], 'flowbytss': ['flowbytess'],
 'flowpktss': ['flowpacketss'],
}


def norm(value):
    return re.sub(r'[^a-z0-9]', '', str(value).lower())


def save_csv(rows, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame = rows if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    temporary = path.with_suffix('.tmp')
    frame.to_csv(temporary, index=False)
    temporary.replace(path)


def save_json(value, path):
    Path(path).write_text(json.dumps(value, indent=2, default=str))


def new_model(seed=MODEL_SEED):
    return Pipeline([
        ('imputer', SimpleImputer(strategy='median', keep_empty_features=True)),
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(max_iter=2000, class_weight='balanced',
                                          solver='lbfgs', random_state=seed)),
    ])


def threshold_at_fpr(probability):
    p = np.sort(np.asarray(probability, dtype=float))
    if not len(p) or not np.isfinite(p).all():
        raise ValueError('Invalid normal calibration probabilities.')
    allowed = int(np.floor(TARGET_FPR * len(p)))
    return float(p[max(0, len(p) - allowed - 1)])


def dataset_files(name):
    root = Path(PATHS[name])
    if not root.exists():
        candidates = [p for p in Path('/kaggle/input').rglob('*')
                      if p.is_dir() and any(marker in str(p).lower()
                                            for marker in DATASET_MARKERS[name])]
        if not candidates:
            raise FileNotFoundError(f'{name}: attach the notebook input dataset: {root}')
        root = min(candidates, key=lambda p: len(str(p)))
    if name == 'CICIoT2023':
        files = [root / split / f'{split}.csv' for split in ['train', 'validation', 'test']]
    elif name == 'CICIoMT2024':
        files = [root / 'train_iomt.csv', root / 'test_iomt.csv']
    elif name == 'CSE':
        files = sorted(root.rglob('*.parquet'))
    elif name == 'TONIoT':
        files = list(root.rglob('TON_IoT_Train_Test_Network.csv'))
        if not files:
            files = list(root.rglob('TONIoTTrainTestNetwork.csv'))
    else:
        files = []
        for options in [['KDDTrain+.txt', 'KDDTrain.txt'],
                        ['KDDTest+.txt', 'KDDTest.txt'], ['KDDTest-21.txt']]:
            found = next((list(root.rglob(option)) for option in options
                          if list(root.rglob(option))), [])
            if found:
                files.append(min(found, key=lambda p: len(str(p))))
    if not files or any(not path.exists() for path in files):
        raise FileNotFoundError(f'{name}: required raw files absent: {files}')
    return files


def chunks_for(path, name):
    if name == 'NSL':
        frame = pd.read_csv(path, header=None)
        if frame.shape[1] not in [42, 43]:
            raise ValueError(f'Unexpected NSL raw schema: {frame.shape}')
        frame.columns = NSL_COLUMNS[:frame.shape[1]]
        yield frame
    elif path.suffix == '.parquet':
        import pyarrow.parquet as pq
        for batch in pq.ParquetFile(path).iter_batches(batch_size=200000):
            yield batch.to_pandas()
    else:
        yield from pd.read_csv(path, chunksize=200000, low_memory=False)


def load_raw(name):
    rng = np.random.default_rng(POOL_SEED)
    reservoirs = {}
    family_map = {attack: family for family, attacks in NSL_FAMILIES.items()
                  for attack in attacks}
    for path in dataset_files(name):
        offset = 0
        domain = (('train' if 'train' in path.name.lower() else
                   'test21' if '21' in path.name else 'test')
                  if name == 'NSL' else path.stem.split('-')[0])
        for frame in chunks_for(path, name):
            frame = frame.copy()
            frame.columns = frame.columns.astype(str).str.strip()
            label_column = next((c for c in frame if c.lower() == 'label'), None)
            if label_column is None:
                raise ValueError(f'{path}: no label column')
            raw_label = frame[label_column].astype(str).str.strip().str.lower().str.rstrip('.')
            if name == 'TONIoT':
                numeric_label = pd.to_numeric(frame[label_column], errors='coerce')
                if not numeric_label.isin([0, 1]).all() or 'type' not in frame:
                    raise ValueError('TON requires binary label and attack type columns.')
                benign = numeric_label.eq(0)
                family = frame['type'].astype(str).str.strip().str.lower()
            elif name == 'NSL':
                benign = raw_label.eq('normal')
                family = raw_label.map(family_map).fillna(raw_label)
            else:
                benign = raw_label.str.contains('benign|normal', regex=True)
                if not benign.any() and pd.to_numeric(raw_label, errors='coerce').notna().all():
                    raise ValueError('Numeric label coding needs an explicit benign mapping.')
                family = raw_label
            row_ids = [f'{path.name}:{offset + index}' for index in range(len(frame))]
            offset += len(frame)
            frame = frame.drop(columns=[label_column])
            frame['label'] = (~benign).to_numpy(dtype=int)
            frame['_family'] = np.where(benign, 'normal', family)
            frame['_domain'] = domain
            frame['_row_id'] = row_ids
            frame['_priority'] = rng.random(len(frame))
            grouping = ['_domain', '_family'] if name in ['CSE', 'NSL'] else ['_family']
            for key, part in frame.groupby(grouping, sort=True):
                family_value = part['_family'].iloc[0]
                cap = CAP_BENIGN if family_value == 'normal' else CAP_ATTACK_PER_FAMILY
                previous = reservoirs.get(key)
                combined = part if previous is None else pd.concat([previous, part], ignore_index=True)
                reservoirs[key] = combined.nsmallest(cap, '_priority').copy()
        print(f'Loaded/sample-capped {name}: {path.name}', flush=True)
    raw = pd.concat(reservoirs.values(), ignore_index=True).drop(columns='_priority')
    if raw['_row_id'].duplicated().any():
        raise ValueError('Duplicate source row IDs.')
    if not raw['label'].eq(0).any():
        raise ValueError('No recognized benign records.')
    return raw


def balanced_domain(frame, seed, cap=6000):
    normal = frame[frame.label == 0]
    attack = frame[frame.label == 1]
    count = min(len(normal), len(attack), cap)
    if count < WINDOW_SIZE:
        return None
    return pd.concat([normal.sample(count, random_state=seed),
                      attack.sample(count, random_state=seed + 1)]).sample(
                          frac=1, random_state=seed + 2).reset_index(drop=True)


def make_splits(name, raw):
    targets = {}
    if name == 'NSL':
        source = raw[raw._domain == 'train'].copy()
        for domain in ['test', 'test21']:
            frame = balanced_domain(raw[raw._domain == domain], POOL_SEED + 90)
            if frame is not None:
                targets[f'official_{domain}'] = frame
    elif name == 'CSE':
        domains = sorted(raw['_domain'].unique())
        source_domain = next((d for d in domains if d == 'DDoS1'), None)
        if source_domain is None:
            raise ValueError('CSE source DDoS1 parquet is absent.')
        source = raw[raw._domain == source_domain].copy()
        for domain in domains:
            if domain != source_domain:
                frame = balanced_domain(raw[raw._domain == domain], POOL_SEED + 91)
                if frame is not None:
                    targets[f'day_{domain}'] = frame
    else:
        source = raw.copy()
    counts = source[source.label == 1]['_family'].value_counts()
    eligible = sorted(counts[counts >= MIN_FAMILY_ROWS].index)
    if not eligible:
        raise ValueError(f'{name}: no sufficiently populated attack families.')
    if name in ['NSL', 'CSE']:
        known = eligible
        heldout = []
    else:
        cut = min(len(eligible), int(np.ceil(SOURCE_FRACTION * len(eligible))))
        known, heldout = eligible[:cut], eligible[cut:]
    per_family = min(CAP_ATTACK_PER_FAMILY, MAX_ATTACK_TOTAL // len(eligible),
                     int(counts[eligible].min()))
    attacks = {'train': [], 'reference': [], 'source_test': [], 'heldout': []}
    for index, family in enumerate(eligible):
        frame = source[source._family == family].sample(
            per_family, random_state=POOL_SEED + index)
        if family in heldout:
            attacks['heldout'].append(frame)
        else:
            first = int(0.50 * len(frame))
            second = first + int(0.25 * len(frame))
            attacks['train'].append(frame.iloc[:first])
            attacks['reference'].append(frame.iloc[first:second])
            attacks['source_test'].append(frame.iloc[second:])
    attack_frames = {key: pd.concat(parts, ignore_index=True)
                     for key, parts in attacks.items() if parts}
    normal = source[source.label == 0]
    need = sum(len(frame) for frame in attack_frames.values())
    if len(normal) < need:
        raise ValueError(f'{name}: balanced split needs {need} normal rows; has {len(normal)}')
    normal = normal.sample(need, random_state=POOL_SEED + 900)
    splits = {}
    start = 0
    for key, attack_frame in attack_frames.items():
        normal_frame = normal.iloc[start:start + len(attack_frame)]
        start += len(attack_frame)
        if key == 'reference':
            splits['normal_reference'] = normal_frame.copy()
            splits['attack_reference'] = attack_frame.copy()
        else:
            splits[key] = pd.concat([normal_frame, attack_frame]).sample(
                frac=1, random_state=POOL_SEED + 901).reset_index(drop=True)
    if 'heldout' in splits:
        targets['heldout_family'] = splits.pop('heldout')
    splits.update({f'natural_{key}': value for key, value in targets.items()})
    seen = set()
    for key, frame in splits.items():
        ids = set(frame['_row_id'])
        if seen & ids:
            raise ValueError(f'{name}: row overlap in {key}')
        seen.update(ids)
    return splits, known, heldout


def resolve_columns(aliases, columns):
    lookup = {norm(column): column for column in columns}
    resolved = []
    for alias in aliases:
        key = norm(alias)
        options = [key] + CSE_ALTERNATE_NAMES.get(key, [])
        found = next((lookup[option] for option in options if option in lookup), None)
        if found is not None and found not in resolved:
            resolved.append(found)
    return resolved


def encode_frames(name, frames):
    train = frames['train']
    excluded = {'label', 'type', 'difficulty', 'attack', 'attack_cat', 'category'}
    identifiers = {'flowid', 'timestamp', 'srcip', 'dstip', 'sourceip', 'destinationip',
                   'srcport', 'dstport', 'sourceport', 'destinationport', 'ts'}
    ton_allowed = set(sum(TON_SCHEMA.values(), []))
    raw_features = [column for column in train
                    if not column.startswith('_') and column.lower() not in excluded
                    and norm(column) not in identifiers and not column.lower().startswith('unnamed')
                    and (name != 'TONIoT' or column in ton_allowed)]
    metadata = {}
    transformations = {}
    encoded = {key: {} for key in frames}
    for column in raw_features:
        numeric = pd.to_numeric(train[column], errors='coerce')
        is_numeric = pd.api.types.is_numeric_dtype(train[column]) or (
            train[column].notna().any()
            and numeric.notna().sum() == train[column].notna().sum())
        if is_numeric:
            if not np.isfinite(numeric.replace([np.inf, -np.inf], np.nan)).any():
                continue
            transformations[column] = [column]
            metadata[column] = {'kind': 'numeric'}
            for key, frame in frames.items():
                encoded[key][column] = pd.to_numeric(frame[column], errors='coerce').replace(
                    [np.inf, -np.inf], np.nan).to_numpy(dtype=float)
        else:
            # Categories are learned from training records ONLY.
            values = train[column].fillna('__MISSING__').astype(str)
            categories = sorted(values.unique())
            if len(categories) > 256:
                continue
            names = [f'{column}__category_{index}' for index in range(len(categories))]
            transformations[column] = names
            metadata[column] = {'kind': 'categorical', 'categories': categories}
            for key, frame in frames.items():
                values = frame[column].fillna('__MISSING__').astype(str)
                for encoded_name, category in zip(names, categories):
                    encoded[key][encoded_name] = values.eq(category).to_numpy(dtype=float)
    outputs = {}
    for key, frame in frames.items():
        transformed = pd.DataFrame(encoded[key])
        for column in ['label', '_row_id', '_family', '_domain']:
            transformed[column] = frame[column].to_numpy()
        outputs[key] = transformed
    features = list(encoded['train'])
    schema = (IOT_SCHEMAS[name] if name in IOT_SCHEMAS else
              TON_SCHEMA if name == 'TONIoT' else NSL_SCHEMA if name == 'NSL' else CSE_SCHEMA)
    groups = {}
    used = set()
    for view, aliases in schema.items():
        columns = resolve_columns(aliases, transformations)
        expanded = [feature for column in columns for feature in transformations[column]]
        expanded = [feature for feature in expanded if feature not in used]
        if expanded:
            groups[view] = expanded
            used.update(expanded)
    mutable_raw = resolve_columns(MUTABLE_ALIASES[name], transformations)
    mutable = [column for column in mutable_raw if metadata[column]['kind'] == 'numeric']
    if not features or len(groups) < 2 or not mutable:
        raise ValueError(f'{name}: invalid resolved schema: views={list(groups)}, mutable={mutable}')
    return outputs, features, groups, mutable, metadata


def rebuild_bundle(name, directory):
    raw = load_raw(name)
    frames, known, heldout = make_splits(name, raw)
    frames, features, groups, mutable, encoding = encode_frames(name, frames)
    normal = frames['normal_reference']
    if len(normal) < 4 * WINDOW_SIZE:
        raise ValueError(f'{name}: normal reference must have at least {4 * WINDOW_SIZE} rows')
    order = np.random.default_rng(1001).permutation(len(normal))
    primary_ix, threshold_ix, fit_ix, calibration_ix = np.array_split(order, 4)
    attack_fit_ix, attack_calibration_ix = np.array_split(
        np.random.default_rng(1005).permutation(len(frames['attack_reference'])), 2)
    primary_calibration = normal.iloc[primary_ix].copy()
    normal_remaining = normal.iloc[np.r_[threshold_ix, fit_ix, calibration_ix]].copy()
    known_fit = pd.concat([normal.iloc[fit_ix],
                          frames['attack_reference'].iloc[attack_fit_ix]], ignore_index=True)
    known_calibration = pd.concat([normal.iloc[calibration_ix],
                                  frames['attack_reference'].iloc[attack_calibration_ix]],
                                 ignore_index=True)
    primary = new_model()
    primary.fit(frames['train'][features], frames['train']['label'])
    primary_threshold = threshold_at_fpr(primary.predict_proba(
        primary_calibration[features])[:, 1])
    bundle = {
        'dataset': name, 'run_kind': 'fresh_development_v1',
        'train_df': frames['train'], 'source_test_df': frames['source_test'],
        'normal_reference_df': normal_remaining,
        'primary_calibration_df': primary_calibration,
        'view_threshold_df': normal.iloc[threshold_ix].copy(),
        'normal_profile_fit_df': normal.iloc[fit_ix].copy(),
        'normal_profile_calibration_df': normal.iloc[calibration_ix].copy(),
        'known_reference_df': known_fit,
        'known_profile_calibration_df': known_calibration,
        'primary_model': primary, 'primary_features': features,
        'primary_threshold': primary_threshold, 'mutable_columns': mutable,
        'semantic_views': groups,
        'evaluation_domains': {key: frame for key, frame in frames.items()
                               if key.startswith('natural_')},
        'encoding': encoding,
    }
    joblib.dump(bundle, directory / f'{name}_bundle.joblib', compress=3)
    save_json(encoding, directory / 'training_only_encoding.json')
    save_json({'dataset': name, 'known_families': known, 'heldout_families': heldout,
               'views': groups, 'mutable_features': mutable,
               'primary_features': features, 'primary_threshold': primary_threshold,
               'schema_status': ('new_explicit_development_schema_not_provenance_verified'
                                 if name in ['CSE', 'NSL'] else 'notebook_development_schema'),
               'pool_seed': POOL_SEED, 'model_seed': MODEL_SEED,
               'split_design': 'fresh 50% train / 25% reference / 25% source test',
               'sampling': 'uniform random-priority capped sampling over complete input streams',
               'test_sampling': 'balanced capped development domains, not population accuracy',
               'warning': 'Not a restoration of old frozen models. Never pool with old results.'},
              directory / 'bootstrap_protocol.json')
    split_rows = []
    for key, frame in frames.items():
        split_rows.append({'dataset': name, 'split': key, 'rows': len(frame),
                           'attack_fraction': float(frame.label.mean()),
                           'row_ids_sha256': hashlib.sha256(
                               '\n'.join(sorted(frame._row_id)).encode()).hexdigest()})
    save_csv(split_rows, directory / 'split_manifest.csv')
    del raw, frames
    gc.collect()
    return bundle


def windows(n, seed=1002, bootstrap=False):
    rng = np.random.default_rng(seed)
    if bootstrap:
        return [rng.choice(n, WINDOW_SIZE, replace=False) for _ in range(REFERENCE_WINDOWS)]
    order = rng.permutation(n)
    return [order[start:start + WINDOW_SIZE]
            for start in range(0, n - WINDOW_SIZE + 1, WINDOW_SIZE)]


def signature_matrix(primary_p, view_p, threshold, view_thresholds, indices):
    result = []
    for ix in indices:
        primary_decision = primary_p[ix] > threshold
        decision = view_p[:, ix] > np.asarray(view_thresholds)[:, None]
        row = [primary_decision.mean(), np.maximum(primary_p[ix], 1-primary_p[ix]).mean()]
        for index in range(len(view_p)):
            row.extend([decision[index].mean(),
                        np.maximum(view_p[index, ix], 1-view_p[index, ix]).mean(),
                        (decision[index] == primary_decision).mean()])
        for left in range(len(view_p)):
            for right in range(left + 1, len(view_p)):
                row.append((decision[left] == decision[right]).mean())
        result.append(row)
    return np.asarray(result, dtype=float)


def build_partition_bank(bundle, groups):
    train = bundle['train_df']
    models, thresholds = {}, []
    screening = []
    for view, columns in groups.items():
        model = new_model()
        model.fit(train[columns], train.label)
        models[view] = model
        thresholds.append(threshold_at_fpr(model.predict_proba(
            bundle['view_threshold_df'][columns])[:, 1]))
        test = bundle['source_test_df']
        p = model.predict_proba(test[columns])[:, 1]
        screening.append({'view': view, 'features': len(columns),
                          'source_accuracy': accuracy_score(test.label, p > thresholds[-1]),
                          'source_balanced_accuracy': balanced_accuracy_score(
                              test.label, p > thresholds[-1])})
    bank = {'models': models, 'groups': groups, 'thresholds': thresholds, 'profiles': {}}
    for profile_name, fit_key, calibration_key in [
        ('normal', 'normal_profile_fit_df', 'normal_profile_calibration_df'),
        ('known', 'known_reference_df', 'known_profile_calibration_df')]:
        pp, vp = bank_probabilities(bundle, bank, bundle[fit_key])
        fit = signature_matrix(pp, vp, bundle['primary_threshold'], thresholds,
                               windows(len(pp), 1003, True))
        median = np.median(fit, axis=0)
        scale = np.maximum(1.4826*np.median(np.abs(fit-median), axis=0), 1/WINDOW_SIZE)
        pp, vp = bank_probabilities(bundle, bank, bundle[calibration_key])
        cal = signature_matrix(pp, vp, bundle['primary_threshold'], thresholds,
                               windows(len(pp), 1004, True))
        scores = np.mean(np.abs((cal-median)/scale), axis=1)
        bank['profiles'][profile_name] = (median, scale, max(float(np.quantile(scores, .95)), 1e-12))
    return bank, screening


def bank_probabilities(bundle, bank, frame):
    pp = bundle['primary_model'].predict_proba(frame[bundle['primary_features']])[:, 1]
    vp = np.vstack([bank['models'][view].predict_proba(frame[columns])[:, 1]
                    for view, columns in bank['groups'].items()])
    return pp, vp


def support_scores(bundle, bank, pp, vp, ix, two_profiles=False):
    sig = signature_matrix(pp, vp, bundle['primary_threshold'], bank['thresholds'], ix)
    scores = []
    for name in (['normal', 'known'] if two_profiles else ['normal']):
        median, scale, threshold = bank['profiles'][name]
        scores.append(np.mean(np.abs((sig-median)/scale), axis=1)/threshold)
    return np.min(np.vstack(scores), axis=0)


def make_attack(bundle, model, epsilon, sparse=False, attack_frame=None):
    train = bundle['train_df']
    test = bundle['source_test_df'] if attack_frame is None else attack_frame
    features = bundle['primary_features']
    coef = dict(zip(features, model.named_steps['classifier'].coef_[0]))
    scales = dict(zip(features, model.named_steps['scaler'].scale_))
    selected = list(bundle['mutable_columns'])
    if sparse:
        selected = sorted(selected, key=lambda column: abs(coef[column]), reverse=True)[:SPARSE_K]
    attacked = test.copy()
    y = test.label.to_numpy()
    for column in selected:
        original = test[column].to_numpy(dtype=float)
        finite_training = train[column].dropna().to_numpy(dtype=float)
        finite_training = finite_training[np.isfinite(finite_training)]
        mask = (y == 1) & np.isfinite(original)
        if not len(finite_training) or not mask.any():
            continue
        origin = original[mask]
        budget = float(epsilon * scales[column])
        qlow, qhigh = np.quantile(finite_training, [.001, .999])
        low = np.maximum(origin-budget, np.minimum(origin, qlow))
        high = np.minimum(origin+budget, np.maximum(origin, qhigh))
        candidate = np.clip(origin-budget*np.sign(coef[column]), low, high)
        if np.all(np.isclose(finite_training, np.round(finite_training), atol=1e-8)):
            rounded = np.round(candidate)
            candidate = np.where((rounded >= low) & (rounded <= high), rounded, origin)
        if np.any(np.abs(candidate-origin) > budget + 1e-7):
            raise AssertionError('Budget violation')
        modified = original.copy()
        modified[mask] = candidate
        attacked[column] = modified
    if not attacked.loc[y == 0].equals(test.loc[y == 0]):
        raise AssertionError('Benign records changed')
    return attacked, selected


def domain_auc(clean, attacked, features, seed):
    count = min(DOMAIN_ROWS, len(clean))
    ix = np.random.default_rng(seed).choice(len(clean), count, replace=False)
    a = clean.iloc[ix][features].to_numpy(dtype=float)
    b = attacked.iloc[ix][features].to_numpy(dtype=float)
    predicted = np.empty(2*count)
    y = np.r_[np.zeros(count), np.ones(count)]
    for train_ix, test_ix in KFold(3, shuffle=True, random_state=seed).split(np.arange(count)):
        model = new_model(seed)
        model.fit(np.vstack([a[train_ix], b[train_ix]]),
                  np.r_[np.zeros(len(train_ix)), np.ones(len(train_ix))])
        p = model.predict_proba(np.vstack([a[test_ix], b[test_ix]]))[:, 1]
        predicted[test_ix] = p[:len(test_ix)]
        predicted[count+test_ix] = p[len(test_ix):]
    return float(roc_auc_score(y, predicted))


def run_experiments(name, bundle, directory):
    features = bundle['primary_features']
    primary = bundle['primary_model']
    threshold = bundle['primary_threshold']
    test = bundle['source_test_df']
    y = test.label.to_numpy()
    ix = windows(len(test))
    clean_p = primary.predict_proba(test[features])[:, 1]
    clean_accuracy = float(((clean_p > threshold) == y).mean())
    clean_margin = float((np.abs(clean_p-threshold) <= MARGIN_WIDTH).mean())
    clean_window_accuracy = np.asarray([((clean_p[k] > threshold) == y[k]).mean() for k in ix])
    configurations = [('semantic', -1, bundle['semantic_views'])]
    union = sum(bundle['semantic_views'].values(), [])
    if len(union) != len(set(union)):
        raise ValueError('Overlapping views')
    for seed in PARTITION_SEEDS:
        shuffled = np.random.default_rng(seed).permutation(union)
        groups, start = {}, 0
        for index, columns in enumerate(bundle['semantic_views'].values()):
            groups[f'random_{index}'] = shuffled[start:start+len(columns)].tolist()
            start += len(columns)
        configurations.append(('random', seed, groups))
    banks, schema_rows, quality_rows, resources = [], [], [], []
    for method, seed, groups in configurations:
        bank, screening = build_partition_bank(bundle, groups)
        banks.append((method, seed, bank))
        joblib.dump(bank, directory/f'partition_bank_{method}_{seed}.joblib', compress=3)
        if method == 'semantic':
            bundle['view_models'] = bank['models']
            bundle['view_thresholds'] = bank['thresholds']
            bundle['profiles'] = bank['profiles']
            joblib.dump(bundle, directory/f'{name}_bundle.joblib', compress=3)
        for row in screening:
            quality_rows.append({'dataset': name, 'method': method, 'partition_seed': seed, **row})
        for view, columns in groups.items():
            for column in columns:
                schema_rows.append({'method': method, 'partition_seed': seed,
                                    'view': view, 'feature': column})
        sample = test.iloc[:min(1000, len(test))]
        bank_probabilities(bundle, bank, sample)
        timings = []
        for _ in range(3):
            start = time.perf_counter()
            bank_probabilities(bundle, bank, sample)
            timings.append(time.perf_counter()-start)
        parameter_count = sum(model.named_steps['classifier'].coef_.size +
                              model.named_steps['classifier'].intercept_.size
                              for model in bank['models'].values())
        resources.append({'dataset': name, 'method': method, 'partition_seed': seed,
                          'view_trainable_parameters': parameter_count,
                          'coefficient_float32_bytes': 4*parameter_count,
                          'primary_plus_views_ms_per_1000':
                              1000*np.median(timings)*1000/len(sample)})
    save_csv(quality_rows, directory/'view_screening.csv')
    save_csv(resources, directory/'resource_measurements.csv')
    save_csv(schema_rows, directory/'partition_schemas.csv')
    baseline_rows, window_rows, risk_rows, decision_rows, natural_rows = [], [], [], [], []
    estimator_rows, attribution_rows, adaptive_candidates, adaptive_selected = [], [], [], []
    clean_estimator_error = {}
    semantic_bank = next(bank for method, _, bank in banks if method == 'semantic')
    reference_frame = bundle['known_reference_df']
    reference_primary, reference_views = bank_probabilities(bundle, semantic_bank, reference_frame)
    reference_y = reference_frame.label.to_numpy()
    reference_view_decisions = reference_views > np.asarray(semantic_bank['thresholds'])[:, None]
    reference_positive_rates = reference_view_decisions.mean(axis=1)
    reference_rate_deviations = np.asarray([
        np.abs(reference_view_decisions[:, index].mean(axis=1)-reference_positive_rates)
        for index in windows(len(reference_frame), 1006, True)])
    attribution_thresholds = np.maximum(np.quantile(reference_rate_deviations, .95, axis=0), 1/WINDOW_SIZE)

    def evaluate(frame, condition, attack_seed, paired=True, modified_columns=None):
        pp = primary.predict_proba(frame[features])[:, 1]
        labels = frame.label.to_numpy()
        indices = ix if paired else windows(len(frame))
        accuracy = np.asarray([((pp[k] > threshold) == labels[k]).mean() for k in indices])
        damage = clean_window_accuracy-accuracy if paired else np.full(len(indices), np.nan)
        rankings = [('primary_confidence_window', -1,
                     np.asarray([-np.maximum(pp[k], 1-pp[k]).mean() for k in indices]))]
        for method, partition_seed, bank in banks:
            bp, vp = bank_probabilities(bundle, bank, frame)
            normal_score = support_scores(bundle, bank, bp, vp, indices)
            rankings.append((method, partition_seed, normal_score))
            if method == 'semantic':
                scores = support_scores(bundle, bank, bp, vp, indices, two_profiles=True)
                current_view_decisions = vp > np.asarray(bank['thresholds'])[:, None]
                for wid, index in enumerate(indices):
                    estimates = estimated_accuracy_values(
                        bp[index], vp[:, index], threshold, bank['thresholds'],
                        reference_primary, reference_views, reference_y)
                    for estimator, estimate in estimates.items():
                        error = estimate-accuracy[wid]
                        if condition == 'clean_source':
                            clean_estimator_error[(estimator, wid)] = error
                        differential = (error-clean_estimator_error[(estimator, wid)]
                                        if paired else np.nan)
                        estimator_rows.append({
                            'dataset': name, 'condition': condition, 'attack_seed': attack_seed,
                            'window': wid, 'estimator': estimator,
                            'estimated_accuracy': estimate, 'true_accuracy': float(accuracy[wid]),
                            'signed_error': float(error),
                            'differential_absolute_error': float(abs(differential)) if paired else np.nan})
                    if modified_columns is not None:
                        deviations = np.abs(current_view_decisions[:, index].mean(axis=1)-reference_positive_rates)
                        for view_index, (view, columns) in enumerate(bank['groups'].items()):
                            exposed = bool(set(columns) & set(modified_columns))
                            attribution_rows.append({
                                'dataset': name, 'condition': condition, 'attack_seed': attack_seed,
                                'window': wid, 'view': view,
                                'feature_group_exposed': int(exposed),
                                'suspect': int(deviations[view_index] > attribution_thresholds[view_index]),
                                'absolute_positive_rate_deviation': float(deviations[view_index]),
                                'interpretation': 'Feature-exposure diagnostic, not causal attribution'})
                for wid, score in enumerate(scores):
                    decision_rows.append({'dataset': name, 'condition': condition,
                                          'attack_seed': attack_seed, 'window': wid,
                                          'support_score': float(score),
                                          'abstain': int(score > 1),
                                          'accuracy': float(accuracy[wid]),
                                          'damage': float(damage[wid]),
                                          'damage_ge_5pp': (int(damage[wid] >= .05) if paired else np.nan)})
                natural_rows.append({'dataset': name, 'condition': condition,
                                     'attack_seed': attack_seed,
                                     'primary_accuracy': float(accuracy.mean()),
                                     'trusted_coverage': float((scores <= 1).mean()),
                                     'trusted_risk': (float(1-accuracy[scores <= 1].mean())
                                                      if (scores <= 1).any() else np.nan),
                                     'abstain_rate': float((scores > 1).mean())})
        for method, partition_seed, scores in rankings:
            for wid, score in enumerate(scores):
                window_rows.append({'dataset': name, 'condition': condition,
                                    'attack_seed': attack_seed, 'method': method,
                                    'partition_seed': partition_seed, 'window': wid,
                                    'ranking_score': float(score),
                                    'primary_accuracy': float(accuracy[wid]),
                                    'paired_window_damage': float(damage[wid])})
            ranking = np.argsort(scores, kind='stable')
            for coverage in COVERAGES:
                count = max(1, int(np.ceil(coverage*len(ranking))))
                kept = ranking[:count]
                risk_rows.append({'dataset': name, 'condition': condition,
                                  'attack_seed': attack_seed, 'method': method,
                                  'partition_seed': partition_seed, 'target_coverage': coverage,
                                  'actual_coverage': count/len(ranking),
                                  'trusted_risk': float(1-accuracy[kept].mean()),
                                  'mean_damage_all_windows': float(damage.mean()) if paired else np.nan,
                                  'mean_damage_kept_windows': float(damage[kept].mean()) if paired else np.nan})

    evaluate(test, 'clean_source', -1)
    for domain, frame in bundle['evaluation_domains'].items():
        if len(frame) >= WINDOW_SIZE:
            evaluate(frame, domain, -1, paired=False)
    for seed in ATTACK_SEEDS:
        train = bundle['train_df']
        rng = np.random.default_rng(seed)
        selected = []
        for label in [0, 1]:
            available = np.flatnonzero(train.label.to_numpy() == label)
            selected.extend(rng.choice(available,
                max(1, int(SURROGATE_FRACTION*len(available))), replace=False))
        surrogate = new_model(seed)
        subset = train.iloc[selected]
        surrogate.fit(subset[features], subset.label)
        for attack_name in ['whitebox_primary', 'genuine_surrogate_transfer', 'sparse_surrogate_transfer']:
            model = primary if attack_name == 'whitebox_primary' else surrogate
            for epsilon in EPSILONS:
                attacked, columns = make_attack(bundle, model, epsilon,
                    sparse=attack_name == 'sparse_surrogate_transfer')
                probability = primary.predict_proba(attacked[features])[:, 1]
                accuracy = float(((probability > threshold) == y).mean())
                margin = float((np.abs(probability-threshold) <= MARGIN_WIDTH).mean())
                auc = domain_auc(test, attacked, features, seed)
                baseline_rows.append({'dataset': name, 'attack': attack_name,
                                      'epsilon': epsilon, 'attack_seed': seed,
                                      'clean_accuracy': clean_accuracy,
                                      'attacked_accuracy': accuracy,
                                      'true_damage': clean_accuracy-accuracy,
                                      'margin_density_change': margin-clean_margin,
                                      'domain_auc': auc, 'attack_columns': '|'.join(columns)})
                evaluate(attacked, f'{attack_name}_eps_{epsilon:.2f}', seed, modified_columns=columns)
                save_csv(baseline_rows, directory/'e9_results.csv')
                save_csv(risk_rows, directory/'e10_matched_coverage.csv')
                save_csv(window_rows, directory/'e10_window_results.csv')
                save_csv(decision_rows, directory/'decision_windows.csv')
                save_csv(natural_rows, directory/'clean_natural_attack_selectivity.csv')
                save_csv(estimator_rows, directory/'estimator_window_results.csv')
                save_csv(attribution_rows, directory/'view_exposure_diagnostics.csv')
                print(name, attack_name, f'eps={epsilon}', f'seed={seed}',
                      f'damage={clean_accuracy-accuracy:.4f}', f'domain_auc={auc:.4f}', flush=True)
                del attacked
                gc.collect()
        # E8 finite-grid adaptive selection uses a labeled reference-calibration
        # partition, never the evaluation test labels. No gradient-free claim.
        selection_frame = bundle['known_profile_calibration_df']
        selection_y = selection_frame.label.to_numpy()
        selection_ix = windows(len(selection_frame))
        selection_pp, selection_vp = bank_probabilities(bundle, semantic_bank, selection_frame)
        selection_accuracy = float(((selection_pp > threshold) == selection_y).mean())
        for epsilon in [.25, .50]:
            candidate_settings = []
            for scale in np.linspace(0, 1, 11):
                candidate_frame, candidate_columns = make_attack(
                    bundle, surrogate, epsilon*scale, attack_frame=selection_frame)
                candidate_pp, candidate_vp = bank_probabilities(bundle, semantic_bank, candidate_frame)
                candidate_accuracy = float(((candidate_pp > threshold) == selection_y).mean())
                candidate_scores = support_scores(bundle, semantic_bank, candidate_pp,
                                                 candidate_vp, selection_ix, two_profiles=True)
                record = {
                    'dataset': name, 'attack_seed': seed, 'epsilon': epsilon,
                    'scale': float(scale), 'selection_damage': selection_accuracy-candidate_accuracy,
                    'selection_trusted_coverage': float((candidate_scores <= 1).mean())}
                candidate_settings.append(record)
                adaptive_candidates.append(record)
            for lambda_value in [0., .25, 1.]:
                chosen = max(candidate_settings, key=lambda row:
                    row['selection_damage'] + lambda_value*row['selection_trusted_coverage'])
                adaptive_frame, columns = make_attack(bundle, surrogate, epsilon*chosen['scale'])
                p, v = bank_probabilities(bundle, semantic_bank, adaptive_frame)
                scores = support_scores(bundle, semantic_bank, p, v, ix, two_profiles=True)
                accuracy = float(((p > threshold) == y).mean())
                adaptive_selected.append({
                    **chosen, 'lambda': lambda_value,
                    'test_damage': clean_accuracy-accuracy,
                    'test_trusted_coverage': float((scores <= 1).mean()),
                    'selection_scope': 'Reference-calibration labels only; test used once per fixed setting',
                    'attack_scope': 'Finite-grid surrogate-direction adaptive development attack'})
                evaluate(adaptive_frame,
                         f'adaptive_grid_eps_{epsilon:.2f}_lambda_{lambda_value:.2f}',
                         seed, modified_columns=columns)
            save_csv(adaptive_candidates, directory/'e8_selection_candidates.csv')
            save_csv(adaptive_selected, directory/'e8_test_frontier.csv')
            print(name, f'adaptive-grid seed={seed} epsilon={epsilon} complete', flush=True)
    save_csv(window_rows, directory/'e10_window_results.csv')
    save_csv(risk_rows, directory/'e10_matched_coverage.csv')
    save_csv(decision_rows, directory/'decision_windows.csv')
    save_csv(natural_rows, directory/'clean_natural_attack_selectivity.csv')
    save_csv(estimator_rows, directory/'estimator_window_results.csv')
    save_csv(attribution_rows, directory/'view_exposure_diagnostics.csv')
    estimator_summary = pd.DataFrame(estimator_rows).groupby(
        ['dataset', 'condition', 'estimator']).agg(
            estimated_accuracy=('estimated_accuracy', 'mean'),
            true_accuracy=('true_accuracy', 'mean'),
            signed_error=('signed_error', 'mean'),
            differential_absolute_error=('differential_absolute_error', 'mean')).reset_index()
    save_csv(estimator_summary, directory/'estimator_summary.csv')
    if attribution_rows:
        attribution = pd.DataFrame(attribution_rows)
        attribution['tp'] = ((attribution.suspect == 1) & (attribution.feature_group_exposed == 1)).astype(int)
        attribution['fp'] = ((attribution.suspect == 1) & (attribution.feature_group_exposed == 0)).astype(int)
        attribution['fn'] = ((attribution.suspect == 0) & (attribution.feature_group_exposed == 1)).astype(int)
        totals = attribution.groupby(['dataset','condition'])[['tp','fp','fn']].sum().reset_index()
        totals['exposure_precision'] = totals.tp/(totals.tp+totals.fp).replace(0,np.nan)
        totals['exposure_recall'] = totals.tp/(totals.tp+totals.fn).replace(0,np.nan)
        save_csv(totals, directory/'view_exposure_summary.csv')
    result = pd.DataFrame(baseline_rows)
    summary = result.groupby(['dataset', 'attack', 'epsilon']).agg(
        repetitions=('attack_seed', 'nunique'), true_damage=('true_damage', 'mean'),
        damage_std=('true_damage', 'std'), attacked_accuracy=('attacked_accuracy', 'mean'),
        margin_density_change=('margin_density_change', 'mean'), domain_auc=('domain_auc', 'mean')).reset_index()
    save_csv(summary, directory/'e9_summary.csv')
    risk = pd.DataFrame(risk_rows)
    summary = risk.groupby(['dataset', 'condition', 'method', 'target_coverage']).agg(
        actual_coverage=('actual_coverage', 'mean'), trusted_risk=('trusted_risk', 'mean'),
        mean_damage_all_windows=('mean_damage_all_windows', 'mean'),
        mean_damage_kept_windows=('mean_damage_kept_windows', 'mean')).reset_index()
    save_csv(summary, directory/'e10_summary.csv')
    decisions = pd.DataFrame(decision_rows)
    paired = decisions[decisions['damage_ge_5pp'].notna()]
    detection_auc = (float(roc_auc_score(paired.damage_ge_5pp, paired.support_score))
                     if paired.damage_ge_5pp.nunique() == 2 else None)
    save_json({'window_damage_auroc': detection_auc,
               'interpretation': 'Descriptive pooled window diagnostic; no independent-run CI',
               'reference_windows': 'Overlapping bootstrap windows; not independent samples',
               'matched_coverage': 'Ranking analysis, not deployable threshold calibration',
               'attack_repetitions': 'Surrogate subset seeds, not primary-model replications',
               'constraints': 'Range/type feature-space only; derived statistics not recomputed',
               'heldout': 'Development domains only, not untouched confirmatory evidence'},
              directory/'evaluation_limitations.json')
    return bundle



def estimated_accuracy_values(primary_p, view_p, threshold, view_thresholds,
                              reference_primary, reference_views, reference_y):
    decision = primary_p > threshold
    view_decision = view_p > np.asarray(view_thresholds)[:, None]
    reference_decision = reference_primary > threshold
    reference_view_decision = reference_views > np.asarray(view_thresholds)[:, None]
    reference_accuracy = float((reference_decision == reference_y).mean())
    confidence = np.maximum(primary_p, 1-primary_p)
    reference_confidence = np.maximum(reference_primary, 1-reference_primary)
    competence = np.clip((reference_view_decision == reference_y).mean(axis=1), .51, .99)
    competence_weights = np.maximum(np.log(competence/(1-competence)), .05)
    drift = reference_view_decision.mean(axis=1)-view_decision.mean(axis=1)
    low = drift[drift <= np.median(drift)]
    robust_scale = max(.02, 2*1.4826*np.median(np.abs(low-np.median(low))))
    excess = np.maximum(drift-np.quantile(drift, .20), 0)
    drift_weights = np.exp(-np.minimum((excess/robust_scale)**2, 50))
    def vote_agreement(weights):
        voted = np.average(view_decision.astype(float), axis=0, weights=weights) > .5
        return float((decision == voted).mean())
    return {
        'AC': float(confidence.mean()),
        'DoC': float(np.clip(reference_accuracy + confidence.mean()-reference_confidence.mean(), 0, 1)),
        'ATC': float((confidence >= np.quantile(reference_confidence, 1-reference_accuracy)).mean()),
        'primary_view_agreement_proxy': float((view_decision == decision).mean()),
        'MAJ_primary_agreement': vote_agreement(np.ones(len(view_p))),
        'WACC_primary_agreement': vote_agreement(competence_weights),
        'DRIFTONLY_primary_agreement': vote_agreement(drift_weights),
        'ANCH_primary_agreement': vote_agreement(competence_weights*drift_weights),
    }

def main():
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    statuses, registry = [], {}
    config = {key: globals()[key] for key in [
        'DATASETS', 'POOL_SEED', 'MODEL_SEED', 'ATTACK_SEEDS', 'PARTITION_SEEDS',
        'EPSILONS', 'SPARSE_K', 'SURROGATE_FRACTION', 'WINDOW_SIZE', 'REFERENCE_WINDOWS',
        'DOMAIN_ROWS', 'COVERAGES', 'MARGIN_WIDTH', 'TARGET_FPR', 'CAP_BENIGN',
        'CAP_ATTACK_PER_FAMILY', 'MAX_ATTACK_TOTAL', 'MIN_FAMILY_ROWS', 'SOURCE_FRACTION',
        'IOT_SCHEMAS', 'TON_SCHEMA', 'NSL_SCHEMA', 'CSE_SCHEMA', 'MUTABLE_ALIASES']}
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    configuration_path = OUTPUT_ROOT/'run_configuration.json'
    if configuration_path.exists():
        previous_config = json.loads(configuration_path.read_text())
        if previous_config['configuration_sha256'] != digest:
            raise RuntimeError('Settings changed: use a NEW OUTPUT_ROOT, not the previous run directory.')
    save_json({'configuration_sha256': digest, 'settings': config}, configuration_path)
    previous_status_path = OUTPUT_ROOT/'dataset_status.csv'
    previous_status = (pd.read_csv(previous_status_path).fillna('')
                       if previous_status_path.exists() else pd.DataFrame())
    for name in DATASETS:
        directory = OUTPUT_ROOT/name
        directory.mkdir(parents=True, exist_ok=True)
        bundle_path = directory/f'{name}_bundle.joblib'
        try:
            completed = (not previous_status.empty
                         and ((previous_status.dataset == name)
                              & (previous_status.status == 'IMPLEMENTED_SUITE_COMPLETE')).any())
            required_outputs = ['e9_summary.csv', 'e10_summary.csv', 'e8_test_frontier.csv',
                                'estimator_summary.csv', 'partition_bank_semantic_-1.joblib']
            if (completed and RESUME_COMPLETED_DATASETS and not FORCE_REBUILD
                    and bundle_path.exists()
                    and all((directory/file).exists() for file in required_outputs)):
                registry[name] = joblib.load(bundle_path)
                statuses.append({'dataset': name, 'status': 'IMPLEMENTED_SUITE_COMPLETE',
                                 'detail': 'Reused completed matching-configuration run'})
                save_csv(statuses, OUTPUT_ROOT/'dataset_status.csv')
                print(f'{name}: already completed; skipped rerun', flush=True)
                continue
            print('\n'+'='*90+'\nREBUILD/RUN '+name+'\n'+'='*90, flush=True)
            bundle = (joblib.load(bundle_path) if bundle_path.exists() and not FORCE_REBUILD
                      else rebuild_bundle(name, directory))
            registry[name] = bundle
            if RUN_EXPERIMENTS:
                run_experiments(name, bundle, directory)
            statuses.append({'dataset': name,
                             'status': 'IMPLEMENTED_SUITE_COMPLETE' if RUN_EXPERIMENTS else 'BUNDLE_REBUILT',
                             'detail': ''})
        except Exception as error:
            statuses.append({'dataset': name, 'status': 'FAILED', 'detail': str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(f'{name}: FAILED: {error}', flush=True)
        save_csv(statuses, OUTPUT_ROOT/'dataset_status.csv')
    for filename in ['e9_summary.csv', 'e10_summary.csv', 'view_screening.csv',
                     'resource_measurements.csv', 'clean_natural_attack_selectivity.csv',
                     'estimator_summary.csv', 'e8_test_frontier.csv', 'view_exposure_summary.csv']:
        tables = [pd.read_csv(OUTPUT_ROOT/row['dataset']/filename)
                  for row in statuses if row['status'] == 'IMPLEMENTED_SUITE_COMPLETE'
                  and (OUTPUT_ROOT/row['dataset']/filename).exists()]
        if tables:
            save_csv(pd.concat(tables, ignore_index=True), OUTPUT_ROOT/f'all_datasets_{filename}')
    ledger = []
    for row in statuses:
        for task in ['raw_loading_and_disjoint_splits', 'primary_model_and_threshold',
                     'persistent_dataset_bundle', 'semantic_view_quality',
                     'clean_and_natural_shift_selectivity', 'whitebox_transfer_sparse_attacks',
                     'margin_density_proxy_and_domain_auc', 'semantic_random_confidence_ablation',
                     'resource_measurements', 'conditional_estimator_ablation_diagnostics',
                     'finite_grid_adaptive_attack', 'view_feature_exposure_diagnostics']:
            is_bootstrap = task in ['raw_loading_and_disjoint_splits', 'primary_model_and_threshold',
                                    'persistent_dataset_bundle']
            done = row['status'] == 'IMPLEMENTED_SUITE_COMPLETE' or (
                row['status'] == 'BUNDLE_REBUILT' and is_bootstrap)
            ledger.append({'dataset': row['dataset'], 'task': task,
                           'status': 'COMPLETE_DEVELOPMENT' if done else 'NOT_COMPLETE'})
        for task in ['actual_published_MD3', 'exact_published_gradient_estimator',
                     'primitive_recomputation_and_packet_validity',
                     'hard_gate_SPSA_NES_adaptive_verification',
                     'exact_agreement_regression_and_published_baseline_replication',
                     'seed_pair_clustered_confirmation_and_Holm',
                     'independent_fifth_dataset_boundary_test',
                     'GBDT_MLP_model_family_replication', 'formal_identifiability_proof']:
            ledger.append({'dataset': row['dataset'], 'task': task, 'status': 'NOT_IMPLEMENTED'})
    save_csv(ledger, OUTPUT_ROOT/'completion_ledger.csv')
    print('\nDATASET STATUS\n'+pd.DataFrame(statuses).to_string(index=False), flush=True)
    print('\nOther study requirements remain visible in completion_ledger.csv; no full-study completion claim.')
    return registry


if __name__ == '__main__':
    DATASET_BUNDLES = main()
