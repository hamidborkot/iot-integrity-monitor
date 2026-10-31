# =============================================================================
# TON_IoT SEMANTIC-PROVENANCE EXPERIMENT -- self-contained, resumable
# This is the first FINAL semantic-view experiment. It does not reuse random views.
# It writes all results to /kaggle/working/ton_semantic_results/.
# Run RUN="smoke" first; then RUN="development"; after protocol freeze RUN="confirm".
# =============================================================================
import os, json, time, hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.metrics import roc_auc_score, roc_curve

RUN = "smoke"                       # "smoke" | "development" | "confirm"
SEEDS = [0] if RUN == "smoke" else ([0, 1, 2] if RUN == "development" else [10, 11, 12])
POOL_SEED = 0 if RUN != "confirm" else 1
CSV = Path('/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network/TON_IoT_Train_Test_Network.csv')
OUT = Path('/kaggle/working/ton_semantic_results')
OUT.mkdir(parents=True, exist_ok=True)

# Frozen semantic provenance schema: do not change after running development.
# Metadata is excluded. Context channels are evidence but immutable for one fixed flow.
SCHEMA = {
    'context_state': {
        'columns': ['proto', 'service', 'conn_state'],
        'kind': 'categorical', 'mutable': False,
        'rule': 'Protocol, service and connection state are immutable for a fixed flow.'},
    'volume_timing': {
        'columns': ['duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts', 'dst_pkts'],
        'kind': 'numeric', 'mutable': True,
        'rule': 'Nonnegative; duration continuous; byte and packet counts nonnegative integers.'},
    'dns_evidence': {
        'columns': ['dns_query', 'dns_qclass', 'dns_qtype', 'dns_rcode', 'dns_AA', 'dns_RD', 'dns_RA', 'dns_rejected'],
        'kind': 'mixed', 'mutable': False,
        'rule': 'DNS transaction evidence is not altered in a flow-summary attack.'},
    'tls_evidence': {
        'columns': ['ssl_version', 'ssl_cipher', 'ssl_resumed', 'ssl_established', 'ssl_subject', 'ssl_issuer'],
        'kind': 'categorical', 'mutable': False,
        'rule': 'TLS handshake evidence is immutable for a completed flow.'},
    'http_evidence': {
        'columns': ['http_trans_depth', 'http_method', 'http_uri', 'http_version', 'http_request_body_len', 'http_response_body_len', 'http_status_code', 'http_user_agent', 'http_orig_mime_types', 'http_resp_mime_types'],
        'kind': 'mixed', 'mutable': False,
        'rule': 'HTTP application evidence is immutable in this restricted attack model.'},
    'anomaly_evidence': {
        'columns': ['weird_name', 'weird_addl', 'weird_notice'],
        'kind': 'categorical', 'mutable': False,
        'rule': 'Zeek weird-event evidence is immutable for a completed flow.'},
}
METADATA = ['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'label', 'type']
SOURCE_ATTACKS = ['scanning', 'dos', 'ddos', 'password']
HELDOUT_ATTACKS = ['injection', 'xss', 'ransomware', 'backdoor', 'mitm']
MAX_TRAIN_PER_CLASS = 50000 if RUN != 'smoke' else 5000
MAX_TEST_NORMAL = 50000 if RUN != 'smoke' else 5000
EPOCHS = 8 if RUN != 'smoke' else 3
EPS = [0.10, 0.25, 0.50] if RUN != 'smoke' else [0.50]
STEPS = 20 if RUN != 'smoke' else 8
BATCH = 512

if not CSV.exists():
    raise FileNotFoundError(f'TON_IoT CSV not found: {CSV}')

# ----------------------------- utilities -----------------------------
def cap(df, n, seed):
    return df.sample(min(n, len(df)), random_state=seed).copy()

def split_cols(df, cols):
    cols = [c for c in cols if c in df.columns]
    num = [c for c in cols if pd.api.types.is_numeric_dtype(df[c])]
    cat = [c for c in cols if c not in num]
    return num, cat

class ViewNet(nn.Module):
    def __init__(self, d):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(d, 32), nn.ReLU(), nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 1))
    def forward(self, x):
        return self.net(x).squeeze(-1)

def fit_view(train_df, val_df, test_df, spec, seed):
    num, cat = split_cols(train_df, spec['columns'])
    parts_train, parts_val, parts_test = [], [], []
    scaler = None; enc = None
    if num:
        scaler = StandardScaler().fit(train_df[num].fillna(0))
        parts_train.append(scaler.transform(train_df[num].fillna(0)))
        parts_val.append(scaler.transform(val_df[num].fillna(0)))
        parts_test.append(scaler.transform(test_df[num].fillna(0)))
    if cat:
        enc = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        trc = train_df[cat].fillna('-').astype(str)
        vac = val_df[cat].fillna('-').astype(str)
        tec = test_df[cat].fillna('-').astype(str)
        enc.fit(trc)
        parts_train.append(enc.transform(trc)); parts_val.append(enc.transform(vac)); parts_test.append(enc.transform(tec))
    Xtr = np.hstack(parts_train).astype('float32')
    Xva = np.hstack(parts_val).astype('float32')
    Xte = np.hstack(parts_test).astype('float32')
    return Xtr, Xva, Xte, num, cat, scaler, enc

def train_model(X, y, seed):
    torch.manual_seed(seed)
    model = ViewNet(X.shape[1]); opt = torch.optim.Adam(model.parameters(), lr=3e-3, weight_decay=1e-4)
    xt, yt = torch.tensor(X), torch.tensor(y.values.astype('float32'))
    lossf = nn.BCEWithLogitsLoss()
    for _ in range(EPOCHS):
        idx = torch.randperm(len(xt))
        for i in range(0, len(xt), BATCH):
            j = idx[i:i+BATCH]; opt.zero_grad(); lossf(model(xt[j]), yt[j]).backward(); opt.step()
    return model.eval()

@torch.no_grad()
def pred(model, X):
    return torch.sigmoid(model(torch.tensor(X, dtype=torch.float32))).numpy()

def view_estimate(Pref, yref, Pcur):
    # drift-gated leave-one-view-out agreement estimator
    rate_ref = (Pref > .5).mean(1)
    rate_cur = (Pcur > .5).mean(1)
    drift = rate_ref - rate_cur
    excess = np.maximum(drift - np.quantile(drift, .2), 0)
    weights = np.exp(-(excess / .05)**2)
    votes = (Pcur > .5).astype(int)
    est = []
    for i in range(len(votes)):
        others = np.delete(votes, i, axis=0)
        ow = np.delete(weights, i)
        pseudo = ((ow[:,None] * others).sum(0) >= .5 * ow.sum()).astype(int)
        est.append((votes[i] == pseudo).mean())
    return np.array(est), weights, drift

def apply_constraints(Xadv, Xbase, mutable_idx, int_idx, lo, hi):
    Xadv = torch.maximum(torch.minimum(Xadv, hi), lo)
    mask = torch.zeros(Xadv.shape[1], dtype=torch.bool); mask[mutable_idx] = True
    Xadv[:, ~mask] = Xbase[:, ~mask]
    if len(int_idx): Xadv[:, int_idx] = torch.round(Xadv[:, int_idx])
    Xadv = torch.maximum(torch.minimum(Xadv, hi), lo)
    Xadv[:, ~mask] = Xbase[:, ~mask]
    return Xadv

def semantic_pgd(models, Xviews, y, mutable_view, eps, seed, monitor_mu=0.0, pref=None, yref=None):
    # Attack only volume_timing. All other semantic evidence views remain immutable.
    torch.manual_seed(seed)
    X0 = Xviews[mutable_view].clone(); X = X0.clone(); y = torch.tensor(y.values.astype('float32'))
    m = models[mutable_view]; lo = X0.min(0).values; hi = X0.max(0).values
    names = SCHEMA[mutable_view]['columns']
    int_idx = [i for i, n in enumerate(names) if n != 'duration']
    mutable_idx = list(range(X0.shape[1]))
    attack_rows = torch.where(y == 1)[0]
    step = eps / STEPS * 2.0
    lossf = nn.BCEWithLogitsLoss()
    # Fixed outputs of immutable evidence views.
    fixed = []
    with torch.no_grad():
        for name, mod in models.items():
            if name != mutable_view: fixed.append(torch.sigmoid(mod(Xviews[name])))
    for _ in range(STEPS):
        X.requires_grad_(True)
        p_mut = torch.sigmoid(m(X))
        Pall = torch.stack(fixed + [p_mut])
        damage = lossf(m(X)[attack_rows], y[attack_rows])
        if monitor_mu > 0 and pref is not None:
            rate_ref = torch.tensor((pref > .5).mean(1), dtype=torch.float32)
            rate_cur = torch.sigmoid(10*(Pall-.5)).mean(1)
            drift = rate_ref - rate_cur
            w = torch.exp(-(torch.relu(drift - torch.quantile(drift,.2))/.05)**2)
            vv = 2*Pall - 1
            total = (w[:,None]*vv).sum(0, keepdim=True) - w[:,None]*vv
            soft_est = torch.sigmoid(10*vv*total).mean()
            damage = damage - monitor_mu*(soft_est - float(np.mean(view_estimate(pref,yref,pref)[0])))**2
        grad, = torch.autograd.grad(damage, X)
        X = (X.detach() + step*grad.sign()).clamp(X0-eps, X0+eps)
        X = apply_constraints(X, X0, mutable_idx, int_idx, lo, hi)
    return X.detach()

def bootstrap_ci(x, n=5000, seed=0):
    x = np.asarray(x); rng = np.random.default_rng(seed)
    if len(x) < 2: return (np.nan,np.nan)
    means = rng.choice(x, size=(n,len(x)), replace=True).mean(1)
    return tuple(np.quantile(means,[.025,.975]))

# ----------------------------- load and define held-out attack families -----------------------------
df = pd.read_csv(CSV, low_memory=False)
df['type'] = df['type'].astype(str).str.lower().str.strip()
df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)

normal = df[df['label'] == 0]
source = df[df['type'].isin(SOURCE_ATTACKS)]
heldout = df[df['type'].isin(HELDOUT_ATTACKS)]
if len(source) == 0 or len(heldout) == 0:
    raise RuntimeError('Attack-family split is empty. Check available type values: ' + str(df.type.value_counts().head(20).to_dict()))

print('TON_IoT source-family training attacks:', source.type.value_counts().to_dict())
print('TON_IoT held-out testing attacks:', heldout.type.value_counts().to_dict())
print('Normal records:', len(normal))

all_results = []
for seed in SEEDS:
    rng = np.random.default_rng(seed)
    # Train/validation are normal + source attack families. Test is normal + unseen attack families.
    ntr = cap(normal, MAX_TRAIN_PER_CLASS, seed)
    atr = cap(source, MAX_TRAIN_PER_CLASS, seed)
    train_all = pd.concat([ntr, atr]).sample(frac=1, random_state=seed).reset_index(drop=True)
    split = int(.8*len(train_all)); train_df, val_df = train_all.iloc[:split], train_all.iloc[split:]
    test_df = pd.concat([cap(normal.drop(ntr.index, errors='ignore'), MAX_TEST_NORMAL, seed+99), heldout]).sample(frac=1, random_state=seed+99).reset_index(drop=True)

    models, Xval, Xtest, meta = {}, {}, {}, {}
    for i,(name,spec) in enumerate(SCHEMA.items()):
        Xtr, Xva, Xte, num, cat, scaler, enc = fit_view(train_df, val_df, test_df, spec, seed)
        if Xtr.shape[1] == 0: continue
        models[name] = train_model(Xtr, train_df.label, seed*100+i)
        Xval[name], Xtest[name] = torch.tensor(Xva), torch.tensor(Xte)
        meta[name] = dict(num=num, cat=cat, scaler=scaler, enc=enc, dim=Xtr.shape[1])

    # Reference and clean held-out predictions.
    Pref = np.stack([pred(m, Xval[n]) for n,m in models.items()])
    Pclean = np.stack([pred(m, Xtest[n]) for n,m in models.items()])
    yv, yt = val_df.label, test_df.label
    est_ref, _, _ = view_estimate(Pref, yv, Pref)
    clean_true = ((Pclean>.5).astype(int) == yt.values).mean(1)

    # Volume/timing attack; semantic attribution ground truth is volume_timing.
    if 'volume_timing' not in models:
        raise RuntimeError('volume_timing view unavailable. Check semantic schema.')

    for eps in EPS:
        for attack_name, mu in [('constrained_whitebox',0.0), ('estimator_aware_mu30',30.0), ('estimator_aware_mu300',300.0)]:
            Xadv = semantic_pgd(models, Xtest, yt, 'volume_timing', eps, seed, mu, Pref, yv)
            Padv = []
            for name, model in models.items():
                Xin = Xadv if name == 'volume_timing' else Xtest[name]
                Padv.append(pred(model, Xin))
            Padv = np.stack(Padv)
            est, weights, drift = view_estimate(Pref, yv, Padv)
            true = ((Padv>.5).astype(int) == yt.values).mean(1)
            damage = clean_true.mean() - true.mean()
            estimate_error = abs((est.mean()-true.mean()) - (est_ref.mean()-clean_true.mean()))
            suspect = list(models.keys())[int(np.argmin(weights))]
            attribution_correct = int(suspect == 'volume_timing')
            all_results.append(dict(seed=seed, eps=eps, attack=attack_name, clean_accuracy=clean_true.mean(), attacked_accuracy=true.mean(),
                                    damage=damage, estimated_accuracy=est.mean(), differential_error=estimate_error,
                                    suspect_view=suspect, attribution_correct=attribution_correct,
                                    min_weight=float(weights.min()), volume_weight=float(weights[list(models.keys()).index('volume_timing')]),
                                    n_views=len(models), model_params=sum(sum(p.numel() for p in m.parameters()) for m in models.values())))

res = pd.DataFrame(all_results)
res.to_csv('/kaggle/working/ton_semantic_results.csv', index=False)
summary = res.groupby(['attack','eps']).agg(
    seeds=('seed','size'), damage=('damage','mean'), differential_error=('differential_error','mean'),
    attribution_accuracy=('attribution_correct','mean'), volume_weight=('volume_weight','mean'), min_weight=('min_weight','mean')
).reset_index()
summary.to_csv('/kaggle/working/ton_semantic_summary.csv', index=False)

print('\n=== TON_IoT SEMANTIC HELD-OUT ATTACK RESULTS ===')
print(summary.round(4).to_string(index=False))
print('\nFiles written:')
print('/kaggle/working/ton_semantic_results.csv')
print('/kaggle/working/ton_semantic_summary.csv')
print('\nPre-registered boundary prediction: mean clean semantic-view accuracy >= 0.80 predicts a positive monitor gain on TON_IoT.')
print('This code prints the raw outcome; do not tune the schema or hyperparameters after seeing it.')
