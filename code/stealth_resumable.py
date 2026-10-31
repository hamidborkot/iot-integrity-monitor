
# ==========================================================================================
#  SELF-CONTAINED, RESUMABLE RUN  (continues the study after a disconnect; no earlier cells needed)
#  - Runs seeds 1 and 2 by default. Seed 0 is already done: if its CSV is still in /kaggle/working it is reused,
#    otherwise it is re-run once (set RERUN_SEED0_IF_MISSING=False to skip and analyse seeds 1-2 only).
#  - Saves after EVERY pair and resumes automatically if the runtime disconnects: just run the cell again.
#  - Tip: use "Save & Run All" (background) so a browser disconnect cannot stop it.
# ==========================================================================================
import os, time, warnings, glob
import numpy as np, pandas as pd, torch, torch.nn as nn
from scipy.stats import norm, linregress
from scipy.cluster.hierarchy import linkage, leaves_list
from scipy.spatial.distance import squareform
warnings.filterwarnings("ignore")
torch.set_num_threads(os.cpu_count() or 4)

RUN = "full"
SEEDS = [1, 2]
RERUN_SEED0_IF_MISSING = True

PATHS = dict(
    nsl="/kaggle/input/datasets/shamstahzib/nsl-kdd-dataset/nsl-kdd-dataset",
    ids18="/kaggle/input/datasets/dhoogla/csecicids2018",
    iot23="/kaggle/input/datasets/himadri07/ciciot2023/CICIOT23",
    iomt="/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024")
CFG = dict(OUT="/kaggle/working", IOT_QB=0.15, IOT_QA=0.01, IOMT_BENIGN_VALUE=None, M_PER_GROUP=2, PGD_STEPS=10,
           G3=6, EPS3=[0.25, 0.5], R3=[2, 3, 4], LAMS=[0.0, 1.0, 10.0, 100.0], N_PAIRS=2, MAX_PER_KIND=3,
           CAP_PER_CLASS=50000, TRAIN_CAP=40000, VAL_CAP=20000, TGT_CAP=20000, EPOCHS=5)
if RUN == "smoke":
    CFG.update(CAP_PER_CLASS=4000, TRAIN_CAP=5000, VAL_CAP=3000, TGT_CAP=3000, N_PAIRS=1, MAX_PER_KIND=1,
               EPOCHS=2, EPS3=[0.5], R3=[3], LAMS=[0.0, 10.0])
QS, TAUS = [0.1, 0.2, 0.3], [0.02, 0.05, 0.1]
BASE_EST = ["AC", "DoC", "ATC", "GDE", "ALine"]

def seed_file(s): return os.path.join(CFG["OUT"], f"results_v3_{RUN}_seeds{s}.csv")
if RERUN_SEED0_IF_MISSING and 0 not in SEEDS and not os.path.exists(seed_file(0)):
    SEEDS = [0] + list(SEEDS); print("seed-0 CSV not found -> seed 0 will be re-run as well", flush=True)
CFG["SEEDS"] = SEEDS

# ------------------------------------------ data ------------------------------------------
def _pool(name, X, y, fam, dom):
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).astype("float32").reset_index(drop=True)
    return dict(name=name, X=X, y=np.asarray(y).astype(int), fam=np.asarray(fam).astype(str), dom=np.asarray(dom).astype(str))

def _cap_classes(df, ycol, cap, seed):
    return pd.concat([g.sample(min(len(g), cap), random_state=seed) for _, g in df.groupby(ycol)])

NSL_COLS = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
 "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations","num_shells",
 "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
 "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
 "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
 "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]
NSL_CAT = {
 "DoS": "neptune back land pod smurf teardrop mailbomb apache2 processtable udpstorm worm".split(),
 "Probe": "ipsweep nmap portsweep satan mscan saint".split(),
 "R2L": "ftp_write guess_passwd imap multihop phf spy warezclient warezmaster sendmail named snmpgetattack snmpguess xlock xsnoop httptunnel".split(),
 "U2R": "buffer_overflow loadmodule perl rootkit ps sqlattack xterm".split()}
NSL_MAP = {a: k for k, v in NSL_CAT.items() for a in v}

def load_nsl(cfg):
    d = PATHS["nsl"]
    def rd(f):
        df = pd.read_csv(os.path.join(d, f), header=None)
        df.columns = NSL_COLS[:df.shape[1]]
        return df
    parts = {"train": rd("KDDTrain+.txt"), "test": rd("KDDTest+.txt"), "test21": rd("KDDTest-21.txt")}
    allx = pd.concat(parts.values())
    for c in ["protocol_type", "service", "flag"]:
        cats = {v: i for i, v in enumerate(sorted(allx[c].astype(str).unique()))}
        for p in parts.values(): p[c] = p[c].astype(str).map(cats)
    df = pd.concat([p.assign(dom=k) for k, p in parts.items()])
    lab = df["label"].astype(str).str.strip(".").str.lower()
    fam = np.where(lab == "normal", "normal", lab.map(NSL_MAP).fillna("other"))
    y = (lab != "normal").astype(int)
    X = df.drop(columns=["label", "difficulty", "dom"])
    return _pool("NSL-KDD", X, y, fam, df["dom"])

def load_ids18(cfg, seed=0):
    out = []
    for f in sorted(glob.glob(PATHS["ids18"] + "/*.parquet")):
        df = pd.read_parquet(f)
        lc = [c for c in df.columns if c.lower() == "label"][0]
        df["_y"] = (~df[lc].astype(str).str.lower().str.contains("benign")).astype(int)
        df = _cap_classes(df, "_y", cfg["CAP_PER_CLASS"] // 3, seed)
        day = os.path.basename(f).split("_")[0]
        df["_dom"], df["_fam"] = day, df[lc].astype(str)
        out.append(df.drop(columns=[lc]))
    df = pd.concat(out)
    X = df.drop(columns=["_y", "_dom", "_fam"]).select_dtypes("number")
    return _pool("CSE-CIC-IDS2018", X, df["_y"], df["_fam"], df["_dom"])

def _sample_csv(path, cfg, seed=0, chunk=400_000, labcol=None):
    rng = np.random.default_rng(seed); parts = []
    for ch in pd.read_csv(path, chunksize=chunk, low_memory=False):
        lc = labcol or ([c for c in ch.columns if c.lower() == "label"] or [ch.columns[-1]])[0]
        benign = ch[lc].astype(str).str.lower().str.contains("benign|normal").values
        keep = np.where(benign, rng.random(len(ch)) < cfg["IOT_QB"], rng.random(len(ch)) < cfg["IOT_QA"])
        parts.append(ch[keep])
    df = pd.concat(parts)
    return df, lc

def load_iot_like(path_list, name, cfg, seed=0, benign_value=None):
    dfs = []; lc = None
    for p in path_list:
        d, lc = _sample_csv(p, cfg, seed); dfs.append(d)
    df = pd.concat(dfs).reset_index(drop=True)
    lab = df[lc].astype(str)
    if benign_value is not None: ben = lab == str(benign_value)
    else: ben = lab.str.lower().str.contains("benign|normal")
    df["_y"] = (~ben).astype(int)
    df = _cap_classes(df, "_y", cfg["CAP_PER_CLASS"], seed)
    lab = df[lc].astype(str)
    fam = lab.str.split("-").str[0]
    X = df.drop(columns=[lc, "_y"]).select_dtypes("number")
    return _pool(name, X, df["_y"], fam, ["all"] * len(df))

def build_pools(cfg):
    pools = {}
    for k, fn in [("nsl", lambda: load_nsl(cfg)), ("ids18", lambda: load_ids18(cfg)),
                  ("iot23", lambda: load_iot_like([PATHS["iot23"] + "/train/train.csv"], "CICIoT2023", cfg)),
                  ("iomt", lambda: load_iot_like([PATHS["iomt"] + "/train_iomt.csv", PATHS["iomt"] + "/test_iomt.csv"],
                                                 "CICIoMT2024", cfg, benign_value=cfg["IOMT_BENIGN_VALUE"]))]:
        try:
            t = time.time(); pools[k] = fn(); p = pools[k]
            print(f"[{k}] rows={len(p['y'])} feats={p['X'].shape[1]} attack%={p['y'].mean():.2f} ({time.time()-t:.0f}s)", flush=True)
        except Exception as e:
            print(f"[{k}] FAILED: {type(e).__name__}: {e}", flush=True)
    return pools

def pairs_for2(pool, cfg, seed):
    rng = np.random.default_rng(seed); out = []
    dom, fam, y, name = pool["dom"], pool["fam"], pool["y"], pool["name"]; n = len(y)
    if name == "NSL-KDD":
        for t in ["test", "test21"]:
            out.append((np.where(dom == "train")[0], np.where(dom == t)[0], f"mixed|train->{t}"))
    if name == "CSE-CIC-IDS2018":
        for s, t in [("DDoS1","DDoS2"),("DDoS2","DDoS1"),("DoS1","DoS2"),("DoS2","DoS1"),("Infil1","Infil2"),("Infil2","Infil1"),("Web1","Web2"),("Web2","Web1")]:
            si = np.where(np.char.startswith(dom.astype(str), s + "-"))[0]; ti = np.where(np.char.startswith(dom.astype(str), t + "-"))[0]
            if len(si) and len(ti): out.append((si, ti, f"covariate|{s}->{t}"))
    base = np.where(dom == "train")[0] if name == "NSL-KDD" else np.arange(n)
    atk_f = np.unique(fam[base][y[base] == 1])
    if len(atk_f) >= 4:
        for kind, frac in [("partial", 1 / 3), ("semantic", 0.0)]:
            for i in range(cfg["N_PAIRS"]):
                f = rng.permutation(atk_f); k = int(len(f) * frac); C = list(f[:k]); rest = f[k:]
                A = list(rest[: len(rest) // 2]) + C; B = list(rest[len(rest) // 2:]) + C
                ben = base[y[base] == 0].copy(); rng.shuffle(ben); h = len(ben) // 2
                src = np.r_[ben[:h], base[(y[base] == 1) & np.isin(fam[base], A)]]
                tgt = np.r_[ben[h:], base[(y[base] == 1) & np.isin(fam[base], B)]]
                out.append((src, tgt, f"{kind}|fam{i}"))
    return out

def pairs_v3(pool, cfg, seed):
    cnt, out = {}, []
    for a, b, name in pairs_for2(pool, cfg, seed):
        k = name.split("|")[0]; cnt[k] = cnt.get(k, 0) + 1
        if cnt[k] <= cfg["MAX_PER_KIND"]: out.append((a, b, name))
    return out

# ------------------------------------------ models ------------------------------------------
class Net(nn.Module):
    def __init__(s, d, h, depth, cols=None):
        super().__init__()
        s.cols = None if cols is None else torch.as_tensor(cols, dtype=torch.long)
        d = d if cols is None else len(cols)
        if h == 0: s.f = nn.Linear(d, 1)
        else:
            L = [nn.Linear(d, h), nn.ReLU()]
            for _ in range(depth - 1): L += [nn.Linear(h, h), nn.ReLU()]
            s.f = nn.Sequential(*L, nn.Linear(h, 1))
    def forward(s, x):
        if s.cols is not None: x = x[:, s.cols]
        return s.f(x).squeeze(-1)

def train_net(X, y, arch, seed, epochs, frac=1.0, cols=None, bs=512):
    torch.manual_seed(seed); n = len(X)
    idx = torch.randperm(n)[: max(64, int(frac * n))]
    net = Net(X.shape[1], arch[0], arch[1], cols); opt = torch.optim.Adam(net.parameters(), 3e-3, weight_decay=1e-4)
    Xi, yi = X[idx], y[idx]; lossf = nn.BCEWithLogitsLoss()
    for _ in range(epochs):
        perm = torch.randperm(len(Xi))
        for b in range(0, len(Xi), bs):
            j = perm[b:b + bs]; opt.zero_grad(); lossf(net(Xi[j]), yi[j]).backward(); opt.step()
    return net.eval()

def train_view_bank(X, y, groups, m, epochs, seed):
    out = []
    for g, cols in enumerate(groups):
        out.append([train_net(X, y, (32, 2) if i == 0 else (16, 1), seed * 1000 + g * 10 + i, epochs, cols=cols) for i in range(m)])
    return out

@torch.no_grad()
def probs(nets, X): return torch.stack([torch.sigmoid(n(X)) for n in nets]).numpy()

@torch.no_grad()
def probs_view(vb, X): return np.stack([probs(g, X).mean(0) for g in vb])

def balanced_groups(X, G):
    C = np.nan_to_num(np.corrcoef(X[:5000].T)); D = 1 - np.abs(C); D = (D + D.T) / 2; np.fill_diagonal(D, 0)
    order = leaves_list(linkage(squareform(D, checks=False), "average"))
    return [order[i::G] for i in range(G)]

# ------------------------------------------ estimators ------------------------------------------
def _pairs_agree(Y):
    Yf = Y.astype("float32"); n = Y.shape[1]
    return (Yf @ Yf.T + (1 - Yf) @ (1 - Yf).T) / n

def _probit(a): return norm.ppf(np.clip(a, 1e-3, 1 - 1e-3))

def estimators(P_id, y_id, P_ood, robust=True):
    Yi, Yo = (P_id > .5).astype(int), (P_ood > .5).astype(int); M = len(Yo)
    acc_id = (Yi == y_id).mean(1); ci, co = np.maximum(P_id, 1 - P_id), np.maximum(P_ood, 1 - P_ood)
    est = {}
    est["AC"] = co.mean(1)
    est["DoC"] = np.clip(acc_id - (ci.mean(1) - co.mean(1)), 0, 1)
    est["ATC"] = np.array([(co[i] > np.quantile(ci[i], 1 - acc_id[i])).mean() for i in range(M)])
    Ao = _pairs_agree(Yo); est["GDE"] = (Ao.sum(1) - np.diag(Ao)) / (M - 1)
    S = Yo.sum(0); est["MAJ"] = np.array([(Yo[i] == (((S - Yo[i]) / (M - 1)) >= .5)).mean() for i in range(M)])
    try:
        Ai = _pairs_agree(Yi); iu = np.triu_indices(M, 1)
        r = linregress(_probit(Ai[iu]), _probit(Ao[iu]))
        est["ALine"] = norm.cdf(r.slope * _probit(acc_id) + r.intercept)
    except Exception: est["ALine"] = np.full(M, np.nan)
    if robust:
        v = 2 * Yo - 1; w = np.ones(M)
        for _ in range(8):
            Tot = (w[:, None] * v).sum(0); pseudo = np.array([((Tot - w[i] * v[i]) >= 0) for i in range(M)]).astype(int)
            a = np.clip((Yo == pseudo).mean(1), .05, .95); w = np.log(a / (1 - a))
        est["RMAJ"] = a
    return est

def true_acc(P, y): return ((P > .5).astype(int) == y).mean(1)

def coerr(P, y):
    W = ((P > .5).astype(int) != y).astype("float32"); e = W.mean()
    if e < 1e-6: return np.nan
    M = len(W); c = (W @ W.T) / W.shape[1]; return float((c.sum() - np.trace(c)) / (M * (M - 1)) / e)

def log_rows(rows, base, est, truth, P_ood, y_ood):
    cr = coerr(P_ood, y_ood)
    for k, v in est.items():
        d = v - truth
        rows.append(dict(base, estimator=k, bias=float(np.nanmean(d)), abs_err=float(np.nanmean(np.abs(d))),
                         true_acc=float(truth.mean()), coerr=cr))

def anchored(P_id, y_id, P_ood, q=0.2, tau=0.05):
    G = len(P_ood); Yi, Yo = (P_id > .5).astype(int), (P_ood > .5).astype(int)
    acc = np.clip((Yi == y_id).mean(1), .51, .99); d = Yi.mean(1) - Yo.mean(1)
    dev = np.maximum(d - np.quantile(d, q), 0)
    w = np.maximum(np.log(acc / (1 - acc)), .05) * np.exp(-(dev / tau) ** 2)
    v = 2 * Yo - 1; tot = (w[:, None] * v).sum(0)
    pseudo = np.array([(tot - w[i] * v[i]) >= 0 for i in range(G)]).astype(int)
    return (Yo == pseudo).mean(1)

def anchored_adapt(P_id, y_id, P_ood, q=0.2, k=2.0, tau_min=0.02, second_pass=False):
    G = len(P_ood); Yi, Yo = (P_id > .5).astype(int), (P_ood > .5).astype(int)
    acc = np.clip((Yi == y_id).mean(1), .51, .99); d = Yi.mean(1) - Yo.mean(1)
    low = d[d <= np.median(d)]; s = 1.4826 * np.median(np.abs(low - np.median(low))); tau = max(tau_min, k * s)
    dev = np.maximum(d - np.quantile(d, q), 0)
    w = np.maximum(np.log(acc / (1 - acc)), .05) * np.exp(-(dev / tau) ** 2)
    v = 2 * Yo - 1
    def vote(w):
        tot = (w[:, None] * v).sum(0)
        return np.array([(tot - w[i] * v[i]) >= 0 for i in range(G)]).astype(int)
    pseudo = vote(w); a = (Yo == pseudo).mean(1)
    if second_pass:
        a2 = np.clip(a, .05, .95); w2 = w * np.maximum(np.log(a2 / (1 - a2)), .05)
        pseudo = vote(w2); a = (Yo == pseudo).mean(1)
    return a

def est_all(Pv_id, yv, Pv):
    e = estimators(Pv_id, yv, Pv); e["ANCH"] = anchored(Pv_id, yv, Pv)
    e["ANCH_A"] = anchored_adapt(Pv_id, yv, Pv)
    e["ANCH_B"] = anchored_adapt(Pv_id, yv, Pv, second_pass=True)
    for q in QS:
        for t in TAUS: e[f"ANCH_q{q}_t{t}"] = anchored(Pv_id, yv, Pv, q, t)
    return e

# ------------------------------------------ attack + experiment ------------------------------------------
def ratematched_sel(y, seed):
    g = torch.Generator().manual_seed(seed); ben = torch.where(y == 0)[0]; n_att = int((y == 1).sum())
    sel = (y == 1).clone(); sel[ben[torch.randperm(len(ben), generator=g)[:min(n_att, len(ben))]]] = True
    return sel

def pgd3(vb, X, y, eps, steps, mut, lo, hi, col_allow, sel, lam, r):
    flat = [n for g in vb for n in g]; sel = (y == 1) if sel is None else sel
    X0 = X.clone(); delta = torch.zeros_like(X0); rows_ = sel.float()[:, None]
    m = mut.float() * col_allow.float(); alpha = 2.5 * eps / steps; ridx = torch.where(sel)[0]; bce = nn.BCEWithLogitsLoss()
    def stats(Xa):
        out = []
        for g in range(r):
            p = torch.stack([torch.sigmoid(n(Xa)) for n in vb[g]]).mean(0)
            out.append(torch.stack([p.mean(), (2 * p - 1).abs().mean()]))
        return torch.stack(out)
    with torch.no_grad(): ref = stats(X0)
    for _ in range(steps):
        delta.requires_grad_(True); Xa = X0 + delta
        dmg = sum(bce(mod(Xa)[ridx], y[ridx]) for mod in flat) / len(flat)
        loss = dmg - lam * ((stats(Xa) - ref) ** 2).sum()
        g_, = torch.autograd.grad(loss, delta)
        delta = (delta.detach() + alpha * g_.sign() * m).clamp(-eps, eps)
        delta = ((X0 + delta).clamp(lo, hi) - X0) * rows_
    return (X0 + delta).detach()

def prep_pair(pool, pair, seed, cfg):
    src, tgt, pname = pair; rng = np.random.default_rng(seed)
    if len(set(pool["y"][src])) < 2 or len(set(pool["y"][tgt])) < 2: return None
    src = rng.permutation(src); n_tr = min(cfg["TRAIN_CAP"], int(.7 * len(src)))
    tr, va = src[:n_tr], src[n_tr:n_tr + cfg["VAL_CAP"]]; tg = rng.permutation(tgt)[:cfg["TGT_CAP"]]
    Xdf = pool["X"]; keep = Xdf.iloc[tr].std().values > 1e-6
    arr = lambda idx: Xdf.iloc[idx].values[:, keep]
    mu, sd = arr(tr).mean(0), arr(tr).std(0) + 1e-6
    T = lambda idx: torch.tensor(np.clip((arr(idx) - mu) / sd, -5, 5), dtype=torch.float32)
    Xtr, Xva, Xtg = T(tr), T(va), T(tg)
    ytr, ytg = [torch.tensor(pool["y"][i], dtype=torch.float32) for i in (tr, tg)]
    mut = torch.tensor([len(np.unique(arr(tr)[:, j])) > 10 for j in range(Xtr.shape[1])])
    return dict(Xtr=Xtr, Xva=Xva, Xtg=Xtg, ytr=ytr, ytg=ytg, yva=pool["y"][va].astype(int), yt=pool["y"][tg].astype(int),
                mut=mut, lo=Xtr.min(0).values, hi=Xtr.max(0).values, d=Xtr.shape[1])

def log_cell(rows, base, Pv_id, yv, Pv, yt_np, r, G, acc0):
    tr = true_acc(Pv, yt_np); d = (Pv_id > .5).mean(1) - (Pv > .5).mean(1)
    margin = float(d[:r].min() - d[r:].max()) if 0 < r < G else np.nan
    b = dict(base, r=r, G=G, damage=float(acc0 - tr.mean()), margin=margin)
    log_rows(rows, b, est_all(Pv_id, yv, Pv), tr, Pv, yt_np)
    for g in range(G): rows.append(dict(b, exp="drift", g=g, attacked=int(g < r), d=float(d[g])))

def run_pair3(pool, pair, seed, cfg, rows):
    P = prep_pair(pool, pair, seed, cfg)
    if P is None: return
    G = cfg["G3"]; groups = balanced_groups(P["Xtr"].numpy(), G)
    vb = train_view_bank(P["Xtr"], P["ytr"], groups, cfg["M_PER_GROUP"], cfg["EPOCHS"], seed)
    Pv_id = probs_view(vb, P["Xva"]); Pv0 = probs_view(vb, P["Xtg"]); acc0 = true_acc(Pv0, P["yt"]).mean()
    base = dict(dataset=pool["name"], pair=pair[2], kind=pair[2].split("|")[0], seed=seed, exp="stealth", eps=0.0, lam=-1.0, mode="none")
    log_cell(rows, base, Pv_id, P["yva"], Pv0, P["yt"], 0, G, acc0)
    rm = ratematched_sel(P["ytg"], seed)
    for eps in cfg["EPS3"]:
        for r in cfg["R3"]:
            col = torch.zeros(P["d"])
            for g in range(r): col[groups[g]] = 1
            for mode, lam, sel in [("standard", 0.0, None)] + [("ratematched", l, rm) for l in cfg["LAMS"]]:
                Xa = pgd3(vb, P["Xtg"], P["ytg"], eps, cfg["PGD_STEPS"], P["mut"], P["lo"], P["hi"], col, sel, lam, r)
                log_cell(rows, dict(base, eps=eps, lam=float(lam), mode=mode), Pv_id, P["yva"], probs_view(vb, Xa), P["yt"], r, G, acc0)

def run_v3(pools, cfg):
    t0 = time.time()
    for seed in cfg["SEEDS"]:
        f = seed_file(seed); rows_seed, done = [], set()
        if os.path.exists(f):
            prev = pd.read_csv(f); rows_seed = prev.to_dict("records"); done = set(zip(prev.dataset, prev.pair))
            print(f"seed {seed}: resuming, {len(done)} pairs already done", flush=True)
        for key, pool in pools.items():
            for pr in pairs_v3(pool, cfg, seed):
                if (pool["name"], pr[2]) in done: continue
                new = []
                try: run_pair3(pool, pr, seed, cfg, new)
                except Exception as e:
                    print("FAILED", pool["name"], pr[2], type(e).__name__, e, flush=True); continue
                rows_seed += new; pd.DataFrame(rows_seed).to_csv(f, index=False)
                print(f"{pool['name']:>16} | {pr[2][:34]:<34} | seed {seed} | {time.time()-t0:5.0f}s", flush=True)

def load_all():
    files = sorted(glob.glob(os.path.join(CFG["OUT"], f"results_v3_{RUN}_seeds*.csv")))
    res = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    print("files used:", [os.path.basename(f) for f in files], "| seeds present:", sorted(res.seed.unique()), flush=True)
    return res

# ------------------------------------------ analysis ------------------------------------------
def boot_ci(x, n=2000, seed=0):
    x = np.asarray(x, float); x = x[~np.isnan(x)]
    if len(x) < 2: return (np.nan, np.nan)
    m = np.random.default_rng(seed).choice(x, (n, len(x))).mean(1)
    return tuple(np.percentile(m, [2.5, 97.5]))

def diff_rows(res):
    st = res[res.exp == "stealth"].copy()
    st["att"] = np.where(st["mode"] == "standard", "standard", "stealth_lam" + st.lam.astype(str))
    key = ["dataset", "pair", "seed", "G", "estimator"]
    r0 = st[st.r == 0]; b0 = dict(zip(zip(*[r0[c] for c in key]), r0.bias))
    a = st[st.r > 0].copy()
    a["dabs"] = (a.bias - np.array([b0.get(k, np.nan) for k in zip(*[a[c] for c in key])])).abs()
    a["zone"] = pd.cut(a.r / a.G, [0.01, 0.49, 0.51, 0.99], labels=["<G/2", "=G/2", ">G/2"])
    return a

def report3(res):
    pd.set_option("display.width", 220); a = diff_rows(res)
    out = []
    for (ds, att, zone), d in a.groupby(["dataset", "att", "zone"], observed=True):
        u = d.groupby(["pair", "seed", "estimator"]).dabs.mean().unstack()
        bb = u[BASE_EST].mean().idxmin(); diff = (u[bb] - u["ANCH"]).values; lo, hi = boot_ci(diff)
        out.append(dict(dataset=ds, attack=att, zone=zone, units=len(u), best_base=bb, base_err=u[bb].mean(), MAJ_err=u["MAJ"].mean(),
                        ANCH_err=u["ANCH"].mean(), cut_pct=100 * (1 - u["ANCH"].mean() / u[bb].mean()), gain_lo=lo, gain_hi=hi))
    T = pd.DataFrame(out); T.to_csv(os.path.join(CFG["OUT"], "v3_main_table.csv"), index=False)
    print("== differential error (|bias(r)-bias(0)|), clustered CIs ==")
    print(T.round(3).to_string(index=False))
    an = a[a.estimator == "ANCH"].groupby(["dataset", "att"]).agg(damage=("damage", "mean"), margin=("margin", "mean"),
                                                                 margin_pos=("margin", lambda x: (x > 0).mean()), ANCH_err=("dabs", "mean"))
    bs = a[a.estimator.isin(BASE_EST)].groupby(["dataset", "att", "estimator"]).dabs.mean().unstack()[BASE_EST].min(1).rename("best_base_err")
    print("\n== damage vs stealth =="); print(an.join(bs).round(3).to_string())
    a["dbin"] = pd.cut(a.damage, [-1, .05, .10, .20, 1.0], labels=["<5pp", "5-10pp", "10-20pp", ">20pp"])
    m1 = a[a.estimator == "ANCH"].groupby(["dataset", "dbin"], observed=True).dabs.mean().rename("ANCH")
    m2 = a[a.estimator.isin(BASE_EST)].groupby(["dataset", "dbin", "estimator"], observed=True).dabs.mean().unstack()[BASE_EST].min(1).rename("best_base")
    print("\n== matched damage bins =="); print(pd.concat([m1, m2], axis=1).round(3).to_string())
    cols = ["ANCH", "ANCH_A", "ANCH_B"] + [f"ANCH_q{q}_t{t}" for q in QS for t in TAUS]
    s = a[a.estimator.isin(cols)].groupby(["dataset", "estimator"]).dabs.mean().unstack()[cols]
    print("\n== ANCH variants / sensitivity =="); print(s.round(3).to_string())
    dr = res[res.exp == "drift"]
    if len(dr):
        g = dr[dr.r > 0].groupby(["dataset", "attacked"]).d.describe(percentiles=[.1, .9])[["mean", "10%", "90%"]]
        print("\n== per-view rate drop: attacked vs clean =="); print(g.round(3).to_string())

def frac_report(res):
    pd.set_option("display.width", 220); a = diff_rows(res)
    g = a.groupby(["dataset", "att", "estimator"]).dabs.mean().unstack()
    dm = a[a.estimator == "ANCH"].groupby(["dataset", "att"]).damage.mean()
    cols = ["ANCH", "ANCH_A", "ANCH_B", "MAJ"] + BASE_EST
    t = g[cols].div(dm, axis=0); t["best_base"] = g[BASE_EST].min(1) / dm; t["damage"] = dm
    print("== differential error as a FRACTION of the true damage (0 = perfect, 1 = blind) ==")
    print(t.round(2).to_string())

# ------------------------------------------ RUN ------------------------------------------
t0 = time.time(); print(f"[{RUN}] seeds to run: {SEEDS}; loading data ...", flush=True)
pools = build_pools(CFG)
print(f"loaded in {time.time()-t0:.0f}s; running (saves after every pair; re-run this cell to resume) ...", flush=True)
run_v3(pools, CFG)
print(f"done in {time.time()-t0:.0f}s", flush=True)
res_all = load_all()
report3(res_all); frac_report(res_all)
