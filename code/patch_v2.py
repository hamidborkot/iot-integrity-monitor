
# =================== PATCH v2  (paste AFTER the original cells; it overrides run_pair / pairs_for) ===================
from scipy.cluster.hierarchy import linkage, leaves_list
from scipy.spatial.distance import squareform
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import roc_auc_score

CFG.update(G_LIST=[4, 6, 8], EPS_LIST=[0.02, 0.05, 0.1, 0.25, 0.5], EPS_REPAIR=[1.0], N_PAIRS=4)

# --- A. shift taxonomy: covariate (same families, other day) / partial (1/3 families shared) / semantic (unseen families)
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
pairs_for = pairs_for2          # run_all() looks up pairs_for at call time

# --- B. balanced views: correlated features are dealt to DIFFERENT groups, so every view sees every kind of signal
def balanced_groups(X, G):
    C = np.nan_to_num(np.corrcoef(X[:5000].T)); D = 1 - np.abs(C); D = (D + D.T) / 2; np.fill_diagonal(D, 0)
    order = leaves_list(linkage(squareform(D, checks=False), "average"))
    return [order[i::G] for i in range(G)]

# --- C. anchored estimator: weight views by their labelled ID accuracy, and down-weight views whose
#        predicted-positive rate DROPPED (vs the ID rate) much more than the least-drifted views
def anchored(P_id, y_id, P_ood, q=0.2, tau=0.05):
    G = len(P_ood); Yi, Yo = (P_id > .5).astype(int), (P_ood > .5).astype(int)
    acc = np.clip((Yi == y_id).mean(1), .51, .99); d = Yi.mean(1) - Yo.mean(1)
    dev = np.maximum(d - np.quantile(d, q), 0)
    w = np.maximum(np.log(acc / (1 - acc)), .05) * np.exp(-(dev / tau) ** 2)
    v = 2 * Yo - 1; tot = (w[:, None] * v).sum(0)
    pseudo = np.array([(tot - w[i] * v[i]) >= 0 for i in range(G)]).astype(int)
    return (Yo == pseudo).mean(1)

def estimators2(P_id, y_id, P_ood):
    e = estimators(P_id, y_id, P_ood); e["ANCH"] = anchored(P_id, y_id, P_ood); return e

# --- D. input-side shift score (does a plain domain classifier already "see" the attack?)
def shift_auc(Xa, Xb, n=4000, seed=0):
    rng = np.random.default_rng(seed)
    a = Xa[rng.choice(len(Xa), min(n, len(Xa)), replace=False)]; b = Xb[rng.choice(len(Xb), min(n, len(Xb)), replace=False)]
    X = np.vstack([a, b]); y = np.r_[np.zeros(len(a)), np.ones(len(b))]
    p = cross_val_predict(LogisticRegression(max_iter=200), X, y, cv=3, method="predict_proba")[:, 1]
    return float(roc_auc_score(y, p))

# --- E. attack with selectable rows (rate-matched = also pushes benign rows to "attack" to hide the rate drop)
def pgd2(models, X, y, eps, steps, mut, lo, hi, col_allow=None, sel=None):
    if eps <= 0: return X
    sel = (y == 1) if sel is None else sel
    X0 = X.clone(); delta = torch.zeros_like(X0); rows = sel.float()[:, None]
    m = mut.float() if col_allow is None else mut.float() * col_allow.float()
    alpha = 2.5 * eps / steps; ridx = torch.where(sel)[0]; bce = nn.BCEWithLogitsLoss()
    for _ in range(steps):
        delta.requires_grad_(True); Xa = X0 + delta
        loss = sum(bce(mod(Xa)[ridx], y[ridx]) for mod in models) / len(models)
        g, = torch.autograd.grad(loss, delta)
        delta = (delta.detach() + alpha * g.sign() * m).clamp(-eps, eps)
        delta = ((X0 + delta).clamp(lo, hi) - X0) * rows
    return (X0 + delta).detach()

def ratematched_sel(y, seed):
    g = torch.Generator().manual_seed(seed); ben = torch.where(y == 0)[0]; n_att = int((y == 1).sum())
    sel = (y == 1).clone(); sel[ben[torch.randperm(len(ben), generator=g)[:min(n_att, len(ben))]]] = True
    return sel

# --- F. new per-pair experiment
def run_pair2(pool, pair, seed, cfg, rows):
    src, tgt, pname = pair; rng = np.random.default_rng(seed)
    if len(set(pool["y"][src])) < 2 or len(set(pool["y"][tgt])) < 2: return
    src = rng.permutation(src); n_tr = min(cfg["TRAIN_CAP"], int(.7 * len(src)))
    tr, va = src[:n_tr], src[n_tr:n_tr + cfg["VAL_CAP"]]; tg = rng.permutation(tgt)[:cfg["TGT_CAP"]]
    Xdf = pool["X"]; keep = Xdf.iloc[tr].std().values > 1e-6
    arr = lambda idx: Xdf.iloc[idx].values[:, keep]
    mu, sd = arr(tr).mean(0), arr(tr).std(0) + 1e-6
    T = lambda idx: torch.tensor(np.clip((arr(idx) - mu) / sd, -5, 5), dtype=torch.float32)
    Xtr, Xva, Xtg = T(tr), T(va), T(tg)
    ytr, yva, ytg = [torch.tensor(pool["y"][i], dtype=torch.float32) for i in (tr, va, tg)]
    mut = torch.tensor([len(np.unique(arr(tr)[:, j])) > 10 for j in range(Xtr.shape[1])])
    lo, hi = Xtr.min(0).values, Xtr.max(0).values; d = Xtr.shape[1]
    base = dict(dataset=pool["name"], pair=pname, kind=pname.split("|")[0], seed=seed)
    yv, yt_np = yva.numpy().astype(int), ytg.numpy().astype(int)

    bank = train_bank(Xtr, ytr, cfg["N_MODELS"], cfg["EPOCHS"], seed)
    P_id = probs(bank, Xva); P_nat = probs(bank, Xtg); acc_nat = true_acc(P_nat, yt_np).mean()
    log_rows(rows, dict(base, exp="natural", mode="none", eps=0.0, r=-1, G=0, **agl_diag(P_id, yv, P_nat, yt_np)),
             estimators2(P_id, yv, P_nat), true_acc(P_nat, yt_np), P_nat, yt_np)
    rows.append(dict(base, exp="shift_score", mode="none", eps=0.0, G=0, shift_auc=shift_auc(Xva.numpy(), Xtg.numpy()), acc_drop=0.0))
    surr = train_net(Xtr[::2], ytr[::2], (32, 2), seed + 777, cfg["EPOCHS"])
    for mode in ["whitebox", "transfer"]:
        for eps in cfg["EPS_LIST"]:
            Xa = pgd2(bank if mode == "whitebox" else [surr], Xtg, ytg, eps, cfg["PGD_STEPS"], mut, lo, hi)
            P_a = probs(bank, Xa)
            log_rows(rows, dict(base, exp="evasion_fullview", mode=mode, eps=eps, r=-1, G=0),
                     estimators2(P_id, yv, P_a), true_acc(P_a, yt_np), P_a, yt_np)
            rows.append(dict(base, exp="shift_score", mode=mode, eps=eps, G=0, shift_auc=shift_auc(Xva.numpy(), Xa.numpy()),
                             acc_drop=float(acc_nat - true_acc(P_a, yt_np).mean())))

    for G in cfg["G_LIST"]:
        groups = balanced_groups(Xtr.numpy(), G)
        vb = train_view_bank(Xtr, ytr, groups, cfg["M_PER_GROUP"], cfg["EPOCHS"], seed)
        Pv_id = probs_view(vb, Xva); Pv_nat = probs_view(vb, Xtg); flat = [n for g in vb for n in g]
        rows.append(dict(base, exp="view_quality", G=G, view_acc_id=float(true_acc(Pv_id, yv).mean()), view_acc_nat=float(true_acc(Pv_nat, yt_np).mean())))
        for eps in cfg["EPS_REPAIR"]:
            for amode in ["standard", "ratematched"]:
                sel = None if amode == "standard" else ratematched_sel(ytg, seed)
                for r in range(0, G):
                    col = torch.zeros(d)
                    for g in range(r): col[groups[g]] = 1
                    Xa = pgd2(flat, Xtg, ytg, eps, cfg["PGD_STEPS"], mut, lo, hi, col_allow=col, sel=sel) if r > 0 else Xtg
                    Pv = probs_view(vb, Xa)
                    log_rows(rows, dict(base, exp="evasion_viewdisjoint", mode=amode, eps=eps, r=r, G=G),
                             estimators2(Pv_id, yv, Pv), true_acc(Pv, yt_np), Pv, yt_np)
run_pair = run_pair2            # run_all() looks up run_pair at call time

# --- G. report
def report2(res):
    pd.set_option("display.width", 220)
    vd = res[res.exp == "evasion_viewdisjoint"]
    g = vd.groupby(["dataset", "mode", "G", "r", "estimator"]).abs_err.mean().unstack()
    base = [c for c in g.columns if c not in ("MAJ", "RMAJ", "ANCH")]
    g["best_base"] = g[base].min(1); g["RMAJ_gain"] = g.best_base - g.RMAJ; g["ANCH_gain"] = g.best_base - g.ANCH
    g["r/G"] = [r / G for (_, _, G, r) in g.index]
    print("== H3: gain over best baseline (positive = repair helps), by G and r ==")
    print(g[["best_base", "RMAJ", "ANCH", "RMAJ_gain", "ANCH_gain", "r/G"]].round(3).to_string())
    q = res[res.exp == "view_quality"].groupby(["dataset", "G"])[["view_acc_id", "view_acc_nat"]].mean()
    print("\n== view quality (mean single-view accuracy) =="); print(q.round(3).to_string())
    s = res[(res.exp == "shift_score") & (res.mode != "none")]
    print("\n== input-side shift score vs real accuracy drop (corr, AUROC for drop>5pp) ==")
    for ds, x in s.groupby("dataset"):
        pos = (x.acc_drop > .05).values
        auc = roc_auc_score(pos, x.shift_auc) if 0 < pos.sum() < len(pos) else np.nan
        print(f"{ds:>16} corr={np.corrcoef(x.shift_auc, x.acc_drop)[0,1]:.2f}  AUROC(drop>5pp)={auc:.2f}")
    k = res[res.exp == "natural"].groupby(["dataset", "kind", "estimator"]).abs_err.mean().unstack()
    print("\n== natural-shift |error| by shift kind =="); print(k.round(3).to_string())
