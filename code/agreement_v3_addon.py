
# ============================================================================================
#  V3 ADD-ON  (paste as ONE cell AFTER all earlier cells incl. PATCH v2; then run SMOKE3, then FULL3)
#  Adds: stealth-aware attacker, damage-vs-stealth curve, ANCH (q,tau) grid, margin diagnostics,
#        clustered-CI differential tables, matched-damage bins.  Saves results_v3_raw.csv.
# ============================================================================================
QS, TAUS = [0.1, 0.2, 0.3], [0.02, 0.05, 0.1]
BASE_EST = ["AC", "DoC", "ATC", "GDE", "ALine"]

CFG3 = dict(CFG, SEEDS=[0, 1], EPOCHS=5, CAP_PER_CLASS=50000, TRAIN_CAP=40000, VAL_CAP=20000, TGT_CAP=20000,
            N_PAIRS=2, MAX_PER_KIND=3, G3=6, EPS3=[0.25, 0.5], R3=[2, 3, 4], LAMS=[0.0, 1.0, 10.0, 100.0], PGD_STEPS=10, M_PER_GROUP=2)
SMOKE3 = dict(CFG3, SEEDS=[0], CAP_PER_CLASS=4000, TRAIN_CAP=5000, VAL_CAP=3000, TGT_CAP=3000, N_PAIRS=1, MAX_PER_KIND=1,
              EPOCHS=2, EPS3=[0.5], R3=[3], LAMS=[0.0, 10.0])

def est_all(Pv_id, yv, Pv):
    e = estimators2(Pv_id, yv, Pv)
    for q in QS:
        for t in TAUS: e[f"ANCH_q{q}_t{t}"] = anchored(Pv_id, yv, Pv, q, t)
    return e

def log_cell(rows, base, Pv_id, yv, Pv, yt_np, r, G, acc0):
    tr = true_acc(Pv, yt_np); d = (Pv_id > .5).mean(1) - (Pv > .5).mean(1)
    margin = float(d[:r].min() - d[r:].max()) if 0 < r < G else np.nan
    b = dict(base, r=r, G=G, damage=float(acc0 - tr.mean()), margin=margin)
    log_rows(rows, b, est_all(Pv_id, yv, Pv), tr, Pv, yt_np)
    for g in range(G): rows.append(dict(b, exp="drift", g=g, attacked=int(g < r), d=float(d[g])))

# --- stealth-aware attacker: maximise damage, penalise change of each attacked view's soft positive rate / confidence
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

def pairs_v3(pool, cfg, seed):
    cnt, out = {}, []
    for a, b, name in pairs_for2(pool, cfg, seed):
        k = name.split("|")[0]; cnt[k] = cnt.get(k, 0) + 1
        if cnt[k] <= cfg["MAX_PER_KIND"]: out.append((a, b, name))
    return out

def run_v3(pools, cfg):
    rows = []; t0 = time.time()
    for key, pool in pools.items():
        for seed in cfg["SEEDS"]:
            for pr in pairs_v3(pool, cfg, seed):
                try: run_pair3(pool, pr, seed, cfg, rows)
                except Exception as e: print("FAILED", pool["name"], pr[2], type(e).__name__, e)
                print(f"{pool['name']:>16} | {pr[2][:34]:<34} | seed {seed} | {time.time()-t0:5.0f}s")
            pd.DataFrame(rows).to_csv(os.path.join(cfg["OUT"], "results_v3_raw.csv"), index=False)
    return pd.DataFrame(rows)

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
    # 1) main table, clustered by (pair, seed)
    out = []
    for (ds, att, zone), d in a.groupby(["dataset", "att", "zone"], observed=True):
        u = d.groupby(["pair", "seed", "estimator"]).dabs.mean().unstack()
        bb = u[BASE_EST].mean().idxmin(); diff = (u[bb] - u["ANCH"]).values; lo, hi = boot_ci(diff)
        out.append(dict(dataset=ds, attack=att, zone=zone, units=len(u), best_base=bb, base_err=u[bb].mean(), MAJ_err=u["MAJ"].mean(),
                        ANCH_err=u["ANCH"].mean(), cut_pct=100 * (1 - u["ANCH"].mean() / u[bb].mean()), gain_lo=lo, gain_hi=hi))
    T = pd.DataFrame(out); T.to_csv(os.path.join(CFG["OUT"], "v3_main_table.csv"), index=False)
    print("== differential error (|bias(r)-bias(0)|), clustered CIs; attack=standard | stealth_lam* ==")
    print(T.round(3).to_string(index=False))
    # 2) damage-stealth curve
    an = a[a.estimator == "ANCH"].groupby(["dataset", "att"]).agg(damage=("damage", "mean"), margin=("margin", "mean"),
                                                                 margin_pos=("margin", lambda x: (x > 0).mean()), ANCH_err=("dabs", "mean"))
    bs = a[a.estimator.isin(BASE_EST)].groupby(["dataset", "att", "estimator"]).dabs.mean().unstack()[BASE_EST].min(1).rename("best_base_err")
    print("\n== damage vs stealth: more lam = more hidden; does damage collapse? is the signature (margin) still separable? ==")
    print(an.join(bs).round(3).to_string())
    # 3) matched damage bins
    a["dbin"] = pd.cut(a.damage, [-1, .05, .10, .20, 1.0], labels=["<5pp", "5-10pp", "10-20pp", ">20pp"])
    m1 = a[a.estimator == "ANCH"].groupby(["dataset", "dbin"], observed=True).dabs.mean().rename("ANCH")
    m2 = a[a.estimator.isin(BASE_EST)].groupby(["dataset", "dbin", "estimator"], observed=True).dabs.mean().unstack()[BASE_EST].min(1).rename("best_base")
    print("\n== matched damage bins =="); print(pd.concat([m1, m2], axis=1).round(3).to_string())
    # 4) sensitivity (q, tau): choose on CICIoMT2024, report elsewhere
    cols = ["ANCH"] + [f"ANCH_q{q}_t{t}" for q in QS for t in TAUS]
    s = a[a.estimator.isin(cols)].groupby(["dataset", "estimator"]).dabs.mean().unstack()[cols]
    print("\n== ANCH sensitivity (mean differential error) =="); print(s.round(3).to_string())
    if "CICIoMT2024" in s.index:
        pick = s.loc["CICIoMT2024", cols[1:]].idxmin(); print("\nfrozen choice from CICIoMT2024:", pick)
        print(s[[pick, "ANCH"]].round(3).to_string())
    # 5) margin assumption: per-view rate-drop distributions
    dr = res[res.exp == "drift"]
    if len(dr):
        g = dr[dr.r > 0].groupby(["dataset", "attacked"]).d.describe(percentiles=[.1, .9])[["mean", "10%", "90%"]]
        print("\n== per-view rate drop: attacked vs clean views (assumption: attacked >> clean spread) =="); print(g.round(3).to_string())

# ------------------------------------------ RUN ------------------------------------------
# 1) smoke test (~10-20 min):
# pools3 = build_pools(SMOKE3); res3b = run_v3(pools3, SMOKE3); report3(res3b)
# 2) full run (~2 h) after smoke passes:
# pools3 = build_pools(CFG3); res3b = run_v3(pools3, CFG3); report3(res3b)
