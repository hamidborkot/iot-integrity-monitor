
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
    e = estimators2(Pv_id, yv, Pv)
    e["ANCH_A"] = anchored_adapt(Pv_id, yv, Pv)
    e["ANCH_B"] = anchored_adapt(Pv_id, yv, Pv, second_pass=True)
    for q in QS:
        for t in TAUS: e[f"ANCH_q{q}_t{t}"] = anchored(Pv_id, yv, Pv, q, t)
    return e

def frac_report(res):
    pd.set_option("display.width", 220); a = diff_rows(res)
    g = a.groupby(["dataset", "att", "estimator"]).dabs.mean().unstack()
    dm = a[a.estimator == "ANCH"].groupby(["dataset", "att"]).damage.mean()
    cols = ["ANCH", "ANCH_A", "ANCH_B", "MAJ"] + BASE_EST
    t = g[cols].div(dm, axis=0); t["best_base"] = g[BASE_EST].min(1) / dm; t["damage"] = dm
    print("== differential error as a FRACTION of the true damage (0 = perfect, 1 = blind) ==")
    print(t.round(2).to_string())
