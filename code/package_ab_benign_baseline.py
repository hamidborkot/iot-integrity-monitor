# PACKAGE A+B: benign-baseline site calibration, detection certificate, recoverability map.
# Reads saved predictions only. No model loading, fitting, inference or PCAP work.
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, math, zlib, traceback
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score

W = Path('/kaggle/working')
B = Path('/kaggle/input/datasets/mdhamidborkottulla/full-working-backup')
PROJECT = 'FIVE_DATASET_FIXED_OP_V1'
MAIN = ['CICIoT2023', 'CICIoMT2024', 'TONIoT']
APPENDIX = ['CSE', 'NSL']
ALPHAS = (0.01, 0.05)
PREVS = (0.01, 0.05, 0.20, 0.50)
SEEDS = 200
DELTA = 0.025
GOOD_AUROC = 0.75
GATE_GAIN = 0.10
GATE_MIN_DOMAINS = 5

class Stop(Exception):
    pass

def sha_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(8 * 1024 ** 2), b''):
            h.update(b)
    return h.hexdigest()

def sha_obj(o):
    return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()

def jwrite(p, o):
    p = Path(p)
    t = p.with_name(p.name + '.tmp')
    t.write_text(json.dumps(o, indent=2, default=str), encoding='utf-8')
    t.replace(p)

def tbool(x):
    if x in (True, 1, '1', 'True', 'true'):
        return True
    if x in (False, 0, '0', 'False', 'false'):
        return False
    raise Stop('Invalid Boolean in operating_points.csv: ' + repr(x))

def find_inputs():
    for root in (W / PROJECT, B / 'kaggle_working' / PROJECT, B / PROJECT):
        p = root / 'receipt.json'
        if p.is_file():
            r = json.loads(p.read_text())
            if r.get('status') == 'FIVE_DATASET_EXTENSION_COMPLETE' and r.get('datasets_complete') == 5:
                return root, r
    raise Stop('Completed ' + PROJECT + ' outputs not found. Mount the saved output; nothing is rerun.')

def locate_job(root, entry):
    for c in (Path(entry['job_directory']), root / Path(entry['job_directory']).name):
        if (c / 'receipt.json').is_file():
            r = json.loads((c / 'receipt.json').read_text())
            if r.get('status') != 'DATASET_EXTENSION_COMPLETE' or r.get('experiment_signature') != entry['signature']:
                raise Stop('Dataset identity mismatch: ' + entry['dataset'])
            hashes = r.get('artifact_sha256', {})
            if not hashes:
                raise Stop('No artifact hashes for ' + entry['dataset'])
            for name, h in hashes.items():
                if not (c / name).is_file() or sha_file(c / name) != h:
                    raise Stop('Artifact hash mismatch: ' + str(c / name))
            return c, r
    raise Stop('Job directory not mounted for ' + entry['dataset'])

def row_order_key(ids):
    out = []
    for s in ids:
        f, _, i = str(s).rpartition(':')
        try:
            out.append((f, int(i)))
        except ValueError:
            out.append((str(s), 0))
    return out

def conformal_cut(cal, alpha):
    n = len(cal)
    k = math.ceil((n + 1) * (1 - alpha))
    if k > n:
        return np.inf
    return float(np.partition(cal, k - 1)[k - 1])

def eps(n):
    return math.sqrt(math.log(1.0 / DELTA) / (2.0 * n))

def decide(p, cut, strict):
    return (p > cut) if strict else (p >= cut)

def analyze(ds, dom, y, p, ids, src, with_cert, variant):
    ben = np.where(y == 0)[0]
    mal = np.where(y == 1)[0]
    if len(ben) < 20 or len(mal) < 20:
        raise Stop('Too few rows in ' + ds + '/' + dom)
    pb, pm = p[ben], p[mal]
    order = sorted(range(len(ben)), key=lambda i: row_order_key([ids[ben[i]]])[0])
    rows = []
    h = len(ben) // 2
    splits = [('order', np.array(order[:h]), np.array(order[h:]))]
    for seed in range(SEEDS):
        perm = np.random.default_rng([seed, zlib.crc32(dom.encode())]).permutation(len(ben))
        splits.append(('random%d' % seed, perm[:h], perm[h:]))
    for tag, ci, ei in splits:
        cal, ev = pb[ci], pb[ei]
        rng = np.random.default_rng([7, zlib.crc32((dom + tag).encode())])
        for a in ALPHAS:
            c = conformal_cut(cal, a)
            scut, sstrict = src[a]
            ev_fpr = float((ev > c).mean())
            rec_bq = float((pm > c).mean())
            rec_src = float(decide(pm, scut, sstrict).mean())
            src_fpr_ev = float(decide(ev, scut, sstrict).mean())
            en, ee = eps(len(cal)), eps(len(ev))
            base = dict(dataset=ds, domain=dom, variant=variant, split='order' if tag == 'order' else 'random',
                        seed=-1 if tag == 'order' else int(tag[6:]), alpha=a, n_cal=len(cal), n_eval=len(ev),
                        ev_fpr=ev_fpr, covered=ev_fpr <= a + en + ee, exceeds_alpha=ev_fpr > a,
                        recall_bq=rec_bq, recall_src=rec_src, src_fpr_eval=src_fpr_ev)
            if not with_cert or tag == 'order':
                rows.append(dict(base, prev=np.nan))
                continue
            for pi in PREVS:
                ma_t = int(round(pi / (1 - pi) * len(ev)))
                ma = min(ma_t, len(pm))
                sel = rng.choice(len(pm), ma, replace=False)
                ps = pm[sel]
                m = len(ev) + ma
                alerts_b, alerts_a = int((ev > c).sum()), int((ps > c).sum())
                rhat = (alerts_b + alerts_a) / m
                true_det = alerts_a / m
                cert = max(0.0, rhat - eps(m) - a - en)
                cbpe = float(ps[ps > c].sum() / m)
                rows.append(dict(base, prev=pi, m=m, prev_eff=ma / m, capped=ma < ma_t, rhat=rhat,
                                 true_det=true_det, cert=cert, cert_valid=cert <= true_det + 1e-12,
                                 cert_positive=cert > 0, cbpe_est=cbpe, cbpe_err=cbpe - true_det,
                                 cbpe_over=cbpe > true_det + 1e-12))
    return rows

def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = W / ('PACKAGE_AB_' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    prereg = dict(
        created_utc=stamp, alphas=ALPHAS, prevalences=PREVS, split_seeds=SEEDS, delta_per_bound=DELTA,
        main_datasets=MAIN, appendix_datasets=APPENDIX,
        cutoff='conformal (1-alpha) quantile of benign calibration half; alert when score > cutoff',
        certificate='max(0, alert_rate - eps_window - alpha - eps_baseline); DKW eps=sqrt(ln(1/delta)/(2n))',
        hypotheses=dict(
            H1='eval-half benign FPR within alpha + eps_cal + eps_eval in >=95% of random splits (holds by construction; sanity check)',
            H2='>=5 of the 7 domains with target AUROC>=0.75 gain >=0.10 recall at alpha=0.05 versus the source cutoff',
            H3='domains with AUROC<0.5 do not gain (recall_bq <= alpha + 0.02)',
            H4='certificate <= true detected fraction in >=95% of windows',
            H5='order-based split (not verified chronological) shows benign FPR drift beyond the random-split FPR'),
        kill_rule='H2 fails -> drop the recoverability claim; H4 fails -> drop the certificate claim',
        note='Random-split H1/H4 are exchangeable by construction. They are not evidence of cross-time or cross-device validity.')
    prereg['sha256'] = sha_obj({k: v for k, v in prereg.items() if k != 'sha256'})
    jwrite(out / 'PREREGISTRATION.json', prereg)
    print('PREREGISTRATION written, sha256', prereg['sha256'], flush=True)

    root, parent = find_inputs()
    all_rows, aucs, dups, inputs = [], [], [], []
    for entry in parent['datasets']:
        ds = entry['dataset']
        job, jr = locate_job(root, entry)
        pred = pd.read_csv(job / 'fixed_model_predictions.csv', dtype={'row_id': str})
        ops = pd.read_csv(job / 'operating_points.csv')
        need = {'dataset', 'domain', 'row_id', 'label', 'probability'}
        if not need.issubset(pred.columns) or not {'name', 'cut', 'strict'}.issubset(ops.columns):
            raise Stop('Schema mismatch for ' + ds)
        if not pred.label.isin([0, 1]).all() or not pred.probability.between(0, 1).all():
            raise Stop('Invalid labels or probabilities for ' + ds)
        src = {}
        for a, nm in ((0.01, 'SOURCE_FPR_1PCT'), (0.05, 'SOURCE_FPR_5PCT')):
            r = ops[ops.name == nm]
            if len(r) != 1:
                raise Stop('Operating point missing: ' + nm + ' in ' + ds)
            src[a] = (float(r.iloc[0].cut), tbool(r.iloc[0].strict))
        inputs.append(dict(dataset=ds, job=str(job), predictions_sha256=sha_file(job / 'fixed_model_predictions.csv'),
                           operating_points_sha256=sha_file(job / 'operating_points.csv')))
        for dom, g in pred.groupby('domain', sort=True):
            if not str(dom).startswith('target::'):
                continue
            y = g.label.to_numpy(int)
            p = g.probability.to_numpy(float)
            ids = g.row_id.tolist()
            aucs.append(dict(dataset=ds, domain=dom, auroc=float(roc_auc_score(y, p)), n=len(g),
                             benign=int((y == 0).sum()), malicious=int((y == 1).sum())))
            key = pd.Series(list(zip(y.tolist(), np.round(p, 12).tolist())))
            dups.append(dict(dataset=ds, domain=dom, dup_share_proxy=float(key.duplicated(keep=False).mean())))
            all_rows += analyze(ds, dom, y, p, ids, src, True, 'full')
            first = ~key.duplicated().to_numpy()
            idx = np.where(first)[0]
            if (y[idx] == 0).sum() >= 20 and (y[idx] == 1).sum() >= 20:
                all_rows += analyze(ds, dom, y[idx], p[idx], [ids[i] for i in idx], src, False, 'dedup_proxy')
            print('DONE', ds, dom, flush=True)

    R = pd.DataFrame(all_rows)
    A = pd.DataFrame(aucs).merge(pd.DataFrame(dups), on=['dataset', 'domain'])
    A['role'] = np.where(A.dataset.isin(MAIN), 'main', 'appendix')
    R.to_csv(out / 'raw_split_results.csv.gz', index=False)
    A.to_csv(out / 'domain_auroc_and_duplicate_proxy.csv', index=False)

    rnd = R[(R.variant == 'full') & (R.split == 'random')]
    t1 = rnd.drop_duplicates(['dataset', 'domain', 'seed', 'alpha']).groupby(['dataset', 'domain', 'alpha'], as_index=False).agg(
        recall_src=('recall_src', 'mean'), recall_bq=('recall_bq', 'mean'), src_fpr_eval=('src_fpr_eval', 'mean'),
        ev_fpr=('ev_fpr', 'mean'), coverage=('covered', 'mean'), exceeds=('exceeds_alpha', 'mean'))
    t1 = t1.merge(A[['dataset', 'domain', 'auroc', 'role', 'dup_share_proxy']], on=['dataset', 'domain'])
    t1['gain'] = t1.recall_bq - t1.recall_src
    t1['ranking_limited'] = 1 - t1.recall_bq
    t1['regime_posthoc'] = np.where(t1.auroc < 0.5, 'inverted', np.where(t1.auroc >= GOOD_AUROC, 'good_ranking', 'weak_ranking'))
    t1.to_csv(out / 'TABLE_recoverability.csv', index=False)

    c = rnd[rnd.prev.notna()]
    t2 = c.groupby(['dataset', 'domain', 'alpha', 'prev'], as_index=False).agg(
        power=('cert_positive', 'mean'), validity=('cert_valid', 'mean'), cert=('cert', 'mean'), true_det=('true_det', 'mean'),
        cbpe_err=('cbpe_err', 'mean'), cbpe_over=('cbpe_over', 'mean'), capped=('capped', 'mean'), prev_eff=('prev_eff', 'mean'))
    t2.to_csv(out / 'TABLE_certificate_vs_cbpe.csv', index=False)

    o = R[(R.variant == 'full') & (R.split == 'order')][['dataset', 'domain', 'alpha', 'ev_fpr', 'covered', 'recall_bq']].rename(
        columns={'ev_fpr': 'order_fpr', 'covered': 'order_covered', 'recall_bq': 'order_recall'})
    t3 = t1[['dataset', 'domain', 'alpha', 'ev_fpr', 'coverage', 'recall_bq']].merge(o, on=['dataset', 'domain', 'alpha'])
    t3['fpr_drift'] = t3.order_fpr - t3.ev_fpr
    t3.to_csv(out / 'TABLE_order_split_drift.csv', index=False)

    dd = R[(R.variant == 'dedup_proxy') & (R.split == 'random')].groupby(['dataset', 'domain', 'alpha'], as_index=False).agg(
        recall_bq_dedup=('recall_bq', 'mean'), recall_src_dedup=('recall_src', 'mean'), ev_fpr_dedup=('ev_fpr', 'mean'))
    t4 = t1[['dataset', 'domain', 'alpha', 'recall_bq', 'recall_src']].merge(dd, on=['dataset', 'domain', 'alpha'], how='left')
    t4.to_csv(out / 'TABLE_dedup_proxy_sensitivity.csv', index=False)

    g5 = t1[t1.alpha == 0.05]
    good = g5[g5.regime_posthoc == 'good_ranking']
    inv = g5[g5.regime_posthoc == 'inverted']
    h1 = float(t1.coverage.min())
    h2_pass = int((good.gain >= GATE_GAIN).sum())
    h2_main = good[good.role == 'main']
    h3 = bool((inv.recall_bq <= 0.05 + 0.02).all()) if len(inv) else None
    h4 = float(t2.validity.min())
    gate = dict(good_ranking_domains=int(len(good)), good_with_gain_ge_0_10=h2_pass, gate_h2_pass=bool(h2_pass >= GATE_MIN_DOMAINS and len(good) >= 7),
                main_only_good=int(len(h2_main)), main_only_gain_ge_0_10=int((h2_main.gain >= GATE_GAIN).sum()),
                inverted_domains=int(len(inv)), h3_inverted_do_not_gain=h3, h1_min_coverage=h1, h4_min_validity=h4,
                h5_mean_fpr_drift_order_minus_random=float(t3.fpr_drift.mean()))
    jwrite(out / 'GATE_RESULT.json', gate)

    pd.set_option('display.width', 250)
    pd.set_option('display.max_columns', 50)
    print('\nRECOVERABILITY (alpha=0.05)')
    print(g5[['dataset', 'domain', 'role', 'auroc', 'regime_posthoc', 'recall_src', 'recall_bq', 'gain', 'ev_fpr', 'src_fpr_eval', 'coverage', 'dup_share_proxy']].round(3).to_string(index=False))
    print('\nCERTIFICATE vs CBPE-STYLE ESTIMATE (alpha=0.05, mean over splits)')
    print(t2[t2.alpha == 0.05][['dataset', 'domain', 'prev', 'power', 'validity', 'cert', 'true_det', 'cbpe_err', 'cbpe_over']].round(3).to_string(index=False))
    print('\nORDER-SPLIT FPR DRIFT (alpha=0.05)')
    print(t3[t3.alpha == 0.05][['dataset', 'domain', 'ev_fpr', 'order_fpr', 'fpr_drift', 'order_recall']].round(3).to_string(index=False))
    print('\nGATE RESULT'); print(json.dumps(gate, indent=2))
    files = {p.name: sha_file(p) for p in sorted(out.iterdir()) if p.is_file() and p.name != 'RECEIPT.json'}
    receipt = dict(status='PACKAGE_AB_COMPLETE', model_fits=0, model_loads=0, new_inference=0, pcap_work=0,
                   preregistration_sha256=prereg['sha256'], inputs=inputs, gate=gate, output_sha256=files,
                   scope='development evidence on exposed data; random splits are exchangeable by construction',
                   novelty_established=False)
    jwrite(out / 'RECEIPT.json', receipt)
    print('\nOUTPUT', out)

def run():
    try:
        main()
    except Exception as e:
        print('STOPPED:', e)
        traceback.print_exc()

if __name__ == '__main__':
    run()
