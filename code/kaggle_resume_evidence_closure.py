# Self-contained Kaggle resume and evidence-closure runner.
import csv
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import traceback
import zipfile
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

EXPECTED_CONFIG_SHA = "48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea"
WINDOW = 128
MIN_MAL = 5
BUDGETS = (0.05, 0.10)
MODELS = ("PRIMARY", "originator", "responder", "timing", "context")
MAX_FILES = 150000
MAX_SCAN_SECONDS = 180
MAX_ARTIFACT_BYTES = 256 * 1024**2
MAX_ZIPS = 24
MAX_HISTORY_BYTES = 512 * 1024**2
HISTORICAL_NAMES = {
    "estimator_results.csv", "unique_window_evaluation.csv",
    "paired_window_results.csv", "matched_coverage_window_results.csv",
}


def canonical(obj):
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024**2), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def write_table(path, rows, columns=None):
    pd.DataFrame(rows, columns=columns).to_csv(path, index=False)


def origin(a):
    return a["path"] + (" :: " + a["member"] if a.get("member") else "")


def read_artifact(a, limit=MAX_ARTIFACT_BYTES):
    if a["bytes"] > limit:
        raise ValueError("Artifact exceeds read limit: " + origin(a))
    if a.get("member"):
        with zipfile.ZipFile(a["path"]) as z:
            with z.open(a["member"]) as f:
                raw = f.read(limit + 1)
    else:
        with Path(a["path"]).open("rb") as f:
            raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Artifact exceeds read limit: " + origin(a))
    # Some earlier backups contain text pointers rather than the actual file.
    if len(raw) < 4096:
        try:
            s = raw.decode("utf-8-sig").strip()
        except UnicodeDecodeError:
            s = ""
        if s.startswith("/kaggle/") and "\n" not in s and "\r" not in s:
            raise ValueError("Backup contains a path pointer, not artifact bytes: " + origin(a))
    return raw


def wanted(name):
    base = Path(name).name
    return (base in {"configuration.json", "source_validation_cache.npz"}
            or base.endswith(".parquet")
            or base in HISTORICAL_NAMES
            or (base.startswith("results_") and "full4" in base and base.endswith(".csv")))


def small_zip_index(path):
    size = path.stat().st_size
    with path.open("rb") as f:
        f.seek(max(0, size - 65557))
        tail = f.read(65557)
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or pos + 22 > len(tail):
        raise ValueError("ZIP directory not located")
    vals = struct.unpack_from("<4s4H2LH", tail, pos)
    if pos + 22 + vals[-1] != len(tail):
        raise ValueError("ZIP end-directory layout unresolved")
    if vals[1] or vals[2] or vals[4] == 65535 or vals[5] == 0xffffffff or vals[6] == 0xffffffff:
        raise ValueError("ZIP64/multidisk indexing deferred")
    if vals[5] > 32 * 1024**2:
        raise ValueError("ZIP central directory exceeds metadata budget")
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) > MAX_FILES:
            raise ValueError("ZIP member count exceeds metadata budget")
        return [{"path": str(path), "member": q.filename, "bytes": q.file_size,
                 "name": Path(q.filename).name}
                for q in z.infolist() if not q.is_dir() and wanted(q.filename)]


def discover(out):
    found, archives, issues = [], [], []
    start = time.monotonic()
    seen_files = 0
    complete = True
    for root in (Path("/kaggle/working"), Path("/kaggle/input")):
        if not root.is_dir():
            continue
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in {".git", "__pycache__"}
                             and not (Path(directory) / d).name.startswith("CLOSING_FINISH_"))
            for name in sorted(files):
                if seen_files >= MAX_FILES or time.monotonic() - start > MAX_SCAN_SECONDS:
                    complete = False
                    break
                seen_files += 1
                p = Path(directory) / name
                try:
                    size = p.stat().st_size
                    if wanted(name):
                        found.append({"path": str(p), "member": "", "bytes": size, "name": name})
                    elif name.lower().endswith(".zip"):
                        archives.append(p)
                except OSError as e:
                    issues.append({"stage": "metadata", "artifact": str(p), "error": str(e)})
            if not complete:
                break
        if not complete:
            break
    for p in archives[:MAX_ZIPS]:
        if time.monotonic() - start > MAX_SCAN_SECONDS:
            complete = False
            break
        try:
            found.extend(small_zip_index(p))
        except Exception as e:
            issues.append({"stage": "archive", "artifact": str(p), "error": str(e)})
    if len(archives) > MAX_ZIPS:
        complete = False
    # Metadata scan only; raw datasets, labels, PCAPs, and models are not opened.
    write_table(out / "discovery_issues.csv", issues, ["stage", "artifact", "error"])
    return found, {"files_seen": seen_files, "bounded_scan_complete": complete,
                   "archives_seen": len(archives), "archives_attempted": min(len(archives), MAX_ZIPS)}


def recover_config(items, out):
    matches, issues = {}, []
    for a in items:
        if a["name"] != "configuration.json" or a["bytes"] > 2 * 1024**2:
            continue
        try:
            raw = read_artifact(a, 2 * 1024**2)
            cfg = json.loads(raw)
            if canonical(cfg) == EXPECTED_CONFIG_SHA:
                matches[origin(a)] = (cfg, raw)
        except Exception as e:
            issues.append({"artifact": origin(a), "error": str(e)})
    write_table(out / "configuration_read_issues.csv", issues, ["artifact", "error"])
    if not matches:
        raise FileNotFoundError("Missing exact source-driver configuration: " + EXPECTED_CONFIG_SHA)
    where = sorted(matches)[0]
    cfg, raw = matches[where]
    (out / "inputs" / "configuration.json").write_bytes(raw)
    return cfg, where


def recover_allocation(cfg, items, out):
    expected = cfg["allocation_sha256"]
    named = Path(cfg["allocation_path"]).name
    candidates = [a for a in items if a["name"] == named and a["bytes"] <= MAX_ARTIFACT_BYTES]
    candidates.sort(key=lambda a: (a["path"] != cfg["allocation_path"], bool(a["member"]), origin(a)))
    for a in candidates:
        try:
            raw = read_artifact(a)
        except Exception:
            continue
        if sha_bytes(raw) == expected:
            dest = out / "inputs" / "source_allocations.parquet"
            dest.write_bytes(raw)
            df = pd.read_parquet(dest)
            if df["record_id"].isna().any() or df["record_id"].astype(str).duplicated().any():
                raise ValueError("Allocation IDs are missing or duplicated")
            return df, origin(a)
    raise FileNotFoundError("Missing byte-verified allocation: " + named + " SHA256=" + expected)


def decode_ids(values):
    return np.asarray([v.decode() if isinstance(v, bytes) else str(v) for v in values], dtype=str)


def metrics(y, p, threshold):
    d = p >= threshold
    positive = y == 1
    negative = y == 0
    tp = int(np.sum(d & positive)); fn = int(np.sum(~d & positive))
    fp = int(np.sum(d & negative)); tn = int(np.sum(~d & negative))
    tpr = tp / (tp + fn) if tp + fn else np.nan
    fpr = fp / (fp + tn) if fp + tn else np.nan
    return {"records": len(y), "TN": tn, "FP": fp, "FN": fn, "TP": tp,
            "accuracy": float(np.mean(d == y)), "malicious_recall": tpr,
            "benign_FPR": fpr, "balanced_accuracy": (tpr + 1 - fpr) / 2}


def validated_folds(cache_path, cfg, allocation):
    role = cfg["role_column"]
    if role not in allocation:
        raise ValueError("Frozen role column missing")
    threshold = float(cfg["classification_threshold"])
    if threshold != 0.5:
        raise ValueError("This reproduction requires the executed threshold 0.5")
    indexed = allocation.copy()
    indexed["record_id"] = indexed["record_id"].astype(str)
    indexed = indexed.set_index("record_id", drop=False)
    folds = []
    with np.load(cache_path, allow_pickle=False) as cache:
        for schema in cfg["schemas"]:
            for held in cfg["sources"]:
                expected = allocation.loc[(allocation["source_scenario"].astype(str) == held)
                                          & (allocation[role].astype(str) == "source_validation"), "record_id"]
                expected_ids = set(expected.astype(str))
                if not expected_ids:
                    raise ValueError("Empty frozen validation fold: " + held)
                for seed in cfg["seeds"]:
                    key = schema.replace("_", "").lower() + "__" + held.replace("-", "").lower() + "__" + str(seed)
                    yraw = np.asarray(cache[key + "__y"])
                    if yraw.ndim != 1 or not np.isin(yraw, [0, 1]).all():
                        raise ValueError("Nonbinary or malformed labels: " + key)
                    y = yraw.astype(int)
                    possible_ids = []
                    for name in cache.files:
                        if not name.startswith(key + "__") or "id" not in name[len(key) + 2:].lower():
                            continue
                        a = np.asarray(cache[name])
                        if a.ndim == 1 and len(a) == len(y) and a.dtype.kind in "US":
                            ids = decode_ids(a)
                            if len(set(ids)) == len(ids) and set(ids) == expected_ids:
                                possible_ids.append((name, ids))
                    if not possible_ids:
                        raise ValueError("No cache ID array matches the entire frozen fold: " + key)
                    names, ids = possible_ids[0]
                    if any(not np.array_equal(ids, other) for _, other in possible_ids[1:]):
                        raise ValueError("Conflicting cache ID arrays: " + key)
                    orderdf = indexed.loc[ids]
                    # record_id is retained with drop=False; compare the actual index too.
                    if not np.array_equal(orderdf.index.to_numpy(dtype=str), ids):
                        raise ValueError("Record ordering mismatch: " + key)
                    if not np.array_equal(orderdf["y"].to_numpy(), y):
                        raise ValueError("Allocation/cache label mismatch: " + key)
                    probabilities = {}
                    for model in MODELS:
                        p = np.asarray(cache[key + "__p_" + model], dtype=float)
                        if p.shape != y.shape or not np.isfinite(p).all() or np.any((p < 0) | (p > 1)):
                            raise ValueError("Invalid probability array: " + key + " " + model)
                        probabilities[model] = p
                    folds.append({"schema": schema, "held_capture": held, "seed": seed,
                                  "key": key, "id_array": names, "ids": ids, "y": y, "p": probabilities})
    return folds


def recover_cache(cfg, allocation, items, out):
    candidates = sorted((a for a in items if a["name"] == "source_validation_cache.npz"
                         and a["bytes"] <= MAX_ARTIFACT_BYTES), key=origin)
    valid, issues = {}, []
    scratch = out / "inputs" / "cache_candidate.npz"
    for a in candidates:
        try:
            raw = read_artifact(a)
            h = sha_bytes(raw)
            if h in valid:
                continue
            scratch.write_bytes(raw)
            folds = validated_folds(scratch, cfg, allocation)
            valid[h] = (raw, folds, origin(a))
        except Exception as e:
            issues.append({"artifact": origin(a), "error": str(e)})
    if scratch.exists():
        scratch.unlink()  # Only this runner's temporary candidate; no input is deleted.
    write_table(out / "cache_validation_issues.csv", issues, ["artifact", "error"])
    if not valid:
        raise FileNotFoundError("No valid source_validation_cache.npz recovered. See cache_validation_issues.csv.")
    values = list(valid.values())
    first = values[0]
    for _, other_folds, _ in values[1:]:
        for a, b in zip(first[1], other_folds):
            if (not np.array_equal(a["ids"], b["ids"]) or not np.array_equal(a["y"], b["y"])
                or any(not np.array_equal(a["p"][m], b["p"][m]) for m in MODELS)):
                raise ValueError("Multiple numerically conflicting validated caches. No automatic latest-file selection.")
    dest = out / "inputs" / "source_validation_cache.npz"
    dest.write_bytes(first[0])
    return first[1], first[2]


def compute_tables(folds, cfg, destination):
    destination.mkdir(exist_ok=True)
    metric_rows, window_rows, rank_rows, counts, dependence = [], [], [], [], []
    threshold = cfg["classification_threshold"]
    for fold in folds:
        tags = {k: fold[k] for k in ("schema", "held_capture", "seed")}
        y, p = fold["y"], fold["p"]
        errors = {}
        for m in MODELS:
            metric_rows.append({**tags, "model": m, **metrics(y, p[m], threshold)})
            errors[m] = (p[m] >= threshold) != y
        for left, right in combinations(MODELS, 2):
            a, b = errors[left].astype(float), errors[right].astype(float)
            corr = float(np.corrcoef(a, b)[0, 1]) if np.std(a) > 0 and np.std(b) > 0 else np.nan
            dependence.append({**tags, "left": left, "right": right, "error_correlation": corr,
                               "decision_disagreement": float(np.mean((p[left] >= threshold) != (p[right] >= threshold))),
                               "joint_error_rate": float(np.mean(errors[left] & errors[right]))})
        fn = (p["PRIMARY"] < threshold) & (y == 1)
        nwin = len(y) // WINDOW
        used = nwin * WINDOW
        wi = np.arange(used).reshape(nwin, WINDOW)
        malicious = y[wi].sum(axis=1)
        win_fn = fn[wi].sum(axis=1)
        assess = malicious >= MIN_MAL
        damaging = assess & (win_fn >= 1)
        conf = np.maximum(p["PRIMARY"], 1 - p["PRIMARY"])[wi].mean(axis=1)
        dis = np.std(np.stack([p[m] for m in MODELS[1:]]), axis=0)[wi].mean(axis=1)
        margin = np.abs(p["PRIMARY"] - 0.5)[wi].mean(axis=1)
        signals = {"composite_dis_conf": dis * (1 - conf), "confidence": conf,
                   "view_disagreement": dis, "primary_margin": margin,
                   "random": np.random.default_rng(fold["seed"]).random(nwin)}
        counts.append({**tags, "total_records": len(y), "full_windows": nwin,
                       "used_records": used, "excluded_tail_records": len(y) - used,
                       "assessable_windows": int(assess.sum()), "damaging_windows": int(damaging.sum()),
                       "total_fn_records": int(fn.sum()), "windowed_fn_records": int(fn[:used].sum()),
                       "tail_fn_records": int(fn[used:].sum())})
        for signal, score in signals.items():
            order = np.argsort(-score)  # Exact direction and tie behavior of the executed cell.
            for budget in BUDGETS:
                k = max(1, int(np.floor(budget * nwin))) if nwin else 0
                selected = order[:k]
                recovered = int(damaging[selected].sum())
                nd = int(damaging.sum())
                rank_rows.append({**tags, "signal": signal, "nominal_budget": budget,
                                  "windows": nwin, "reviewed": k,
                                  "actual_budget": k / nwin if nwin else np.nan,
                                  "damaging": nd, "damaging_recovered": recovered,
                                  "recall_at_budget": recovered / nd if nd else np.nan,
                                  "uniform_random_expected_recall": k / nwin if nd else np.nan})
        for i in range(nwin):
            window_rows.append({**tags, "window_id": i, "first_record_id": fold["ids"][i * WINDOW],
                                "last_record_id": fold["ids"][(i + 1) * WINDOW - 1],
                                "malicious": int(malicious[i]), "fn_count": int(win_fn[i]),
                                "assessable": bool(assess[i]), "damaging": bool(damaging[i]),
                                **{name: float(score[i]) for name, score in signals.items()}})
    met = pd.DataFrame(metric_rows)
    rankings = pd.DataFrame(rank_rows)
    met.to_csv(destination / "source_metrics_by_seed.csv", index=False)
    pd.DataFrame(dependence).to_csv(destination / "source_dependence_by_seed.csv", index=False)
    pd.DataFrame(counts).to_csv(destination / "window_counts_by_seed.csv", index=False)
    pd.DataFrame(window_rows).to_csv(destination / "window_details.csv", index=False)
    rankings.to_csv(destination / "window_rankings_by_seed.csv", index=False)
    rankings.groupby(["schema", "held_capture", "signal", "nominal_budget"], as_index=False).agg(
        mean_recall=("recall_at_budget", "mean"), valid_seeds=("recall_at_budget", "count"),
        n_seeds=("seed", "nunique"), reviewed=("reviewed", "first"), actual_budget=("actual_budget", "first")
    ).to_csv(destination / "window_rankings_descriptive.csv", index=False)
    policy = cfg["eligibility"]
    gate_rows = []
    foldmeans = met.groupby(["schema", "held_capture", "model"], as_index=False)["balanced_accuracy"].mean()
    for schema in cfg["schemas"]:
        block = foldmeans[foldmeans["schema"].eq(schema)]
        primary = block.loc[block["model"].eq("PRIMARY"), "balanced_accuracy"]
        pmin = float(primary.min())
        primary_ok = bool(primary.notna().all() and len(primary) == len(cfg["sources"])
                          and pmin >= policy["primary_min_fold_mean_bacc"])
        eligible = []
        for m in MODELS[1:]:
            v = block.loc[block["model"].eq(m), "balanced_accuracy"]
            ok = bool(v.notna().all() and len(v) == len(cfg["sources"])
                      and v.mean() >= policy["view_mean_fold_bacc"]
                      and v.min() > policy["view_each_fold_mean_bacc_strictly_above"])
            if ok:
                eligible.append(m)
        views_ok = len(eligible) >= policy["minimum_views"]
        gate_rows.append({"schema": schema, "minimum_fold_mean_primary_bacc": pmin,
                          "primary_required": policy["primary_min_fold_mean_bacc"],
                          "primary_pass": primary_ok, "eligible_views": "|".join(eligible),
                          "eligible_view_count": len(eligible), "views_required": policy["minimum_views"],
                          "views_pass": views_ok, "source_gate_pass": primary_ok and views_ok})
    foldmeans.to_csv(destination / "fold_mean_bacc.csv", index=False)
    write_table(destination / "source_gate_decision.csv", gate_rows)
    return gate_rows


def preserve_history(items, out):
    folder = out / "historical_tables"
    folder.mkdir()
    rows, failures, unique = [], [], {}
    used = 0
    candidates = sorted((a for a in items if a["name"] in HISTORICAL_NAMES
                         or (a["name"].startswith("results_") and "full4" in a["name"]
                             and a["name"].endswith(".csv"))), key=origin)
    for a in candidates:
        row = {"artifact": origin(a), "logical_name": a["name"], "sha256": "",
               "status": "", "rows": None, "saved_copy": "", "scope": "HISTORICAL_CANDIDATE_NOT_ACCEPTED_AUTOMATICALLY"}
        try:
            if a["bytes"] > 32 * 1024**2 or used + a["bytes"] > MAX_HISTORY_BYTES:
                row["status"] = "DEFERRED_SIZE_OR_READ_BUDGET"
            else:
                raw = read_artifact(a, 32 * 1024**2)
                used += len(raw)
                digest = sha_bytes(raw)
                row["sha256"] = digest
                if digest not in unique:
                    frame = pd.read_csv(io.BytesIO(raw), low_memory=False)
                    dest = folder / (digest + "__" + a["name"])
                    dest.write_bytes(raw)
                    unique[digest] = (str(dest.relative_to(out)), len(frame), list(frame.columns))
                    row["status"] = "PRESERVED_UNIQUE"
                else:
                    row["status"] = "BYTE_IDENTICAL_DUPLICATE"
                row["saved_copy"], row["rows"], _ = unique[digest]
        except Exception as e:
            row["status"] = "READ_FAILED"
            failures.append({"artifact": origin(a), "error": str(e)})
        rows.append(row)
    write_table(out / "historical_table_manifest.csv", rows,
                ["artifact", "logical_name", "sha256", "status", "rows", "saved_copy", "scope"])
    write_table(out / "historical_read_issues.csv", failures, ["artifact", "error"])
    write_json(out / "historical_table_schemas.json", {k: {"copy": v[0], "rows": v[1], "columns": v[2]}
                                                    for k, v in unique.items()})
    return {"candidates": len(candidates), "unique_tables_preserved": len(unique),
            "read_failures": len(failures), "raw_full4_filename_candidates": sum("full4" in a["name"] for a in candidates)}


CHILD = r"""
import hashlib, json, sys
from pathlib import Path
import numpy as np
import pandas as pd
root = Path(sys.argv[1])
cfg = json.loads((root/'inputs/configuration.json').read_text())
manifest = json.loads((root/'input_manifest.json').read_text())
for name, digest in manifest['copied_input_sha256'].items():
    h = hashlib.sha256()
    with (root/name).open('rb') as f:
        for b in iter(lambda: f.read(4*1024**2), b''): h.update(b)
    if h.hexdigest() != digest: raise ValueError('Copied input changed: '+name)
rows = []
with np.load(root/'inputs/source_validation_cache.npz', allow_pickle=False) as c:
    for fold in manifest['folds']:
        key = fold['key']; y = c[key+'__y']; positive = y==1; negative = y==0
        for model in ['PRIMARY','originator','responder','timing','context']:
            p = c[key+'__p_'+model]; d = p >= cfg['classification_threshold']
            tp=int(np.sum(d & positive)); fn=int(np.sum(~d & positive))
            fp=int(np.sum(d & negative)); tn=int(np.sum(~d & negative))
            tpr=tp/(tp+fn) if tp+fn else np.nan
            fpr=fp/(fp+tn) if fp+tn else np.nan
            rows.append({k:fold[k] for k in ['schema','held_capture','seed']} |
                        {'model':model,'records':len(y),'TN':tn,'FP':fp,'FN':fn,'TP':tp,
                         'accuracy':float(np.mean(d==y)),'malicious_recall':tpr,'benign_FPR':fpr,
                         'balanced_accuracy':(tpr+1-fpr)/2})
a=pd.DataFrame(rows)
b=pd.read_csv(root/'source_tables/source_metrics_by_seed.csv')
pd.testing.assert_frame_equal(a,b,check_exact=False,rtol=0,atol=1e-12)
a.to_csv(root/'clean_process_source_metrics.csv',index=False)
(root/'clean_process_result.json').write_text(json.dumps(
    {'status':'PASSED','rows_recomputed':len(a),'scope':'Saved-source primary/view metrics only',
     'tolerance':1e-12,'models_loaded':False,'models_trained':False,'new_targets_read':False},indent=2))
"""


def clean_reproduce(out):
    child = out / "reproduce_source_metrics.py"
    child.write_text(CHILD, encoding="utf-8")
    started = time.monotonic()
    proc = subprocess.run([sys.executable, str(child), str(out)], capture_output=True, text=True, timeout=120)
    (out / "clean_process_stdout.txt").write_text(proc.stdout)
    (out / "clean_process_stderr.txt").write_text(proc.stderr)
    result = {"status": "PASSED" if proc.returncode == 0 else "FAILED", "returncode": proc.returncode,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "scope": "Clean-process reproduction of saved-source primary/view metrics; not full E10"}
    write_json(out / "clean_process_receipt.json", result)
    if proc.returncode:
        raise RuntimeError("Clean-process reproduction failed; see clean_process_stderr.txt")
    return result


def main():
    started = time.monotonic()
    work = Path("/kaggle/working")
    if not work.is_dir():
        raise RuntimeError("Run this cell in Kaggle; /kaggle/working is absent")
    out = work / ("CLOSING_FINISH_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    out.mkdir()
    (out / "inputs").mkdir()
    failures = []
    receipt = {"stage": "Resume and bounded evidence closure", "output_directory": str(out),
               "source_status": "NOT_STARTED", "models_trained": False, "models_loaded": False,
               "new_target_records_read": False, "packet_experiments_run": False,
               "original_inputs_modified": False, "source_gate_overridden": False,
               "window_definition": {"records": WINDOW, "min_malicious": MIN_MAL,
                                     "order": "EXISTING_CACHE_ORDER_NOT_VERIFIED_CHRONOLOGICAL"},
               "new_ranking_signals_added": False, "seeds_are_independent_captures": False}
    items, scan = discover(out)
    receipt["discovery"] = scan
    print("[1/4] Resume discovery finished; recovering exact saved source artifacts.", flush=True)
    gate_rows = None
    try:
        cfg, cfg_origin = recover_config(items, out)
        allocation, allocation_origin = recover_allocation(cfg, items, out)
        folds, cache_origin = recover_cache(cfg, allocation, items, out)
        print("[2/4] Cache labels, record IDs, fold membership, and probabilities verified.", flush=True)
        manifest = {"configuration_canonical_sha256": EXPECTED_CONFIG_SHA,
                    "original_locations": {"config": cfg_origin, "allocation": allocation_origin, "cache": cache_origin},
                    "copied_input_sha256": {str(p.relative_to(out)): sha_file(p) for p in (out / "inputs").iterdir()},
                    "folds": [{k: f[k] for k in ("schema", "held_capture", "seed", "key", "id_array")} for f in folds],
                    "allocation_cache_membership_and_labels_verified": True,
                    "cache_model_provenance_independently_verified": False,
                    "thresholds_loaded_from_existing_driver_not_changed": cfg["eligibility"]}
        write_json(out / "input_manifest.json", manifest)
        gate_rows = compute_tables(folds, cfg, out / "source_tables")
        receipt["source_status"] = "SAVED_SOURCE_ANALYSIS_COMPLETE"
        receipt["source_gate_decision"] = gate_rows
        receipt["clean_process"] = clean_reproduce(out)
        print("[3/4] Source metrics, dependence, executed-window check, gate decision, and clean-process metrics completed.", flush=True)
    except Exception as e:
        receipt["source_status"] = "BLOCKED_OR_FAILED"
        failures.append({"stage": "source", "error": f"{type(e).__name__}: {e}"})
        (out / "source_failure_traceback.txt").write_text(traceback.format_exc())
        print("SOURCE BLOCKER:", e, flush=True)
    try:
        receipt["historical_tables"] = preserve_history(items, out)
    except Exception as e:
        failures.append({"stage": "historical_preservation", "error": f"{type(e).__name__}: {e}"})
        receipt["historical_tables"] = {"status": "FAILED"}
    print("[4/4] Historical-table preservation finished; writing package and remaining-work ledger.", flush=True)
    if receipt["source_status"] != "SAVED_SOURCE_ANALYSIS_COMPLETE":
        reason = "SOURCE_ARTIFACT_OR_VALIDATION_BLOCKER"
    elif any(r["source_gate_pass"] for r in gate_rows):
        reason = "SOURCE_GATE_PASSES_FOR_AT_LEAST_ONE_SCHEMA_BUT_FINAL_MONITOR_AND_TARGET_PROTOCOL_NOT_VERIFIED"
    else:
        reason = "CURRENT_CANDIDATES_FAIL_EXISTING_SOURCE_GATE"
    ledger = [
        {"package": "E2/E3 evidence", "status": receipt["source_status"], "reason": "Recomputed from exact allocation plus validated cache; no retraining"},
        {"package": "Executed window diagnostic", "status": receipt["source_status"], "reason": "Original 128/5 definition and descending score directions retained; cache-order only"},
        {"package": "E4 confirmatory calibration", "status": "NOT_EXECUTED", "reason": reason},
        {"package": "E5 new packet controls/target freeze", "status": "NOT_EXECUTED", "reason": "No verified final eligible-monitor/target-freeze contract is supplied to this runner"},
        {"package": "E6/E7 new held-out confirmation", "status": "NOT_EXECUTED", "reason": reason},
        {"package": "E8 historical evidence", "status": "PRESERVATION_ONLY", "reason": "Hashed unique tables saved; validity, model identity, and accepted/superseded scope not inferred"},
        {"package": "E9 source descriptive analysis", "status": receipt["source_status"], "reason": "Fold/seed metrics, dependence, window counts and ranking; no cross-seed significance claims"},
        {"package": "E10 saved-source metric reproduction", "status": receipt.get("clean_process", {}).get("status", "NOT_COMPLETED"), "reason": "Only metric-table component; no deployed-monitor latency or hardware-resource claim"},
    ]
    write_table(out / "execution_ledger.csv", ledger)
    write_json(out / "remaining_work.json", {
        "decision_basis": reason, "all_E0_to_E10_complete": False,
        "not_completed": ["Final E4 monitor calibration", "New E5 packet controls/target freeze",
                          "New E6/E7 held-out execution", "E8 validity/accepted-table reconciliation",
                          "Full E9 impact/statistical analysis", "Full E10 model/monitor resource measurement"],
        "if_source_artifacts_missing": "Mount a saved backup containing today's source configuration, allocation and validation cache. A disconnected runtime cannot restore unsaved files.",
        "if_source_gate_failed": "Do not change gates or score new targets as successful-method confirmation. Preserve the negative candidate result.",
        "scope_corrections": ["Class-capped selected source panels are not natural-prevalence target validation.",
                              "Cached record order is not established as time order.",
                              "Confidence and primary_margin are retained in their original descending directions; they are not low-confidence-review baselines.",
                              "All-damaging folds and folds without damaging windows cannot establish useful discrimination.",
                              "Nominal review budgets may select the same k; report actual_budget.",
                              "Window damage means at least one FN and at least five malicious records; not a calibrated operational recall threshold."]})
    write_table(out / "errors.csv", failures, ["stage", "error"])
    receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
    receipt["status"] = "BOUNDED_COMPONENTS_COMPLETED" if not failures else "PARTIAL_WITH_EXPLICIT_BLOCKERS"
    receipt["all_remaining_experiments_complete"] = False
    receipt["decision_basis"] = reason
    write_json(out / "receipt.json", receipt)
    outputs = [{"file": str(p.relative_to(out)), "bytes": p.stat().st_size, "sha256": sha_file(p)}
               for p in sorted(out.rglob("*")) if p.is_file()]
    write_table(out / "file_manifest.csv", outputs, ["file", "bytes", "sha256"])
    zip_path = Path(shutil.make_archive(str(out) + "_PACK", "zip", root_dir=out))
    print("\n=== EXECUTION LEDGER ===")
    print(pd.DataFrame(ledger).to_string(index=False))
    if gate_rows is not None:
        print("\n=== RECOMPUTED SOURCE GATE ===")
        print(pd.DataFrame(gate_rows).to_string(index=False))
    print("\n=== RECEIPT ===")
    print(json.dumps(receipt, indent=2, default=str))
    print("\nPersistent evidence pack:", zip_path)
    print("Save this evidence pack as a Kaggle output/dataset before another reset.")
    return str(out)


CLOSING_FINISH_DIRECTORY = main()
