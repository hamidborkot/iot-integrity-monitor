from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import collections
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import shutil
import traceback
import warnings
import zipfile

import joblib
import numpy as np
import pandas as pd
from threadpoolctl import threadpool_limits

VERSION = "capture49_association_screen_v1"
SCENARIO = "CTU-IoT-Malware-Capture-49-1"
OWNER = Path("/kaggle/input/datasets/mdhamidborkottulla")
ROOTS = [OWNER / n for n in [
    "all-kaggle-work", "complete-backup", "full-backup", "last-day-backup",
    "one-last", "ran-files", "the-last-update", "whole-in-one",
    "the-last-days-backup", "research-closing-code", "research-experiment-suite"
]] + [Path("/kaggle/working")]
FEATURES = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
            "orig_ip_bytes", "resp_ip_bytes", "missed_bytes", "proto"]
SEEDS = [8101, 8102, 8103]
MAX_MEMBER = 256 * 1024**2

class Blocked(Exception):
    pass

def save_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")

@contextmanager
def opened(asset):
    if asset["member"]:
        with zipfile.ZipFile(asset["path"]) as z, z.open(asset["member"]) as f:
            yield f
    else:
        with open(asset["path"], "rb") as f:
            yield f

def digest(asset):
    h = hashlib.sha256()
    with opened(asset) as f:
        for b in iter(lambda: f.read(4 * 1024**2), b""):
            h.update(b)
    return h.hexdigest()

def category(path):
    s = str(path).replace("\\", "/")
    name = s.split("/")[-1]
    if name == "frozen_source_models.joblib" and "TRACE_CONFIRMATORY_SOURCE_MODELS_v1_1/" in s:
        return "models"
    if SCENARIO in s and "E5_EXPLORATORY_REAL_PCAP_PACING_SEARCH_v1/" in s:
        if s.endswith("/delay_0s/candidate_selected_features.csv"):
            return "clean"
        if s.endswith("/delay_10s/candidate_selected_features.csv"):
            return "selected10"
    if "E5_CAPTURE49_FRAGMENT_DIAGNOSTIC_" in s:
        if name == "associated_connection_records.csv":
            return "associated"
        if name == "per_original_flow_counter_reconciliation.csv":
            return "reconciliation"
    return None

def discover(out):
    assets, errors, mounts = [], [], []
    archives = []
    for root in ROOTS:
        mounts.append({"path": str(root), "exists": root.is_dir()})
        if not root.is_dir():
            continue
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}
                       and not d.startswith("LINEAGE_SCREEN_BATCH1_")]
            for name in files:
                p = Path(current) / name
                if p.is_symlink():
                    continue
                try:
                    kind = category(p)
                    if kind:
                        assets.append(dict(kind=kind, path=str(p), member="", bytes=p.stat().st_size))
                    elif p.suffix.lower() == ".zip":
                        archives.append(p)
                except Exception as e:
                    errors.append({"path": str(p), "error": repr(e)})
    # Read ZIP directories, not their dataset contents; no archive is unpacked.
    for p in archives:
        try:
            with zipfile.ZipFile(p) as z:
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    kind = category(info.filename)
                    if kind:
                        assets.append(dict(kind=kind, path=str(p), member=info.filename,
                                           bytes=info.file_size))
        except Exception as e:
            errors.append({"path": str(p), "error": repr(e)})
    pd.DataFrame(mounts).to_csv(out / "mounts.csv", index=False)
    pd.DataFrame(errors, columns=["path", "error"]).to_csv(out / "discovery_errors.csv", index=False)
    pd.DataFrame(assets, columns=["kind", "path", "member", "bytes"]).to_csv(out / "candidates.csv", index=False)
    selected, resolution = {}, []
    for kind in ["clean", "selected10", "associated", "reconciliation", "models"]:
        candidates = [a for a in assets if a["kind"] == kind]
        variants = collections.defaultdict(list)
        for a in candidates:
            if a["bytes"] > MAX_MEMBER:
                resolution.append({**a, "sha256": "", "status": "OVER_SIZE_LIMIT"})
                continue
            try:
                a = dict(a, sha256=digest(a))
                variants[a["sha256"]].append(a)
                resolution.append({**a, "status": "HASHED"})
            except Exception as e:
                resolution.append({**a, "sha256": "", "status": repr(e)})
        if len(variants) == 1:
            copies = next(iter(variants.values()))
            selected[kind] = min(copies, key=lambda a: (bool(a["member"]), len(a["path"]), a["path"]))
        elif len(variants) > 1:
            selected[kind] = {"conflict": True, "distinct_hashes": list(variants)}
    pd.DataFrame(resolution).to_csv(out / "candidate_hashes.csv", index=False)
    save_json(out / "resolved_inputs.json", selected)
    missing = [k for k in ["clean", "selected10", "associated", "reconciliation", "models"]
               if k not in selected or selected[k].get("conflict")]
    if missing:
        raise Blocked("Missing or content-conflicting exact inputs: " + ", ".join(missing)
                      + ". See candidates.csv and candidate_hashes.csv; no arbitrary version selected.")
    return selected

def frame(asset):
    with opened(asset) as f:
        data = f.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        raise Blocked("Input exceeds bounded read limit")
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
        if len(data) > MAX_MEMBER:
            raise Blocked("Decompressed table exceeds limit")
    return pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)

def require(df, columns, name):
    missing = set(columns) - set(df.columns)
    if missing:
        raise Blocked(name + " lacks columns: " + ", ".join(sorted(missing)))

def booleans(series):
    v = series.astype(str).str.strip().str.lower()
    if not v.isin(["true", "false", "1", "0"]).all():
        raise Blocked("Invalid boolean values in " + str(series.name))
    return v.isin(["true", "1"])

def normalize(df):
    out = df.copy()
    require(out, FEATURES, "feature table")
    out["proto"] = out.proto.str.lower()
    if not out.proto.isin(["tcp", "udp", "icmp"]).all():
        raise Blocked("Unexpected protocol outside historical encoder")
    for c in FEATURES[:-1]:
        # Historical inference encoded Zeek '-' as zero. Do not coerce malformed numbers.
        x = pd.to_numeric(out[c].replace({"-": "0", "": "0"}), errors="raise").astype(float)
        if not np.isfinite(x).all() or (x < 0).any():
            raise Blocked("Invalid numeric predictor: " + c)
        out[c] = x
    return out

def matrix(df):
    return np.column_stack([np.log1p(df[FEATURES[:-1]].to_numpy(float)),
                            *[df.proto.eq(p).to_numpy(float) for p in ["tcp", "udp", "icmp"]]])

def p1(model, df):
    if list(model.classes_) != [0, 1]:
        raise Blocked("Unexpected model class ordering")
    p = model.predict_proba(matrix(df))[:, 1]
    if not np.isfinite(p).all():
        raise Blocked("Nonfinite model output")
    return p

def main():
    work = Path("/kaggle/working")
    if not work.is_dir():
        raise RuntimeError("Run this script inside your Kaggle notebook, not this chat environment.")
    out = work / ("LINEAGE_SCREEN_BATCH1_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    out.mkdir(exist_ok=False)
    tests = {"test1": "NOT_RUN", "test2": "NOT_RUN", "test3": "NOT_RUN"}
    receipt = dict(version=VERSION, scenario=SCENARIO, tests=tests,
        models_retrained=False, new_PCAP_replays=0, original_files_overwritten=False,
        packet_lineage_proved=False, malicious_functionality_tested=False,
        scope="Exposed-case screening using historical endpoint/time associations; not activity-recall certification",
        output_directory=str(out))
    save_json(out / "environment.json", {
        "python": platform.python_version(),
        "packages": {p: importlib.metadata.version(p) for p in ["numpy", "pandas", "scikit-learn", "joblib"]},
        "free_GiB": shutil.disk_usage(work).free / 1024**3})
    try:
        if shutil.disk_usage(work).free < 1024**3:
            raise Blocked("Less than 1 GiB free; no data copied or extracted")
        print("Resolving only the five exact capture-49 inputs; no bulk restoration.", flush=True)
        a = discover(out)
        clean, selected = normalize(frame(a["clean"])), normalize(frame(a["selected10"]))
        frag, rec = frame(a["associated"]), frame(a["reconciliation"])
        require(clean, ["ks", "y"], "clean sample")
        require(selected, ["ks", "y"], "10s selected sample")
        if len(clean) != 1024 or clean.ks.duplicated().any() or selected.ks.duplicated().any():
            raise Blocked("Historical 1024-row sample/key contract failed")
        if set(clean.ks) != set(selected.ks):
            raise Blocked("Clean and 10s key sets differ")
        selected = selected.set_index("ks").loc[clean.ks].reset_index()
        y = pd.to_numeric(clean.y, errors="raise").to_numpy(int)
        if set(y) != {0, 1} or not np.array_equal(y, pd.to_numeric(selected.y).to_numpy(int)):
            raise Blocked("Binary label/membership contract failed")
        if (y == 1).sum() != 512:
            raise Blocked("Expected 512 historical malicious rows")
        require(frag, ["associated_original_ks", "association_ambiguous", "is_original_start_key",
                       "original_direction_pkts", "original_direction_ip_bytes", "uid", "ts"] + FEATURES,
                "associated records")
        require(rec, ["ks", "associated_records", "ambiguous_association",
                      "packet_counter_reconciles", "IP_byte_counter_reconciles"], "reconciliation")
        if rec.ks.duplicated().any():
            raise Blocked("Duplicate original keys in reconciliation")
        keys = set(clean.loc[y == 1, "ks"])
        if set(rec.ks) != keys or not set(frag.associated_original_ks).issubset(keys):
            raise Blocked("Association/reconciliation population differs from selected malicious units")
        if frag.duplicated(["associated_original_ks", "uid"]).any():
            raise Blocked("Duplicate associated connection rows")
        frag = normalize(frag)
        frag["ambiguous"] = booleans(frag.association_ambiguous)
        frag["start_key"] = booleans(frag.is_original_start_key)
        for c in ["original_direction_pkts", "original_direction_ip_bytes"]:
            frag[c] = pd.to_numeric(frag[c], errors="raise")
            if not np.isfinite(frag[c]).all() or (frag[c] < 0).any():
                raise Blocked("Invalid association counter")
        shared_uids = set(frag.groupby("uid").associated_original_ks.nunique().loc[lambda x: x > 1].index)
        ci, si, ri = clean.set_index("ks"), selected.set_index("ks"), rec.set_index("ks")
        audit = []
        for k in sorted(keys):
            g = frag[frag.associated_original_ks.eq(k)]
            start = g[g.start_key]
            count_ok = (len(g) == int(ri.loc[k, "associated_records"]))
            pk_ok = bool(np.isclose(g.original_direction_pkts.sum(), ci.loc[k, "orig_pkts"], atol=0, rtol=0))
            byte_ok = bool(np.isclose(g.original_direction_ip_bytes.sum(), ci.loc[k, "orig_ip_bytes"], atol=0, rtol=0))
            numerical_match = len(start) == 1 and np.allclose(
                start[FEATURES[:-1]].to_numpy(float)[0], si.loc[k, FEATURES[:-1]].to_numpy(float), atol=1e-9, rtol=1e-9)
            proto_match = len(start) == 1 and start.iloc[0].proto == si.loc[k, "proto"]
            unambiguous = len(g) > 0 and not g.ambiguous.any() and not g.uid.isin(shared_uids).any()
            audit.append(dict(ks=k, associated_records=len(g), count_matches_summary=count_ok,
                packet_counter_reconciles=pk_ok, IP_byte_counter_reconciles=byte_ok,
                unique_start_key=len(start)==1, start_matches_selected=bool(numerical_match and proto_match),
                association_unambiguous=unambiguous,
                usable_for_conditional_screen=bool(count_ok and pk_ok and byte_ok and unambiguous
                                                  and numerical_match and proto_match)))
        audit = pd.DataFrame(audit)
        audit.to_csv(out / "test1_association_audit.csv", index=False)
        tests["test1"] = "COMPLETED"
        print("\nTEST 1: ASSOCIATION ACCOUNTING", flush=True)
        print(audit.drop(columns="ks").sum(numeric_only=True).to_string())
        # Load only the user's own exact historical model artifact, never recovered code.
        from sklearn.exceptions import InconsistentVersionWarning
        with opened(a["models"]) as f, warnings.catch_warnings():
            warnings.simplefilter("error", InconsistentVersionWarning)
            bundle = joblib.load(io.BytesIO(f.read(MAX_MEMBER + 1)))
        if not isinstance(bundle, dict) or not isinstance(bundle.get("models"), dict):
            raise Blocked("Unexpected historical bundle schema")
        banks = {int(k): v for k, v in bundle["models"].items()}
        if set(banks) != set(SEEDS):
            raise Blocked("Historical model seeds differ; no substitution allowed")
        all_rows, repro = [], []
        with threadpool_limits(limits=2):
            for seed in SEEDS:
                bank = banks[seed]
                if "PRIMARY" not in bank:
                    raise Blocked("PRIMARY model missing")
                model = bank["PRIMARY"]
                p0, p10, pf = p1(model, clean), p1(model, selected), p1(model, frag)
                d0, d10 = p0 >= .5, p10 >= .5
                damage = float((d0 == y).mean() - (d10 == y).mean())
                repro.append(dict(seed=seed, clean_accuracy=float((d0==y).mean()),
                                  selected_record_accuracy=float((d10==y).mean()),
                                  selected_record_damage=damage,
                                  reproduces_historical_half_point_drop=bool(np.isclose(damage,.5,atol=1e-12,rtol=0))))
                fp = frag.assign(probability=pf, prediction=pf>=.5)
                clean_predictions = dict(zip(clean.ks, d0))
                selected_predictions = dict(zip(clean.ks, d10))
                good = audit.set_index("ks").usable_for_conditional_screen.to_dict()
                for k in sorted(keys):
                    g = fp[fp.associated_original_ks.eq(k)]
                    ok = bool(good[k])
                    all_rows.append(dict(seed=seed, ks=k, association_usable=ok,
                        associated_records=len(g), clean_detected=bool(clean_predictions[k]),
                        selected_record_detected=bool(selected_predictions[k]),
                        any_associated_record_alarm=bool(g.prediction.any()) if ok else None,
                        max_associated_probability=float(g.probability.max()) if len(g) else None))
        repro = pd.DataFrame(repro)
        repro.to_csv(out / "test2_historical_reproduction.csv", index=False)
        per = pd.DataFrame(all_rows)
        per.to_csv(out / "test2_per_original_unit_predictions.csv", index=False)
        tests["test2"] = "COMPLETED" if repro.reproduces_historical_half_point_drop.all() else "REPRODUCTION_MISMATCH"
        print("\nTEST 2: FROZEN-MODEL REPRODUCTION", flush=True)
        print(repro.to_string(index=False))
        if tests["test2"] != "COMPLETED":
            raise Blocked("Historical damage did not reproduce. No new result interpreted as same experiment.")
        summary = []
        for seed, g in per.groupby("seed"):
            good = g.association_usable
            detected = g.any_associated_record_alarm.fillna(False).astype(bool)
            lost_selected = g.clean_detected & ~g.selected_record_detected
            recovered = good & lost_selected & detected
            residual = good & lost_selected & ~detected
            unresolved = ~good
            clean_n = int(g.clean_detected.sum())
            associated_n = int((good & detected).sum())
            summary.append(dict(seed=int(seed), original_malicious_units=len(g), usable_associations=int(good.sum()),
                unresolved_units=int(unresolved.sum()), clean_detected_units=clean_n,
                selected_record_detected_units=int(g.selected_record_detected.sum()),
                any_associated_alarm_units=associated_n,
                selected_losses_recovered_by_other_records=int(recovered.sum()),
                selected_losses_without_associated_alarm=int(residual.sum()),
                selected_losses_unresolved=int((lost_selected & unresolved).sum()),
                conditional_alarm_fraction_lower=associated_n/len(g),
                conditional_alarm_fraction_upper=(associated_n+int(unresolved.sum()))/len(g),
                original_unit_detection_not_certified=True))
        summary = pd.DataFrame(summary)
        summary.to_csv(out / "test3_association_sensitivity.csv", index=False)
        tests["test3"] = "COMPLETED_CONDITIONAL_ASSOCIATION_ANALYSIS"
        receipt["status"] = "BATCH1_COMPLETED_NOT_PACKET_LINEAGE_PROOF"
        receipt["result_interpretation"] = (
            "An alarm in an associated record is an offline sensitivity result. Counter reconciliation and "
            "endpoint/time matching do not prove packet lineage, alert attribution, completeness, or functionality.")
        print("\nTEST 3: DOES INCLUDING ASSOCIATED RECORDS CHANGE THE RESULT?", flush=True)
        print(summary.to_string(index=False))
    except Blocked as e:
        receipt["status"] = "BLOCKED_WITH_EXACT_REASON"
        receipt["reason"] = str(e)
        print("\nBLOCKED:", str(e), flush=True)
    except Exception as e:
        receipt["status"] = "FAILED_WITH_SAVED_TRACEBACK"
        receipt["reason"] = repr(e)
        (out / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        print("\nFAILED:", repr(e), flush=True)
    finally:
        receipt["files"] = sorted(p.name for p in out.iterdir() if p.is_file())
        save_json(out / "receipt.json", receipt)
        print("\nRECEIPT\n" + json.dumps(receipt, indent=2, default=str), flush=True)

if __name__ == "__main__":
    main()
