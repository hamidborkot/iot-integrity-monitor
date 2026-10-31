# Aligned-profile reproduction and saved-SPSA replay.
# Original numerical helpers extracted from uploaded notebook cell 75 (one-based).
# No model fitting, new attack optimization, NF inspection, or overwrite.
import gc
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
SESSION = Path("/kaggle/working/research_resume_20261010T150010065402Z")
BASE = SESSION / "development"
WINDOW_SIZE = 128
FIT_RESAMPLES = 512
CALIBRATION_RESAMPLES = 512
CALIBRATION_QUANTILE = 0.95
DATASETS = ["CICIoT2023", "CICIoMT2024", "CSE", "NSL", "TONIoT"]
CONFIGURATIONS = [("logistic_existing", 10)] + [(family, seed) for family in ["MLP", "GBDT"] for seed in [10, 11, 12]]
OUT = SESSION / ("aligned_profile_replay_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
OUT.mkdir(parents=True, exist_ok=False)
def save(rows, name, columns=None):
    pd.DataFrame(rows, columns=columns).to_csv(OUT / name, index=False)

def probabilities(bundle, bank, frame):
    primary = bundle["primary_model"].predict_proba(
        frame[bundle["primary_features"]]
    )[:, 1]

    views = np.vstack([
        bank["models"][view].predict_proba(frame[columns])[:, 1]
        for view, columns in bundle["semantic_views"].items()
    ])

    return primary, views

def disjoint_windows(n):
    order = np.random.default_rng(1002).permutation(n)

    return [
        order[start:start + WINDOW_SIZE]
        for start in range(0, n - WINDOW_SIZE + 1, WINDOW_SIZE)
    ]

def signatures(bundle, bank, primary, views, windows):
    rows = []

    for indices in windows:
        primary_decision = (
            primary[indices] > bundle["primary_threshold"]
        )

        view_decision = (
            views[:, indices]
            > np.asarray(bank["thresholds"])[:, None]
        )

        row = [
            primary_decision.mean(),
            np.maximum(
                primary[indices], 1 - primary[indices]
            ).mean(),
        ]

        for index in range(len(views)):
            row.extend([
                view_decision[index].mean(),
                np.maximum(
                    views[index, indices],
                    1 - views[index, indices],
                ).mean(),
                (
                    view_decision[index] == primary_decision
                ).mean(),
            ])

        for left in range(len(views)):
            for right in range(left + 1, len(views)):
                row.append(
                    (
                        view_decision[left] == view_decision[right]
                    ).mean()
                )

        rows.append(row)

    return np.asarray(rows, dtype=float)

def training_mixture_weights(train, reference, normal_only=False):
    if "_family" not in train or "_family" not in reference:
        raise KeyError("Recorded attack-family metadata is required.")

    if normal_only:
        if not reference["label"].eq(0).all():
            raise ValueError("Normal reference contains attack records.")

        return np.full(len(reference), 1 / len(reference))

    target = train["_family"].value_counts(normalize=True)
    available = reference["_family"].value_counts()

    missing = set(target.index) - set(available.index)

    if missing:
        raise ValueError(
            f"Reference allocation lacks training families: {sorted(missing)}"
        )

    weights = np.asarray([
        target.get(family, 0.0) / available[family]
        for family in reference["_family"]
    ], dtype=float)

    if not np.isfinite(weights).all() or weights.sum() <= 0:
        raise ValueError("Invalid reference sampling weights.")

    return weights / weights.sum()

def real_record_resamples(n, weights, count, seed):
    rng = np.random.default_rng(seed)

    # Bootstrap selections contain only indices of existing real records.
    # Replacement avoids finite-population shrinkage from sampling a
    # substantial fraction of a small reference pool without replacement.
    return [
        rng.choice(
            n,
            size=WINDOW_SIZE,
            replace=True,
            p=weights,
        )
        for _ in range(count)
    ]

def fit_aligned_profiles(bundle, bank):
    profiles = {}
    metadata = []

    allocations = [
        (
            "normal",
            "normal_profile_fit_df",
            "normal_profile_calibration_df",
            True,
        ),
        (
            "known",
            "known_reference_df",
            "known_profile_calibration_df",
            False,
        ),
    ]

    for profile, fit_key, calibration_key, normal_only in allocations:
        fit_frame = bundle[fit_key]
        calibration_frame = bundle[calibration_key]

        fit_ids = set(fit_frame["_row_id"])
        calibration_ids = set(calibration_frame["_row_id"])
        test_ids = set(bundle["source_test_df"]["_row_id"])
        train_ids = set(bundle["train_df"]["_row_id"])

        if fit_ids & calibration_ids:
            raise AssertionError("Profile fit/calibration record overlap.")

        if (fit_ids | calibration_ids) & (test_ids | train_ids):
            raise AssertionError("Reference overlaps training or source test.")

        for domain_frame in bundle["evaluation_domains"].values():
            if (fit_ids | calibration_ids) & set(domain_frame["_row_id"]):
                raise AssertionError("Reference overlaps natural-shift evaluation.")

        fit_weights = training_mixture_weights(
            bundle["train_df"], fit_frame, normal_only
        )

        calibration_weights = training_mixture_weights(
            bundle["train_df"], calibration_frame, normal_only
        )

        primary, views = probabilities(bundle, bank, fit_frame)

        fit_matrix = signatures(
            bundle,
            bank,
            primary,
            views,
            real_record_resamples(
                len(fit_frame),
                fit_weights,
                FIT_RESAMPLES,
                7101,
            ),
        )

        median = np.median(fit_matrix, axis=0)

        scale = np.maximum(
            1.4826 * np.median(
                np.abs(fit_matrix - median), axis=0
            ),
            1 / WINDOW_SIZE,
        )

        primary, views = probabilities(
            bundle, bank, calibration_frame
        )

        calibration_matrix = signatures(
            bundle,
            bank,
            primary,
            views,
            real_record_resamples(
                len(calibration_frame),
                calibration_weights,
                CALIBRATION_RESAMPLES,
                7102,
            ),
        )

        calibration_scores = np.mean(
            np.abs((calibration_matrix - median) / scale),
            axis=1,
        )

        threshold = max(
            float(np.quantile(
                calibration_scores,
                CALIBRATION_QUANTILE,
                method="higher",
            )),
            1e-12,
        )

        profiles[profile] = (median, scale, threshold)

        metadata.append({
            "profile": profile,
            "fit_records": len(fit_frame),
            "calibration_records": len(calibration_frame),
            "original_fit_attack_fraction": float(
                fit_frame["label"].mean()
            ),
            "original_calibration_attack_fraction": float(
                calibration_frame["label"].mean()
            ),
            "weighted_fit_attack_fraction": float(
                np.dot(fit_weights, fit_frame["label"].to_numpy())
            ),
            "weighted_calibration_attack_fraction": float(
                np.dot(
                    calibration_weights,
                    calibration_frame["label"].to_numpy(),
                )
            ),
            "calibration_effective_record_count": float(
                1 / np.sum(calibration_weights ** 2)
            ),
            "score_threshold": threshold,
            "bootstrap_windows_independent": False,
        })

    return profiles, metadata

def scores_from_profiles(matrix, profiles):
    normalized = []

    for profile in ["normal", "known"]:
        median, scale, threshold = profiles[profile]

        normalized.append(
            np.mean(
                np.abs((matrix - median) / scale),
                axis=1,
            ) / threshold
        )

    return np.min(np.vstack(normalized), axis=0)

def replay_saved_attack(bundle, artifact):
    with np.load(artifact, allow_pickle=False) as saved:
        offsets = saved["offsets"].copy()
        row_ids = saved["source_row_ids"].astype(str)
        mutable = saved["mutable_columns"].astype(str).tolist()

    if mutable != list(bundle["mutable_columns"]):
        raise ValueError("Saved attack mutable-feature order mismatch.")

    source = bundle["source_test_df"].copy()
    source["_row_id"] = source["_row_id"].astype(str)

    if source["_row_id"].duplicated().any():
        raise ValueError("Source row IDs are duplicated.")

    frame = (
        source.set_index("_row_id", drop=False)
        .loc[row_ids]
        .reset_index(drop=True)
        .copy()
    )

    if len(frame) != len(offsets) * WINDOW_SIZE:
        raise ValueError("Saved SPSA window dimensions mismatch.")

    stem_parts = artifact.stem.split("_")
    epsilon = float(stem_parts[stem_parts.index("eps") + 1])

    features = list(bundle["primary_features"])
    scales = bundle["primary_model"].named_steps["scaler"].scale_

    feature_scales = np.asarray([
        scales[features.index(column)] for column in mutable
    ])

    original = frame[mutable].to_numpy(dtype=float)

    proposed = (
        original
        + np.repeat(offsets, WINDOW_SIZE, axis=0)
        * feature_scales[None, :]
    )

    malicious = frame["label"].to_numpy() == 1
    train = bundle["train_df"]

    for index, column in enumerate(mutable):
        values = train[column].dropna().to_numpy(dtype=float)
        values = values[np.isfinite(values)]

        qlow, qhigh = np.quantile(values, [0.001, 0.999])
        origin = original[:, index]
        budget = epsilon * feature_scales[index]

        low = np.maximum(
            origin - budget,
            np.minimum(origin, qlow),
        )
        high = np.minimum(
            origin + budget,
            np.maximum(origin, qhigh),
        )

        candidate = np.clip(proposed[:, index], low, high)

        if np.all(np.isclose(values, np.round(values), atol=1e-8)):
            rounded = np.round(candidate)

            candidate = np.where(
                (rounded >= low) & (rounded <= high),
                rounded,
                origin,
            )

        eligible = malicious & np.isfinite(origin)

        candidate = np.where(eligible, candidate, origin)

        if np.any(
            eligible & (np.abs(candidate - origin) > budget + 1e-7)
        ):
            raise AssertionError("Replayed attack exceeded its budget.")

        frame[column] = candidate

    clean_ordered = (
        source.set_index("_row_id", drop=False)
        .loc[row_ids]
        .reset_index(drop=True)
    )

    if not frame.loc[~malicious].equals(
        clean_ordered.loc[~malicious]
    ):
        raise AssertionError("Replayed attack changed benign records.")

    return frame, clean_ordered

checks, metadata_rows, summaries, failures = [], [], [], []
def evaluate_frame(bundle, bank, frame, condition, fixed=False, clean=None):
    indices = ([np.arange(i, i + WINDOW_SIZE) for i in range(0, len(frame)-WINDOW_SIZE+1, WINDOW_SIZE)]
               if fixed else disjoint_windows(len(frame)))
    if not indices:
        raise ValueError("No complete evaluation windows.")
    pp, vp = probabilities(bundle, bank, frame)
    if not np.isfinite(pp).all() or not np.isfinite(vp).all():
        raise ValueError("Nonfinite predictions.")
    matrix = signatures(bundle, bank, pp, vp, indices)
    scores = scores_from_profiles(matrix, bank["profiles"])
    if not np.isfinite(scores).all():
        raise ValueError("Nonfinite support scores.")
    y = frame["label"].to_numpy()
    accuracies = np.asarray([((pp[ix] > bundle["primary_threshold"]) == y[ix]).mean() for ix in indices])
    trusted = scores <= 1
    damage = None
    if clean is not None:
        if not np.array_equal(frame["_row_id"].astype(str), clean["_row_id"].astype(str)):
            raise ValueError("Clean/attacked row alignment mismatch.")
        if not np.array_equal(y, clean["label"].to_numpy()):
            raise ValueError("Clean/attacked label mismatch.")
        cp = bundle["primary_model"].predict_proba(clean[bundle["primary_features"]])[:,1]
        ca = np.asarray([((cp[ix] > bundle["primary_threshold"]) == y[ix]).mean() for ix in indices])
        damage = ca - accuracies
    return {
        "condition": condition, "windows": len(indices),
        "primary_accuracy": float(accuracies.mean()),
        "trusted_coverage": float(trusted.mean()),
        "abstain_rate": float(1-trusted.mean()),
        "trusted_risk": float(1-accuracies[trusted].mean()) if trusted.any() else np.nan,
        "mean_support_score": float(scores.mean()),
        "mean_paired_damage": float(damage.mean()) if damage is not None else np.nan,
        "hidden_damage_ge_5pp_fraction": float(((damage >= .05) & trusted).mean()) if damage is not None else np.nan,
    }

for dataset in DATASETS:
    bundle = None
    try:
        bundle = joblib.load(BASE / dataset / f"{dataset}_bundle.joblib")
        if bundle.get("run_kind") != "fresh_development_v1":
            raise ValueError("Unexpected bundle version.")
        if list(bundle["primary_model"].classes_) != [0,1]:
            raise ValueError("Unexpected primary classes.")
        attacks = sorted((BASE / "real_data_hard_gate_spsa_v1" / dataset).glob("spsa_*.npz"))
        if not attacks:
            failures.append({"dataset":dataset,"configuration":"saved_attacks","error":"No saved SPSA artifacts found."})
        for family, seed in CONFIGURATIONS:
            bank = saved_bank = None
            label = f"{family}_seed_{seed}"
            try:
                original_path = BASE / "view_family_replication_v1" / dataset / label / "view_bank.joblib"
                aligned_path = BASE / "reference_mixture_calibration_audit_v1" / dataset / label / "aligned_view_bank.joblib"
                if not original_path.is_file() or not aligned_path.is_file():
                    raise FileNotFoundError(f"Required saved banks: {original_path}; {aligned_path}")
                bank = joblib.load(original_path)
                saved_bank = joblib.load(aligned_path)
                for view, columns in bundle["semantic_views"].items():
                    if list(bank["models"][view].classes_) != [0,1]:
                        raise ValueError(f"Unexpected classes for {view}.")
                    if hasattr(bank["models"][view],"feature_names_in_") and list(bank["models"][view].feature_names_in_) != list(columns):
                        raise ValueError(f"Feature mismatch: {view}.")
                if not np.array_equal(bank["thresholds"],saved_bank["thresholds"]):
                    raise ValueError("Original/aligned saved thresholds differ.")
                rebuilt, metadata = fit_aligned_profiles(bundle,bank)
                local_checks=[]
                for profile in ["normal","known"]:
                    actual=rebuilt[profile]; expected=saved_bank["profiles"][profile]
                    match=all(np.allclose(np.asarray(a),np.asarray(b),rtol=1e-10,atol=1e-12) for a,b in zip(actual,expected))
                    local_checks.append({"dataset":dataset,"family":family,"view_seed":seed,"profile":profile,"saved_aligned_profile_matches":bool(match)})
                checks.extend(local_checks)
                if not all(row["saved_aligned_profile_matches"] for row in local_checks):
                    raise ValueError("Saved aligned profiles do not numerically reproduce.")
                metadata_rows.extend({"dataset":dataset,"family":family,"view_seed":seed,**row} for row in metadata)
                original_profiles=bank["profiles"]
                evaluations=[("clean_source",bundle["source_test_df"])] + list(bundle["evaluation_domains"].items())
                for version,profiles in [("original",original_profiles),("training_mixture_aligned",rebuilt)]:
                    bank["profiles"]=profiles
                    for condition,frame in evaluations:
                        row=evaluate_frame(bundle,bank,frame,condition)
                        summaries.append({"dataset":dataset,"family":family,"view_seed":seed,"profile_version":version,**row})
                    for artifact in attacks:
                        attacked,clean=replay_saved_attack(bundle,artifact)
                        row=evaluate_frame(bundle,bank,attacked,"saved_attack_transfer_replay:"+artifact.stem,True,clean)
                        summaries.append({"dataset":dataset,"family":family,"view_seed":seed,"profile_version":version,**row})
                print(dataset,label,"PROFILE VERIFIED AND REPLAYED",flush=True)
            except Exception as error:
                failures.append({"dataset":dataset,"configuration":label,"error":f"{type(error).__name__}: {error}"})
                print(dataset,label,"FAILED",str(error),flush=True)
            finally:
                bank=saved_bank=None
                gc.collect()
                save(checks,"profile_checks.csv")
                save(metadata_rows,"calibration_metadata.csv")
                save(summaries,"paired_profile_results.csv")
                save(failures,"failures.csv",["dataset","configuration","error"])
    except Exception as error:
        failures.append({"dataset":dataset,"configuration":"bundle","error":f"{type(error).__name__}: {error}"})
    finally:
        bundle=None
        gc.collect()

save(failures,"failures.csv",["dataset","configuration","error"])
results=pd.DataFrame(summaries)
clean=results[results["condition"].eq("clean_source")] if not results.empty else pd.DataFrame()
clean.to_csv(OUT/"clean_source_comparison.csv",index=False)
receipt={
    "output_directory":str(OUT),"expected_configurations":35,
    "profile_checks":len(checks),"profiles_reproduced":sum(row["saved_aligned_profile_matches"] for row in checks),
    "result_rows":len(summaries),"explicit_failures":len(failures),
    "models_retrained":False,"classifier_thresholds_changed":False,
    "new_attacks_optimized":False,"saved_attack_scope":"Transfer/replay against revised profiles; not adaptive verification of revised gate",
    "NF_records_inspected":False,"original_files_overwritten":False,
    "independent_confirmation_performed":False,
}
(OUT/"receipt.json").write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print("\nCLEAN SOURCE COMPARISON")
print(clean.to_string(index=False))
print("\nFAILURES")
print(pd.DataFrame(failures).to_string(index=False) if failures else "None")
