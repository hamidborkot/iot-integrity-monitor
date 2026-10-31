# =============================================================================
# NEXT EXPERIMENT — REFERENCE-MIXTURE / CLEAN-CALIBRATION AUDIT
#
# Real saved data only.
# No model retraining.
# No synthetic features or labels.
# No threshold selection using evaluation results.
#
# Compare:
#   Original normal/known profiles.
#   Profiles fitted/calibrated using the TRAINING family's mixture.
#
# Evaluation:
#   Clean source.
#   Every existing natural-shift domain.
#   Saved real-data SPSA attacks, replayed exactly.
#
# Saved SPSA attacks were optimized against the ORIGINAL logistic monitor.
# Their evaluation here is a transfer/replay test, NOT a new adaptive attack.
#
# Old results and old banks are never overwritten.
# =============================================================================

import hashlib
import json
import traceback
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# =============================================================================
# 1. SETTINGS
# =============================================================================

BASE = Path("/kaggle/working/fresh_all_datasets_v1")
FAMILY_ROOT = BASE / "view_family_replication_v1"
SPSA_ROOT = BASE / "real_data_hard_gate_spsa_v1"

OUT = BASE / "reference_mixture_calibration_audit_v1"
OUT.mkdir(parents=True, exist_ok=True)

DATASETS = ["CICIoT2023", "CICIoMT2024", "CSE", "NSL", "TONIoT"]

CONFIGURATIONS = (
    [("logistic_existing", 10)]
    + [("MLP", seed) for seed in [10, 11, 12]]
    + [("GBDT", seed) for seed in [10, 11, 12]]
)

WINDOW_SIZE = 128
FIT_RESAMPLES = 512
CALIBRATION_RESAMPLES = 512
CALIBRATION_QUANTILE = 0.95

MIN_CLEAN_COVERAGE = 0.85
MAX_CLEAN_FALSE_ABSTAIN = 0.15

SETTINGS = {
    "window_size": WINDOW_SIZE,
    "fit_resamples": FIT_RESAMPLES,
    "calibration_resamples": CALIBRATION_RESAMPLES,
    "calibration_quantile": CALIBRATION_QUANTILE,
    "reference_target": "Training-family proportions",
    "minimum_clean_coverage": MIN_CLEAN_COVERAGE,
    "maximum_clean_false_abstain": MAX_CLEAN_FALSE_ABSTAIN,
    "datasets": DATASETS,
    "configurations": CONFIGURATIONS,
}

settings_hash = hashlib.sha256(
    json.dumps(SETTINGS, sort_keys=True).encode()
).hexdigest()

settings_path = OUT / "settings.json"

if settings_path.exists():
    previous = json.loads(settings_path.read_text())

    if previous["settings_sha256"] != settings_hash:
        raise RuntimeError("Settings changed. Use a new OUT directory.")

settings_path.write_text(json.dumps({
    "settings_sha256": settings_hash,
    "settings": SETTINGS,
}, indent=2))


# =============================================================================
# 2. LOCAL FUNCTIONS
# =============================================================================

def save_csv(rows, path):
    frame = rows if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    temporary = path.with_suffix(".tmp")
    frame.to_csv(temporary, index=False)
    temporary.replace(path)


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


# =============================================================================
# 3. RUN ALL DATASETS / EXISTING VIEW BANKS
# =============================================================================

composition_rows = []
summary_rows = []
window_rows = []
statuses = []

for dataset in DATASETS:
    dataset_out = OUT / dataset
    dataset_out.mkdir(parents=True, exist_ok=True)

    try:
        bundle = joblib.load(
            BASE / dataset / f"{dataset}_bundle.joblib"
        )

        train_prior = float(bundle["train_df"]["label"].mean())

        for allocation in [
            "train_df",
            "source_test_df",
            "normal_profile_fit_df",
            "normal_profile_calibration_df",
            "known_reference_df",
            "known_profile_calibration_df",
        ]:
            frame = bundle[allocation]

            composition_rows.append({
                "dataset": dataset,
                "allocation": allocation,
                "records": len(frame),
                "attack_fraction": float(frame["label"].mean()),
                "training_attack_fraction": train_prior,
            })

        save_csv(
            composition_rows,
            OUT / "reference_composition_audit.csv",
        )

        for family, view_seed in CONFIGURATIONS:
            original_directory = (
                FAMILY_ROOT
                / dataset
                / f"{family}_seed_{view_seed}"
            )

            bank_path = original_directory / "view_bank.joblib"

            if not bank_path.exists():
                raise FileNotFoundError(bank_path)

            bank = joblib.load(bank_path)

            aligned_profiles, calibration_metadata = (
                fit_aligned_profiles(bundle, bank)
            )

            directory = dataset_out / f"{family}_seed_{view_seed}"
            directory.mkdir(parents=True, exist_ok=True)

            aligned_bank = dict(bank)
            aligned_bank["profiles"] = aligned_profiles
            aligned_bank["calibration_version"] = (
                "training_family_mixture_real_record_bootstrap_v1"
            )

            joblib.dump(
                aligned_bank,
                directory / "aligned_view_bank.joblib",
                compress=3,
            )

            save_csv(
                calibration_metadata,
                directory / "calibration_metadata.csv",
            )

            profile_versions = {
                "original": bank["profiles"],
                "training_mixture_aligned": aligned_profiles,
            }

            def evaluate(
                frame,
                condition,
                fixed_order=False,
                paired_clean=None,
            ):
                windows = (
                    [
                        np.arange(start, start + WINDOW_SIZE)
                        for start in range(
                            0,
                            len(frame) - WINDOW_SIZE + 1,
                            WINDOW_SIZE,
                        )
                    ]
                    if fixed_order
                    else disjoint_windows(len(frame))
                )

                if not windows:
                    return

                primary, views = probabilities(bundle, bank, frame)
                labels = frame["label"].to_numpy()

                matrix = signatures(
                    bundle, bank, primary, views, windows
                )

                accuracy = np.asarray([
                    (
                        (
                            primary[indices]
                            > bundle["primary_threshold"]
                        )
                        == labels[indices]
                    ).mean()
                    for indices in windows
                ])

                if paired_clean is not None:
                    clean_probability = bundle[
                        "primary_model"
                    ].predict_proba(
                        paired_clean[bundle["primary_features"]]
                    )[:, 1]

                    clean_labels = paired_clean["label"].to_numpy()

                    clean_accuracy = np.asarray([
                        (
                            (
                                clean_probability[indices]
                                > bundle["primary_threshold"]
                            )
                            == clean_labels[indices]
                        ).mean()
                        for indices in windows
                    ])

                    damage = clean_accuracy - accuracy

                else:
                    damage = np.full(len(windows), np.nan)

                for version, profiles in profile_versions.items():
                    scores = scores_from_profiles(matrix, profiles)
                    trusted = scores <= 1.0

                    for window in range(len(windows)):
                        window_rows.append({
                            "dataset": dataset,
                            "family": family,
                            "view_seed": view_seed,
                            "profile_version": version,
                            "condition": condition,
                            "window": window,
                            "primary_accuracy": float(accuracy[window]),
                            "support_score": float(scores[window]),
                            "trusted": int(trusted[window]),
                            "paired_damage": float(damage[window]),
                        })

                    coverage = float(trusted.mean())

                    summary_rows.append({
                        "dataset": dataset,
                        "family": family,
                        "view_seed": view_seed,
                        "profile_version": version,
                        "condition": condition,
                        "windows": len(windows),
                        "primary_accuracy": float(accuracy.mean()),
                        "trusted_coverage": coverage,
                        "abstain_rate": 1 - coverage,
                        "trusted_risk": (
                            float(1 - accuracy[trusted].mean())
                            if trusted.any()
                            else np.nan
                        ),
                        "mean_support_score": float(scores.mean()),
                        "mean_paired_damage": (
                            float(damage.mean())
                            if paired_clean is not None
                            else np.nan
                        ),
                        "hidden_damage_ge_5pp_fraction": (
                            float(
                                ((damage >= 0.05) & trusted).mean()
                            )
                            if paired_clean is not None
                            else np.nan
                        ),
                        "clean_calibration_gate_pass": (
                            int(
                                coverage >= MIN_CLEAN_COVERAGE
                                and 1 - coverage <= MAX_CLEAN_FALSE_ABSTAIN
                            )
                            if condition == "clean_source"
                            else np.nan
                        ),
                    })

            evaluate(
                bundle["source_test_df"],
                "clean_source",
            )

            for domain, frame in bundle["evaluation_domains"].items():
                evaluate(frame, domain)

            artifacts = sorted(
                (SPSA_ROOT / dataset).glob("spsa_*.npz")
            )

            if not artifacts:
                raise FileNotFoundError(
                    f"{dataset}: saved real-data SPSA attacks are absent."
                )

            for artifact in artifacts:
                attacked, clean_ordered = replay_saved_attack(
                    bundle, artifact
                )

                evaluate(
                    attacked,
                    "original_monitor_attack_replay_" + artifact.stem,
                    fixed_order=True,
                    paired_clean=clean_ordered,
                )

            save_csv(
                summary_rows,
                OUT / "all_datasets_calibration_comparison.csv",
            )
            save_csv(
                window_rows,
                OUT / "all_datasets_calibration_windows.csv",
            )

            print(
                dataset,
                family,
                f"view_seed={view_seed}",
                "CALIBRATION AUDIT COMPLETE",
                flush=True,
            )

        statuses.append({
            "dataset": dataset,
            "status": "CALIBRATION_AUDIT_COMPLETE",
            "detail": "",
        })

    except Exception as error:
        statuses.append({
            "dataset": dataset,
            "status": "FAILED",
            "detail": str(error),
        })

        (dataset_out / "error.txt").write_text(
            traceback.format_exc()
        )

        print(f"{dataset}: FAILED: {error}", flush=True)

    save_csv(statuses, OUT / "dataset_status.csv")


# =============================================================================
# 4. CLEAN CALIBRATION DECISION TABLE
# =============================================================================

if summary_rows:
    results = pd.DataFrame(summary_rows)

    save_csv(
        results,
        OUT / "all_datasets_calibration_comparison.csv",
    )

    clean = results[
        results["condition"].eq("clean_source")
    ].copy()

    save_csv(
        clean,
        OUT / "clean_calibration_gate_results.csv",
    )

    clean_table = (
        clean
        .groupby(["dataset", "family", "profile_version"])
        .agg(
            primary_accuracy=("primary_accuracy", "mean"),
            trusted_coverage=("trusted_coverage", "mean"),
            false_abstain_rate=("abstain_rate", "mean"),
            configurations_passing=(
                "clean_calibration_gate_pass", "sum"
            ),
            configurations_evaluated=("view_seed", "nunique"),
        )
        .reset_index()
    )

    save_csv(
        clean_table,
        OUT / "clean_calibration_summary.csv",
    )

    print("\n" + "=" * 90)
    print("ORIGINAL VS TRAINING-MIXTURE CALIBRATION")
    print("=" * 90)
    print(clean_table.round(4).to_string(index=False))

protocol = {
    "experiment": "Reference-mixture and clean-calibration audit",
    "settings_sha256": settings_hash,
    "data": "Existing real dataset records only",
    "models": "All primary and view models unchanged",
    "target_reference_mixture": "Computed from training families only",
    "threshold_selection": "Reference calibration only; never evaluation data",
    "evaluation": [
        "Clean source",
        "Existing natural-shift domains",
        "Exact replay of saved original-monitor SPSA attacks",
    ],
    "limitations": [
        "This is a post-development method revision, not confirmation",
        "Bootstrap windows overlap and are not independent observations",
        "Clean calibration pass is descriptive, not a coverage guarantee",
        "Original-monitor attack replay is not adaptive to the revised gate",
        "Actual adaptive attacks must be rerun against any revised gate",
        "No packet-semantic validity or population-prevalence guarantee",
        "All original and negative results are retained",
    ],
}

(OUT / "protocol.json").write_text(
    json.dumps(protocol, indent=2)
)

print("\nDATASET STATUS")
print(pd.DataFrame(statuses).to_string(index=False))