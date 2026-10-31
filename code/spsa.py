# =============================================================================
# REAL-DATA CONTINUATION
#
# 1. Verify saved evaluation records against raw Kaggle files.
# 2. Audit the attainable damage of the frozen linear detector.
# 3. Run query-based SPSA against the actual hard abstention gate.
#
# NO synthetic records, generated labels, or replacement datasets.
# Existing experiment results are not overwritten.
#
# Threat scope:
#   Dataset-specific mutable columns.
#   Budgets measured using the frozen PRIMARY model's training scales.
#   Shared per-window offsets, applied only to malicious records.
#   Range/type feature-space constraints; NOT packet-semantic validity.
#
# This is development evaluation, NOT confirmatory evidence.
# =============================================================================

import json
import traceback
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# =============================================================================
# 1. FIXED SETTINGS
# =============================================================================

BASE = Path("/kaggle/working/fresh_all_datasets_v1")
OUT = BASE / "real_data_hard_gate_spsa_v1"
OUT.mkdir(parents=True, exist_ok=True)

DATASETS = [
    "CICIoT2023",
    "CICIoMT2024",
    "CSE",
    "NSL",
    "TONIoT",
]

SEEDS = [10, 11, 12]
EPSILONS = [0.25, 0.50]
LAMBDAS = [0.0, 0.25, 1.0]

WINDOW_SIZE = 128
SPSA_STEPS = 30
SPSA_RESTARTS = 2
STEP_SIZE = 0.15
PROBE_SIZE = 0.10

MARKERS = {
    "CICIoT2023": ["ciciot2023", "ciciot23"],
    "CICIoMT2024": ["cic-iomt-dataset-2024"],
    "CSE": ["csecicids2018"],
    "NSL": ["nsl-kdd-dataset"],
    "TONIoT": ["ton-iot-train-test-network"],
}

NSL_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]


def save_csv(rows, path):
    frame = rows if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    temporary = path.with_suffix(".tmp")
    frame.to_csv(temporary, index=False)
    temporary.replace(path)


# =============================================================================
# 2. VERIFY REAL RECORDS AGAINST RAW INPUTS
# =============================================================================

def find_raw_file(dataset, filename):
    candidates = [
        path
        for path in Path("/kaggle/input").rglob(filename)
        if path.is_file()
        and any(marker in str(path).lower() for marker in MARKERS[dataset])
    ]

    if not candidates:
        raise FileNotFoundError(
            f"{dataset}: raw input file is not attached: {filename}"
        )

    return min(candidates, key=lambda path: len(str(path)))


def read_raw_row(path, position, dataset):
    if dataset == "NSL":
        frame = pd.read_csv(path, header=None, nrows=position + 1)

        if frame.shape[1] not in [42, 43]:
            raise ValueError("Unexpected NSL raw schema.")

        frame.columns = NSL_COLUMNS[:frame.shape[1]]
        return frame.iloc[position]

    if path.suffix.lower() == ".parquet":
        import pyarrow.parquet as pq

        offset = 0

        for batch in pq.ParquetFile(path).iter_batches(batch_size=100_000):
            if offset <= position < offset + batch.num_rows:
                frame = batch.to_pandas()
                frame.columns = frame.columns.astype(str).str.strip()
                return frame.iloc[position - offset]

            offset += batch.num_rows

    else:
        offset = 0

        for frame in pd.read_csv(
            path,
            chunksize=100_000,
            low_memory=False,
        ):
            frame.columns = frame.columns.astype(str).str.strip()

            if offset <= position < offset + len(frame):
                return frame.iloc[position - offset]

            offset += len(frame)

    raise IndexError(f"Raw row {position} absent from {path.name}.")


def verify_real_data(dataset, bundle):
    frame = bundle["source_test_df"]

    if "_row_id" not in frame:
        raise ValueError("Missing raw-source row identifiers.")

    if not bundle.get("encoding"):
        raise ValueError("Missing recorded training-only encoding.")

    locations = frame["_row_id"].astype(str).str.rsplit(":", n=1, expand=True)
    locations.columns = ["filename", "position"]
    locations["position"] = pd.to_numeric(
        locations["position"], errors="raise"
    ).astype(int)
    locations["frame_position"] = np.arange(len(frame))

    verified = []

    # Verify the earliest sampled evaluation row from each contributing file.
    for filename, group in locations.groupby("filename"):
        location = group.sort_values("position").iloc[0]
        path = find_raw_file(dataset, filename)

        raw = read_raw_row(path, int(location["position"]), dataset)
        transformed = frame.iloc[int(location["frame_position"])]

        checked_features = 0

        for column, specification in bundle["encoding"].items():
            if column not in raw.index:
                raise ValueError(f"Raw predictor absent: {column}")

            if specification["kind"] == "numeric":
                value = pd.to_numeric(
                    pd.Series([raw[column]]), errors="coerce"
                ).iloc[0]

                if pd.notna(value) and not np.isfinite(float(value)):
                    value = np.nan

                observed = float(transformed[column])

                if not np.isclose(
                    float(value),
                    observed,
                    rtol=1e-7,
                    atol=1e-7,
                    equal_nan=True,
                ):
                    raise AssertionError(
                        f"{dataset}: raw/transformed mismatch for {column}"
                    )

                checked_features += 1

            else:
                value = (
                    "__MISSING__"
                    if pd.isna(raw[column])
                    else str(raw[column])
                )

                for index, category in enumerate(specification["categories"]):
                    encoded_column = f"{column}__category_{index}"
                    expected = float(value == category)

                    if float(transformed[encoded_column]) != expected:
                        raise AssertionError(
                            f"{dataset}: categorical encoding mismatch."
                        )

                    checked_features += 1

        label_column = next(
            column for column in raw.index
            if str(column).strip().lower() == "label"
        )

        if dataset == "TONIoT":
            expected_label = int(raw[label_column])

        else:
            value = str(raw[label_column]).strip().lower().rstrip(".")
            expected_label = int(
                value != "normal"
                if dataset == "NSL"
                else not ("benign" in value or "normal" in value)
            )

        if expected_label != int(transformed["label"]):
            raise AssertionError(f"{dataset}: raw label mismatch.")

        verified.append({
            "dataset": dataset,
            "raw_file": str(path),
            "raw_position": int(location["position"]),
            "checked_encoded_features": checked_features,
            "label_verified": True,
            "status": "RAW_RECORD_MATCH",
        })

    return verified


# =============================================================================
# 3. VECTORIZED SIGNATURES AND EXACT HARD GATE
# =============================================================================

def probabilities(bundle, frame):
    primary = bundle["primary_model"].predict_proba(
        frame[bundle["primary_features"]]
    )[:, 1]

    views = np.vstack([
        bundle["view_models"][view].predict_proba(frame[columns])[:, 1]
        for view, columns in bundle["semantic_views"].items()
    ])

    return primary, views


def signature_matrix(bundle, primary, views):
    n_windows = len(primary) // WINDOW_SIZE

    p = primary.reshape(n_windows, WINDOW_SIZE)
    v = views.reshape(len(views), n_windows, WINDOW_SIZE)

    primary_decision = p > bundle["primary_threshold"]
    view_decision = (
        v > np.asarray(bundle["view_thresholds"])[:, None, None]
    )

    columns = [
        primary_decision.mean(axis=1),
        np.maximum(p, 1 - p).mean(axis=1),
    ]

    for index in range(len(views)):
        columns.extend([
            view_decision[index].mean(axis=1),
            np.maximum(v[index], 1 - v[index]).mean(axis=1),
            (view_decision[index] == primary_decision).mean(axis=1),
        ])

    for left in range(len(views)):
        for right in range(left + 1, len(views)):
            columns.append(
                (view_decision[left] == view_decision[right]).mean(axis=1)
            )

    return np.column_stack(columns)


def hard_gate_scores(bundle, primary, views):
    signatures = signature_matrix(bundle, primary, views)
    scores = []

    for profile_name in ["normal", "known"]:
        median, scale, threshold = bundle["profiles"][profile_name]

        scores.append(
            np.mean(
                np.abs((signatures - median) / scale),
                axis=1,
            ) / threshold
        )

    return np.min(np.vstack(scores), axis=0)


# =============================================================================
# 4. REAL-DATA ATTACK CONTEXT
# =============================================================================

def prepare_context(bundle, epsilon):
    test = bundle["source_test_df"]
    train = bundle["train_df"]

    order = np.random.default_rng(1002).permutation(len(test))
    count = (len(test) // WINDOW_SIZE) * WINDOW_SIZE

    frame = test.iloc[order[:count]].reset_index(drop=True).copy()
    labels = frame["label"].to_numpy(dtype=int)
    mutable = list(bundle["mutable_columns"])
    features = list(bundle["primary_features"])

    if not count:
        raise ValueError("No complete real-data evaluation windows.")

    primary = bundle["primary_model"]
    scaler = primary.named_steps["scaler"]
    classifier = primary.named_steps["classifier"]

    feature_indices = [features.index(column) for column in mutable]

    scales = scaler.scale_[feature_indices]
    coefficients = classifier.coef_[0, feature_indices]

    original = frame[mutable].to_numpy(dtype=float)
    low = original.copy()
    high = original.copy()
    integer = []

    for index, column in enumerate(mutable):
        values = train[column].dropna().to_numpy(dtype=float)
        values = values[np.isfinite(values)]

        if not len(values):
            raise ValueError(f"No finite training values for {column}.")

        qlow, qhigh = np.quantile(values, [0.001, 0.999])
        budget = epsilon * scales[index]

        low[:, index] = np.maximum(
            original[:, index] - budget,
            np.minimum(original[:, index], qlow),
        )
        high[:, index] = np.minimum(
            original[:, index] + budget,
            np.maximum(original[:, index], qhigh),
        )

        integer.append(
            bool(np.all(np.isclose(values, np.round(values), atol=1e-8)))
        )

    primary_p, views_p = probabilities(bundle, frame)
    clean_scores = hard_gate_scores(bundle, primary_p, views_p)

    clean_accuracy = (
        (primary_p > bundle["primary_threshold"]) == labels
    ).reshape(-1, WINDOW_SIZE).mean(axis=1)

    return {
        "frame": frame,
        "labels": labels,
        "mutable": mutable,
        "original": original,
        "low": low,
        "high": high,
        "integer": integer,
        "scales": scales,
        "coefficients": coefficients,
        "epsilon": epsilon,
        "windows": count // WINDOW_SIZE,
        "clean_accuracy": clean_accuracy,
        "clean_scores": clean_scores,
        "primary": primary,
        "raw_gradients": coefficients / scales,
    }


def project_values(context, proposed):
    values = np.clip(
        proposed,
        context["low"],
        context["high"],
    )

    for index, integer in enumerate(context["integer"]):
        if not integer:
            continue

        rounded = np.round(values[:, index])

        valid = (
            (rounded >= context["low"][:, index])
            & (rounded <= context["high"][:, index])
        )

        values[:, index] = np.where(
            valid,
            rounded,
            context["original"][:, index],
        )

    eligible = (
        (context["labels"] == 1)[:, None]
        & np.isfinite(context["original"])
    )

    return np.where(eligible, values, context["original"])


def frame_from_offsets(context, offsets):
    repeated = np.repeat(offsets, WINDOW_SIZE, axis=0)

    proposed = (
        context["original"]
        + repeated * context["scales"][None, :]
    )

    values = project_values(context, proposed)

    eligible = (
        (context["labels"] == 1)[:, None]
        & np.isfinite(context["original"])
    )

    displacement = np.abs(values - context["original"])
    budget = context["epsilon"] * context["scales"][None, :]

    if np.any(eligible & (displacement > budget + 1e-7)):
        raise AssertionError("Attack budget exceeded.")

    attacked = context["frame"].copy()
    attacked[context["mutable"]] = values

    benign = context["labels"] == 0

    if not attacked.loc[benign].equals(context["frame"].loc[benign]):
        raise AssertionError("Benign records changed.")

    return attacked


# =============================================================================
# 5. LINEAR-DETECTOR REACHABILITY AUDIT
#
# Exact within the stated per-record box/type feature-space threat model.
# This bound does not establish packet feasibility.
# =============================================================================

def reachable_damage_audit(dataset, bundle, context):
    original = context["original"]
    gradients = context["raw_gradients"]

    optimum = np.where(
        gradients[None, :] >= 0,
        context["low"],
        context["high"],
    )

    for index, integer in enumerate(context["integer"]):
        if not integer:
            continue

        low_integer = np.ceil(context["low"][:, index])
        high_integer = np.floor(context["high"][:, index])

        optimal_integer = (
            low_integer
            if gradients[index] >= 0
            else high_integer
        )

        feasible = low_integer <= high_integer

        # Preserve the original value if no integer lies in the budget.
        # Include original as an option under the existing projection policy.
        options = np.where(
            feasible,
            optimal_integer,
            original[:, index],
        )

        improves_logit = (
            gradients[index] * (options - original[:, index]) <= 0
        )

        optimum[:, index] = np.where(
            improves_logit,
            options,
            original[:, index],
        )

    eligible = (
        (context["labels"] == 1)[:, None]
        & np.isfinite(original)
    )

    optimum = np.where(eligible, optimum, original)

    attacked = context["frame"].copy()
    attacked[context["mutable"]] = optimum

    probability = context["primary"].predict_proba(
        attacked[bundle["primary_features"]]
    )[:, 1]

    minimum_accuracy = float(
        (
            (probability > bundle["primary_threshold"])
            == context["labels"]
        ).mean()
    )

    return {
        "dataset": dataset,
        "epsilon": context["epsilon"],
        "evaluated_records": len(attacked),
        "clean_accuracy": float(context["clean_accuracy"].mean()),
        "minimum_box_type_accuracy": minimum_accuracy,
        "maximum_box_type_damage": (
            float(context["clean_accuracy"].mean()) - minimum_accuracy
        ),
        "mutable_columns": "|".join(context["mutable"]),
        "scope": "Primary-scale box/type bound; no packet-validity claim",
    }


# =============================================================================
# 6. SPSA: SOFT EVASION OBJECTIVE + ACTUAL DISCRETE ABSTENTION GATE
#
# Each window has its own shared mutable-feature offset vector.
# Attack labels identify attacker-controlled malicious records.
# Hyperparameters are fixed above, not selected using reported damage.
# =============================================================================

def evaluate_offsets(bundle, context, offsets, lambda_value):
    attacked = frame_from_offsets(context, offsets)

    primary_p, views_p = probabilities(bundle, attacked)
    support = hard_gate_scores(bundle, primary_p, views_p)

    malicious = (
        context["labels"] == 1
    ).reshape(context["windows"], WINDOW_SIZE)

    p = primary_p.reshape(context["windows"], WINDOW_SIZE)

    evasion_objective = (
        (1 - p) * malicious
    ).mean(axis=1)

    # Actual hard decision; no smooth replacement of the gate.
    alarm = support > 1.0
    objective = evasion_objective - lambda_value * alarm.astype(float)

    accuracy = (
        (primary_p > bundle["primary_threshold"])
        == context["labels"]
    ).reshape(context["windows"], WINDOW_SIZE).mean(axis=1)

    return objective, support, accuracy


def run_spsa(bundle, context, seed, lambda_value):
    rng = np.random.default_rng(seed)

    shape = (
        context["windows"],
        len(context["mutable"]),
    )

    best_objective = np.full(context["windows"], -np.inf)
    best_support = np.full(context["windows"], np.nan)
    best_accuracy = np.full(context["windows"], np.nan)
    best_offsets = np.zeros(shape)

    queries_per_window = 0

    def update_best(offsets, objective, support, accuracy):
        improve = objective > best_objective

        best_objective[improve] = objective[improve]
        best_support[improve] = support[improve]
        best_accuracy[improve] = accuracy[improve]
        best_offsets[improve] = offsets[improve]

    for restart in range(SPSA_RESTARTS):
        if restart == 0:
            offsets = np.zeros(shape)
        else:
            offsets = np.tile(
                -context["epsilon"] * np.sign(context["coefficients"]),
                (context["windows"], 1),
            )

        objective, support, accuracy = evaluate_offsets(
            bundle, context, offsets, lambda_value
        )
        queries_per_window += 1
        update_best(offsets, objective, support, accuracy)

        for step in range(SPSA_STEPS):
            direction = rng.choice([-1.0, 1.0], size=shape)

            probe = (
                PROBE_SIZE * context["epsilon"]
                / (step + 1) ** 0.101
            )

            positive = np.clip(
                offsets + probe * direction,
                -context["epsilon"],
                context["epsilon"],
            )
            negative = np.clip(
                offsets - probe * direction,
                -context["epsilon"],
                context["epsilon"],
            )

            plus_objective, plus_support, plus_accuracy = evaluate_offsets(
                bundle, context, positive, lambda_value
            )
            minus_objective, minus_support, minus_accuracy = evaluate_offsets(
                bundle, context, negative, lambda_value
            )

            queries_per_window += 2

            update_best(
                positive, plus_objective, plus_support, plus_accuracy
            )
            update_best(
                negative, minus_objective, minus_support, minus_accuracy
            )

            gradient = (
                (plus_objective - minus_objective)[:, None]
                / (2 * probe)
            ) * direction

            learning_rate = (
                STEP_SIZE * context["epsilon"]
                / (step + 1) ** 0.602
            )

            offsets = np.clip(
                offsets + learning_rate * np.sign(gradient),
                -context["epsilon"],
                context["epsilon"],
            )

            objective, support, accuracy = evaluate_offsets(
                bundle, context, offsets, lambda_value
            )
            queries_per_window += 1

            update_best(offsets, objective, support, accuracy)

    return {
        "support": best_support,
        "accuracy": best_accuracy,
        "offsets": best_offsets,
        "queries_per_window": queries_per_window,
    }


# =============================================================================
# 7. EXECUTE ON ALL FIVE REAL DATASETS
# =============================================================================

verification_rows = []
reachability_rows = []
result_rows = []
statuses = []

for dataset in DATASETS:
    dataset_out = OUT / dataset
    dataset_out.mkdir(parents=True, exist_ok=True)

    try:
        bundle_path = BASE / dataset / f"{dataset}_bundle.joblib"

        if not bundle_path.exists():
            raise FileNotFoundError(bundle_path)

        # Load only your own trusted saved artifact.
        bundle = joblib.load(bundle_path)

        for required in [
            "view_models",
            "view_thresholds",
            "profiles",
            "encoding",
            "mutable_columns",
        ]:
            if required not in bundle:
                raise KeyError(f"{dataset}: missing {required}")

        verification_rows.extend(verify_real_data(dataset, bundle))

        save_csv(
            verification_rows,
            OUT / "real_data_provenance_checks.csv",
        )

        print("\n" + "=" * 90)
        print(f"RAW-DATA VERIFIED — CONTINUING: {dataset}")
        print("=" * 90, flush=True)

        for epsilon in EPSILONS:
            context = prepare_context(bundle, epsilon)

            audit = reachable_damage_audit(dataset, bundle, context)
            reachability_rows.append(audit)

            save_csv(
                reachability_rows,
                OUT / "linear_reachability_audit.csv",
            )

            print(
                dataset,
                f"epsilon={epsilon}",
                "maximum_box_type_damage="
                f"{audit['maximum_box_type_damage']:.4f}",
                flush=True,
            )

            for seed in SEEDS:
                for lambda_value in LAMBDAS:
                    checkpoint = dataset_out / (
                        f"spsa_eps_{epsilon:.2f}"
                        f"_seed_{seed}"
                        f"_lambda_{lambda_value:.2f}.csv"
                    )

                    if checkpoint.exists():
                        saved = pd.read_csv(checkpoint)
                        result_rows.extend(saved.to_dict("records"))
                        print("Reusing", checkpoint.name, flush=True)
                        continue

                    result = run_spsa(
                        bundle,
                        context,
                        seed,
                        lambda_value,
                    )

                    damage = (
                        context["clean_accuracy"]
                        - result["accuracy"]
                    )

                    rows = []

                    for window in range(context["windows"]):
                        rows.append({
                            "dataset": dataset,
                            "epsilon": epsilon,
                            "attack_search_seed": seed,
                            "lambda": lambda_value,
                            "window": window,
                            "clean_accuracy": float(
                                context["clean_accuracy"][window]
                            ),
                            "attacked_accuracy": float(
                                result["accuracy"][window]
                            ),
                            "true_damage": float(damage[window]),
                            "clean_support_score": float(
                                context["clean_scores"][window]
                            ),
                            "attacked_support_score": float(
                                result["support"][window]
                            ),
                            "trusted_after_attack": int(
                                result["support"][window] <= 1
                            ),
                            "damage_ge_5pp": int(damage[window] >= 0.05),
                            "hidden_damage_ge_5pp": int(
                                damage[window] >= 0.05
                                and result["support"][window] <= 1
                            ),
                            "queries_per_window": (
                                result["queries_per_window"]
                            ),
                            "attack_scope": (
                                "Shared-window-offset SPSA; real data"
                            ),
                        })

                    save_csv(rows, checkpoint)
                    result_rows.extend(rows)

                    np.savez_compressed(
                        checkpoint.with_suffix(".npz"),
                        offsets=result["offsets"],
                        source_row_ids=context["frame"][
                            "_row_id"
                        ].to_numpy(dtype=str),
                        mutable_columns=np.asarray(
                            context["mutable"], dtype=str
                        ),
                    )

                    save_csv(
                        result_rows,
                        OUT / "all_datasets_spsa_window_results.csv",
                    )

                    print(
                        dataset,
                        f"eps={epsilon}",
                        f"seed={seed}",
                        f"lambda={lambda_value}",
                        f"damage={damage.mean():.4f}",
                        "trusted_coverage="
                        f"{(result['support'] <= 1).mean():.4f}",
                        flush=True,
                    )

        statuses.append({
            "dataset": dataset,
            "status": "REAL_DATA_SPSA_COMPLETE",
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
# 8. SAVE CROSS-DATASET RESULTS
# =============================================================================

if result_rows:
    results = pd.DataFrame(result_rows)

    save_csv(
        results,
        OUT / "all_datasets_spsa_window_results.csv",
    )

    summary = (
        results
        .groupby(["dataset", "epsilon", "lambda"])
        .agg(
            search_seeds=("attack_search_seed", "nunique"),
            clean_accuracy=("clean_accuracy", "mean"),
            attacked_accuracy=("attacked_accuracy", "mean"),
            true_damage=("true_damage", "mean"),
            trusted_coverage=("trusted_after_attack", "mean"),
            hidden_damage_window_fraction=(
                "hidden_damage_ge_5pp", "mean"
            ),
            queries_per_window=("queries_per_window", "max"),
        )
        .reset_index()
    )

    save_csv(
        summary,
        OUT / "all_datasets_spsa_summary.csv",
    )

    print("\n" + "=" * 90)
    print("REAL-DATA HARD-GATE SPSA SUMMARY")
    print("=" * 90)
    print(summary.round(4).to_string(index=False))

protocol = {
    "data": "Verified sampled evaluation records against raw Kaggle inputs",
    "synthetic_experiments": False,
    "dataset_scope": DATASETS,
    "evaluation_domain": "Existing source-test split for each dataset",
    "budget_scale": "Frozen primary-model training StandardScaler",
    "gate": "Exact existing two-profile discrete abstention decision",
    "attack": "SPSA with shared per-window mutable-feature offsets",
    "objective": "Soft evasion minus lambda times exact hard-gate alarm",
    "seeds": SEEDS,
    "epsilons": EPSILONS,
    "lambdas": LAMBDAS,
    "steps": SPSA_STEPS,
    "restarts": SPSA_RESTARTS,
    "limitations": [
        "Sampled provenance checks are not full-file verification",
        "Shared offsets are a restricted attack parameterization",
        "No claim that SPSA finds the global adaptive optimum",
        "No packet-semantic validity or derived-feature recomputation",
        "Attack-search seeds are not independent trained-model replications",
        "Results are development diagnostics, not confirmatory inference",
        "Do not pool with earlier surrogate-scaled attack results",
    ],
}

(OUT / "protocol.json").write_text(
    json.dumps(protocol, indent=2)
)

print("\nDATASET STATUS")
print(pd.DataFrame(statuses).to_string(index=False))