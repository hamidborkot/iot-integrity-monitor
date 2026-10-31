# E1-CORRECTED-v2: complete TON-IoT semantic-view screening notebook script
import json, hashlib, warnings
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
warnings.filterwarnings("ignore", category=UserWarning)

SEED = 10
CSV_PATH = Path("/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network/TON_IoT_Train_Test_Network.csv")
OUT = Path("/kaggle/working/ton_e1_corrected_v2")
OUT.mkdir(parents=True, exist_ok=True)
SOURCE = ["scanning", "dos", "ddos", "password"]
HELDOUT = ["injection", "xss", "ransomware", "backdoor", "mitm"]
N_STRAIN, N_SREF, N_STEST = 5000, 2500, 5000
N_NTRAIN, N_NREF, N_NSTEST, N_NZTEST, N_ZATTACK = 20000, 10000, 20000, 25000, 25000
TARGET_NORMAL_REFERENCE_FPR = 0.05
MIN_DIMS, MIN_SOURCE_BACC, MIN_ZERO_BACC, MAX_NORMAL_FPR, MIN_VIEWS = 4, .55, .50, .10, 4
MIN_CATEGORY_FREQUENCY = 10
VIEWS = {
    "context_state": ["proto", "service", "conn_state"],
    "volume": ["src_bytes", "dst_bytes", "missed_bytes", "src_pkts", "dst_pkts"],
    "timing": ["duration"],
    "dns_codes": ["dns_qclass", "dns_qtype", "dns_rcode", "dns_AA", "dns_RD", "dns_RA", "dns_rejected"],
    "tls_state": ["ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established"],
    "http_state": ["http_trans_depth", "http_method", "http_version", "http_request_body_len", "http_response_body_len", "http_status_code", "http_orig_mime_types", "http_resp_mime_types"],
    "zeek_anomaly_state": ["weird_name", "weird_notice"],
}
EXCLUDED = {"ts", "src_ip", "dst_ip", "src_port", "dst_port", "dns_query", "ssl_subject", "ssl_issuer", "http_uri", "http_user_agent", "weird_addl", "label", "type", "_row_id"}

def sample(df, n, seed):
    if len(df) < n:
        raise ValueError(f"Need {n:,} rows; only {len(df):,} available")
    return df.sample(n=n, random_state=seed).copy()

def row_hash(df):
    a = np.sort(df["_row_id"].to_numpy(dtype=np.int64))
    return hashlib.sha256(a.tobytes()).hexdigest()[:20]

def check_disjoint(parts):
    items = list(parts.items())
    for i, (a, adf) in enumerate(items):
        ai = set(adf._row_id.tolist())
        for b, bdf in items[i+1:]:
            overlap = ai & set(bdf._row_id.tolist())
            if overlap:
                raise RuntimeError(f"LEAKAGE: {a} and {b} share {len(overlap)} rows")

def family_split(df, name, seed):
    x = df[df.type.eq(name)]
    need = N_STRAIN + N_SREF + N_STEST
    x = sample(x, need, seed).reset_index(drop=True)
    return x.iloc[:N_STRAIN].copy(), x.iloc[N_STRAIN:N_STRAIN+N_SREF].copy(), x.iloc[N_STRAIN+N_SREF:].copy()

def heldout_sample(df):
    chosen = []
    base, rem = divmod(N_ZATTACK, len(HELDOUT))
    for i, fam in enumerate(HELDOUT):
        x = df[df.type.eq(fam)]
        n = min(len(x), base + int(i < rem))
        if n:
            chosen.append(sample(x, n, SEED + 300 + i))
    out = pd.concat(chosen, ignore_index=True)
    if len(out) < N_ZATTACK:
        unused = df[~df._row_id.isin(out._row_id)]
        out = pd.concat([out, sample(unused, N_ZATTACK-len(out), SEED+399)], ignore_index=True)
    return out.sample(frac=1, random_state=SEED+400).reset_index(drop=True)

def cols(df, wanted):
    return [c for c in wanted if c in df.columns and c not in EXCLUDED]

def make_model(df, use_cols):
    num = [c for c in use_cols if pd.api.types.is_numeric_dtype(df[c])]
    cat = [c for c in use_cols if c not in num]
    tr = []
    if num:
        tr.append(("num", Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), num))
    if cat:
        tr.append(("cat", Pipeline([("impute", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=MIN_CATEGORY_FREQUENCY))]), cat))
    if not tr:
        raise ValueError("No usable columns")
    return Pipeline([("prep", ColumnTransformer(tr)), ("clf", LogisticRegression(solver="lbfgs", max_iter=2000, class_weight="balanced", random_state=SEED))])

def transformed_dim(model, X):
    return int(model.named_steps["prep"].transform(X.iloc[:64]).shape[1])

# This is the requested strict threshold implementation.
def calibrated_threshold(
    model,
    normal_reference_X,
    target_fpr=TARGET_NORMAL_REFERENCE_FPR,
):
    probability = model.predict_proba(
        normal_reference_X
    )[:, 1]

    probability = np.sort(
        np.asarray(probability, dtype=float)
    )

    n = len(probability)

    allowed_positive_count = int(
        np.floor(target_fpr * n)
    )

    if allowed_positive_count <= 0:
        return float(
            np.nextafter(
                probability[-1],
                np.inf,
            )
        )

    boundary_index = n - allowed_positive_count

    if boundary_index >= n:
        return float(
            np.nextafter(
                probability[-1],
                np.inf,
            )
        )

    boundary_probability = probability[
        boundary_index
    ]

    return float(
        np.nextafter(
            boundary_probability,
            np.inf,
        )
    )

def evaluate_model(model, X, y, threshold, split):
    probability = model.predict_proba(X)[:, 1]
    prediction = (
        probability > threshold
    ).astype(int)
    y = np.asarray(y, dtype=int)
    normal, attack = y == 0, y == 1
    return dict(split=split, rows=int(len(y)), attack_fraction=float(y.mean()), threshold=float(threshold),
                accuracy=float(accuracy_score(y, prediction)), balanced_accuracy=float(balanced_accuracy_score(y, prediction)),
                f1=float(f1_score(y, prediction, zero_division=0)), precision=float(precision_score(y, prediction, zero_division=0)),
                recall=float(recall_score(y, prediction, zero_division=0)),
                normal_false_positive_rate=float(prediction[normal].mean()) if normal.any() else np.nan,
                attack_recall=float(prediction[attack].mean()) if attack.any() else np.nan,
                mean_attack_probability=float(probability.mean()))

if not CSV_PATH.exists():
    raise FileNotFoundError(CSV_PATH)
df = pd.read_csv(CSV_PATH, low_memory=False)
df.columns = [str(c).strip() for c in df.columns]
if not {"type", "label"}.issubset(df.columns):
    raise KeyError("TON-IoT must contain type and label columns")
df["_row_id"] = np.arange(len(df), dtype=np.int64)
df["type"] = df["type"].astype(str).str.strip().str.lower()
df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
normal = df[df.label.eq(0)].copy()
source = df[df.type.isin(SOURCE)].copy()
heldout = df[df.type.isin(HELDOUT)].copy()
print("="*100); print("E1-CORRECTED-v2: TON-IoT SEMANTIC VIEW SCREENING"); print("="*100)
print("SOURCE\n", source.type.value_counts().sort_index().to_string())
print("HELDOUT\n", heldout.type.value_counts().sort_index().to_string())
print("NORMAL:", len(normal))

st, sr, ss = [], [], []
for i, fam in enumerate(SOURCE):
    a, b, c = family_split(source, fam, SEED+100*i); st.append(a); sr.append(b); ss.append(c)
st, sr, ss = pd.concat(st, ignore_index=True), pd.concat(sr, ignore_index=True), pd.concat(ss, ignore_index=True)
za = heldout_sample(heldout)
pool = sample(normal, N_NTRAIN+N_NREF+N_NSTEST+N_NZTEST, SEED+500).reset_index(drop=True)
nt = pool.iloc[:N_NTRAIN].copy(); nr = pool.iloc[N_NTRAIN:N_NTRAIN+N_NREF].copy()
ns = pool.iloc[N_NTRAIN+N_NREF:N_NTRAIN+N_NREF+N_NSTEST].copy(); nz = pool.iloc[N_NTRAIN+N_NREF+N_NSTEST:].copy()
check_disjoint({"normal_train":nt,"normal_reference":nr,"normal_source_test":ns,"normal_zero_day_test":nz,"source_train":st,"source_reference":sr,"source_test":ss,"heldout_zero_day":za})
train = pd.concat([nt,st], ignore_index=True).sample(frac=1,random_state=SEED+1).reset_index(drop=True)
known_ref = pd.concat([nr,sr], ignore_index=True).sample(frac=1,random_state=SEED+2).reset_index(drop=True)
source_test = pd.concat([ns,ss], ignore_index=True).sample(frac=1,random_state=SEED+3).reset_index(drop=True)
zero_test = pd.concat([nz,za], ignore_index=True).sample(frac=1,random_state=SEED+4).reset_index(drop=True)
manifest = pd.DataFrame([dict(split=k, rows=len(v), attack_fraction=float(v.label.mean()), row_id_sha256=row_hash(v)) for k,v in {"train":train,"normal_reference":nr,"known_reference":known_ref,"source_family_test":source_test,"balanced_zero_day_test":zero_test}.items()])
manifest.to_csv(OUT/"split_manifest.csv",index=False)
print("\nSPLIT MANIFEST\n",manifest.to_string(index=False))

schema=[]
for view,wanted in VIEWS.items():
    for feature in wanted:
        schema.append(dict(dataset="TON_IoT",feature=feature,semantic_view=view,available=feature in df.columns,included=feature in cols(df,[feature]),dtype=str(df[feature].dtype) if feature in df.columns else "MISSING"))
for feature in sorted(EXCLUDED & set(df.columns)):
    schema.append(dict(dataset="TON_IoT",feature=feature,semantic_view="EXCLUDED",available=True,included=False,dtype=str(df[feature].dtype)))
pd.DataFrame(schema).to_csv(OUT/"feature_provenance_screened.csv",index=False)

primary_cols=[]
for wanted in VIEWS.values():
    for c in cols(df,wanted):
        if c not in primary_cols: primary_cols.append(c)
primary = make_model(train,primary_cols); primary.fit(train[primary_cols],train.label)
pthr=calibrated_threshold(primary,nr[primary_cols])
primary_rows=[]
for name,x in {"known_reference":known_ref,"clean_normal_reference":nr,"source_family_test":source_test,"balanced_zero_day_test":zero_test}.items():
    q=evaluate_model(primary,x[primary_cols],x.label,pthr,name); q.update(model="primary",raw_feature_count=len(primary_cols),transformed_feature_count=transformed_dim(primary,train[primary_cols])); primary_rows.append(q)
pres=pd.DataFrame(primary_rows); pres.to_csv(OUT/"primary_results.csv",index=False)
print("\n"+"="*100); print("PRIMARY IDS RESULTS"); print("="*100); print(pres.round(4).to_string(index=False))

view_rows=[]
for name,wanted in VIEWS.items():
    use=cols(df,wanted); row=dict(view=name,requested_columns="|".join(wanted),usable_columns="|".join(use),raw_feature_count=len(use),status="FAIL",failure_reason="")
    try:
        model=make_model(train,use); model.fit(train[use],train.label)
        threshold=calibrated_threshold(model,nr[use]); dim=transformed_dim(model,train[use])
        clean=evaluate_model(model,nr[use],nr.label,threshold,"clean_normal_reference")
        src=evaluate_model(model,source_test[use],source_test.label,threshold,"source_family_test")
        zero=evaluate_model(model,zero_test[use],zero_test.label,threshold,"balanced_zero_day_test")
        row.update(threshold=threshold,transformed_feature_count=dim,clean_normal_fpr=clean["normal_false_positive_rate"],source_accuracy=src["accuracy"],source_balanced_accuracy=src["balanced_accuracy"],source_attack_recall=src["attack_recall"],zero_day_accuracy=zero["accuracy"],zero_day_balanced_accuracy=zero["balanced_accuracy"],zero_day_attack_recall=zero["attack_recall"])
        failures=[]
        if dim < MIN_DIMS: failures.append("too_few_transformed_features")
        if src["balanced_accuracy"] < MIN_SOURCE_BACC: failures.append("source_balanced_accuracy_below_0.55")
        if zero["balanced_accuracy"] < MIN_ZERO_BACC: failures.append("zero_day_balanced_accuracy_below_0.50")
        if clean["normal_false_positive_rate"] > MAX_NORMAL_FPR: failures.append("clean_normal_fpr_above_0.10")
        row["failure_reason"]="|".join(failures); row["status"]="PASS" if not failures else "FAIL"
    except Exception as e:
        row["failure_reason"]=f"{type(e).__name__}: {str(e)[:250]}"
    view_rows.append(row)
views=pd.DataFrame(view_rows); views.to_csv(OUT/"semantic_view_screening_results.csv",index=False)
print("\n"+"="*100); print("SEMANTIC VIEW ELIGIBILITY RESULTS"); print("="*100); print(views.round(4).to_string(index=False))

pnormal=pres[pres.split.eq("clean_normal_reference")].iloc[0]; psource=pres[pres.split.eq("source_family_test")].iloc[0]; pzero=pres[pres.split.eq("balanced_zero_day_test")].iloc[0]
accepted=views[views.status.eq("PASS")].view.tolist()
ok=bool(len(accepted)>=MIN_VIEWS and pnormal.normal_false_positive_rate<=MAX_NORMAL_FPR and psource.balanced_accuracy>=MIN_SOURCE_BACC and pzero.balanced_accuracy>=MIN_ZERO_BACC)
decision=dict(study="IoT_integrity_monitoring",experiment="E1_corrected_v2",dataset="TON_IoT",seed=SEED,pass_=ok,primary_threshold=float(pthr),primary_clean_normal_fpr=float(pnormal.normal_false_positive_rate),primary_source_balanced_accuracy=float(psource.balanced_accuracy),primary_zero_day_balanced_accuracy=float(pzero.balanced_accuracy),accepted_views=accepted,accepted_view_count=len(accepted),required_minimum_accepted_views=MIN_VIEWS,next_action_if_pass="Proceed to E2 only.",next_action_if_fail="Do not run attacks; revise schema or declare TON-IoT a boundary failure.")
with open(OUT/"e1_corrected_v2_decision.json","w") as f: json.dump(decision,f,indent=2)
print("\n"+"="*100); print("E1-CORRECTED-v2 FINAL DECISION"); print("="*100); print(json.dumps(decision,indent=2))
print("\nFILES WRITTEN:"); [print("-",p.name) for p in sorted(OUT.glob("*"))]
print("\nE1-CORRECTED-v2 RESULT:","PASS" if ok else "FAIL")
