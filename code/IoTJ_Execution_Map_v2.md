# IoT-J Integrity Monitoring Execution Map v2

## Rule zero

**No further attack, monitor, abstention, or confirmation experiment is run until the semantic-view preflight passes.**

A result is eligible for the manuscript only when its experiment card is marked **PASS** in this document. Development-only results remain development evidence.

---

## A. Paper and plan audit

### Original KARAT paper

| Original component | Status in new study | Reason |
|---|---|---|
| Cloud disaster-recovery ranking | Retired | New target is IoT IDS primary-label integrity |
| Synthetic KARAT-SYN benchmark | Retired | New paper uses real network telemetry |
| CKA monitor | Retired as method | Co-movement motivates the non-identifiability problem only |
| Teacher/student blending | Retired | Teacher-cost and always-blend objections remain fatal |
| CICIDS/NSL semantic mapping | Retired | No mapping of IDS labels to cloud priorities |
| Co-movement observation | Keep as motivation | Output agreement does not imply primary-model correctness |

### New paper target

> Can a frozen edge IoT IDS determine when its labels remain trustworthy without runtime labels, and abstain when telemetry evidence makes that decision non-identifiable?

### New paper output

\[
\mathcal I_t = (s_t,\; \mathcal V_{suspect},\; \mathbf d_t,\; \mathbf w_t,\; h_t),
\]

where \(s_t\in\{trusted,suspect,abstain\}\), \(\mathcal V_{suspect}\) is a semantic evidence channel, \(\mathbf d_t\) are drift statistics, \(\mathbf w_t\) are channel weights, and \(h_t\) records monitor/schema provenance.

---

## B. Evidence status

| Item | Current evidence | Status | Manuscript use now |
|---|---|---|---|
| Output-only monitor blindness | Development experiments show overconfidence under strong evasion | Exploratory PASS | Motivation only until regenerated/frozen |
| Drift-gated vote on random views | Positive on CICIoMT2024 and CICIoT2023, negative/weak elsewhere | Exploratory PASS | Development ablation only |
| Transfer attack | Positive development evidence on two IoT datasets | Exploratory PASS | Not final until semantic views |
| Sparse attack | Positive development evidence | Exploratory PASS | Not final until semantic views |
| Adaptive attack | Soft-surrogate attack does not remove all gains | Exploratory PASS | Not final; gradient-free check remains |
| TON semantic schema | Real feature groups are available | PASS | Ready for semantic view screening |
| TON primary detector monitor | v1/v2/v3 code had metric/split/support errors | FAIL | Do not cite or use results |
| TON selective support monitor | v4 preflight ran but rejected all normal traffic | FAIL | Requires view screening and profile redesign |
| Semantic channel attribution | Current setup only attacks one mutable view at a time | FAIL | Not yet nontrivial |
| Realistic flow validity | Integer rounding/range clipping only | FAIL | Must implement primitive/derived rules |
| Confirmatory replication | Not started | PENDING | Required before submission |

---

## C. Preflight diagnosis

### TON preflight observations

| Observation | Meaning | Required correction |
|---|---|---|
| `dns` view has 913 dimensions in a 5,000-row smoke sample | Likely high-cardinality query memorization | Exclude raw `dns_query`; retain controlled DNS codes only |
| `tls` and `zeek_anomaly` have 1.00 normal accuracy but near-zero zero-day accuracy | Degenerate channel / dataset artifact; not a reliable independent semantic model | Screen or drop channels that fail support/coverage criteria |
| `http` has 0.0006 normal accuracy | Model/view representation is invalid for normal traffic | Screen and redesign HTTP channel; remove high-cardinality URI/user-agent fields |
| Zero-day mix is 94.19% attacks | Evaluation prevalence is artificial and dominates accuracy | Use a fixed 50/50 zero-day evaluation and separately report prevalence sensitivity |
| Normal-test primary accuracy 0.874 vs known-reference 0.934 | Distribution/reference mismatch | Build normal profile from normal-only windows and use robust calibrated support |
| 24 windows for 27 monitor features | Insufficient support sample size | Use >=100 reference windows or reduce monitor feature dimension |

### Semantic view eligibility gate

A view may enter the final monitor only if all conditions hold:

1. It has at least 4 nonconstant transformed features.
2. It has no raw high-cardinality identity string (`dns_query`, `ssl_subject`, `ssl_issuer`, `http_uri`, `http_user_agent`).
3. Its normal-test accuracy is above the majority baseline by at least 0.05.
4. Its source-family accuracy is above 0.55.
5. It does not have a clean-normal false-drift rate above 10%.
6. It has a documented telemetry provenance and validity rule.

Failure to pass means: exclude the channel, report the exclusion, and retain its raw field only as metadata if appropriate.

---

## D. Final datasets and roles

| Dataset | Role | Required before final run |
|---|---|---|
| TON_IoT | Fifth independent boundary test and semantic provenance test | Complete semantic screening, balanced zero-day test, constrained attacks |
| CICIoMT2024 | Primary IoT semantic evaluation | Build manual feature-provenance map and repeat semantic protocol |
| CICIoT2023 | Primary IoT semantic evaluation | Build manual feature-provenance map and repeat semantic protocol |
| CSE-CIC-IDS2018 | Negative control | Semantic map; retain failure if it remains a failure |
| NSL-KDD | Legacy robustness/control dataset | Do not use as primary evidence; report boundary result |

The final paper must include all five datasets. However, identical views are not required because schemas differ. Every dataset must use the same *view construction rules*: telemetry semantics, attacker controllability, derived-feature handling, and fixed protocol.

---

## E. Experiments in order

### E1. Semantic view screening

**Goal:** produce a valid semantic view schema for TON, CICIoMT2024 and CICIoT2023.

**Inputs:** raw feature schema, source/normal/held-out family splits.

**Outputs:**
- `feature_provenance_schema.csv`
- accepted views
- excluded fields with reason
- view accuracy table
- normal false-drift table

**Pass condition:** at least 4 valid nondegenerate semantic views per primary IoT dataset.

**Failure action:** redesign groups before any attack experiment.

### E2. Primary detector baseline

**Goal:** verify the monitored object is meaningful.

**Metrics:**
- primary accuracy on normal test;
- primary accuracy on source-family test;
- primary accuracy on balanced zero-day test;
- macro-F1, attack recall, normal false-positive rate.

**Pass condition:** clean-normal and source-family performance are operationally acceptable; zero-day degradation is observable but not complete random collapse.

### E3. Clean selective-monitor calibration

**Goal:** normal profile accepts clean normal traffic.

**Metrics:**
- trusted coverage on normal test;
- trusted risk;
- false abstention rate;
- false suspect rate.

**Pass condition:** normal trusted coverage >= 85%, trusted risk no greater than primary clean risk plus 2 percentage points, false suspect rate <= 5%.

### E4. Source-family monitor test

**Goal:** known attack traffic does not automatically trigger abstention.

**Metrics:**
- source-family trusted coverage;
- source-family trusted risk;
- known-family false abstention.

**Pass condition:** report honestly even if it fails. No tuning after this result.

### E5. Zero-day family test

**Goal:** evaluate held-out attack families without runtime labels.

**Metrics:**
- collapse recall for accuracy drop >5 points;
- trusted coverage;
- trusted risk;
- abstain rate;
- suspect rate.

**Pass condition:** collapsed windows should not be trusted at a high rate. The monitor may abstain; it must not falsely certify trust.

### E6. Semantic constrained attacks

Attack each permitted primitive channel separately and jointly:

| Channel | Actions | Ground-truth attribution |
|---|---|---|
| Volume | padding/injection represented by valid byte/packet count changes | `volume` |
| Timing | nonnegative pacing/delay changes | `timing` |
| Volume + timing | joint constrained action | `{volume,timing}` |
| HTTP | only after valid application-level rule is specified | `http` |
| DNS | only after valid DNS transaction rule is specified | `dns` |

**Metrics:** damage, validity rate, trusted risk, collapse recall, attribution top-1/top-2 recall.

**Pass condition:** volume and timing attribution must be nontrivial; volume-only attack must not trivially force the answer by disabling all other views.

### E7. Baselines

Final baseline set:

1. Confidence/AC.
2. DoC.
3. ATC.
4. GDE / agreement-on-the-line.
5. Actual MD3.
6. Domain-classifier monitor explicitly named `Domain-AUC`, unless actual D3 is reproduced.
7. Exact gradient-based method only if faithfully reproduced.
8. Drift-only semantic monitor.
9. Competence-only monitor.
10. Primary confidence abstention baseline.

**Pass condition:** every baseline has an implementation citation and exact naming.

### E8. Adaptive and transfer attackers

Required:

1. White-box constrained attacker.
2. Transfer attacker.
3. Sparse primitive-channel attacker.
4. Rate-matched attacker.
5. Estimator-aware adaptive attacker.
6. Gradient-free check against the same monitor objective.

**Pass condition:** adaptive attack is at least as strong as nonadaptive attack on primary damage, or explain why semantic constraints prevent it.

### E9. Semantic versus random partition ablation

**Goal:** establish that provenance views—not arbitrary partitions—cause the effect.

Compare:
- semantic views;
- correlation-balanced/random views;
- monolithic detector only.

**Pass condition:** semantic views improve selective risk, collapse recall, attribution, or attack frontier under the fixed protocol.

### E10. Model-family check

Run the frozen primary detector as:
- small MLP;
- HistGradientBoosting / LightGBM-like model.

Use the same semantic monitor views and transfer attacks.

**Pass condition:** if GBDT fails, report model-family boundary; do not hide it.

### E11. Confirmation

Frozen settings only:

```text
RUN = confirm
SEEDS = [10, 11, 12]
POOL_SEED = 1
```

Primary test family is frozen before execution. Holm correction covers only the declared primary comparisons.

---

## F. Final claims allowed only after gates pass

### Claim 1: Non-identifiability

Output-only monitor observations cannot identify true primary-detector accuracy under coordinated evasion without assumptions.

**Required:** formal theorem and proof.

### Claim 2: Semantic selective integrity monitoring

Under semantic evidence constraints, the monitor can select trusted windows and abstain on unidentifiable windows.

**Required:** E3, E4 and E5 pass.

### Claim 3: Attack-channel attribution

Semantic provenance views identify manipulated telemetry channels.

**Required:** E6 attribution metrics under at least two mutable channels.

### Claim 4: Stealth--damage trade-off

An adversary preserving monitor integrity evidence sacrifices primary-detector damage.

**Required:** E8 frontier with adaptive and gradient-free attack checks.

### Claim 5: Edge suitability

The monitor fits the stated memory and latency envelope.

**Required:** E10 resource table; no energy claim without hardware measurement.

---

## G. Current strict next action

**Only E1 is active now.**

Do not run attacks, abstention, development, or confirmation until the preflight is corrected:

1. Remove high-cardinality identity-like content fields.
2. Screen degenerate semantic views.
3. Build a balanced zero-day mixture.
4. Use enough clean windows for the robust support profile.
5. Re-run preflight.

Only if E1 passes do we proceed to E2.
