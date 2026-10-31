"""Read-only A–G evidence audit. Run in Kaggle after stopping other jobs.
No joblib loading, training, predictions, attack optimization, or automatic approval.
"""
import csv,gzip,hashlib,io,json,os,re,shutil,zipfile
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd

ACTIVE=Path('/kaggle/working/resume_verified_20261011T144807877506Z')
WORK=Path('/kaggle/working');INPUT=Path('/kaggle/input')
if not (ACTIVE/'development').is_dir():raise FileNotFoundError(ACTIVE/'development')
OUT=WORK/('PLAN_CLOSURE_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)
COPY=OUT/'evidence';COPY.mkdir()
MAX_ENTRY=24*1024**2
MAX_TOTAL=384*1024**2
MAX_NESTED_ZIP=64*1024**2
MAX_DEPTH=3
MAX_CSV_ROWS=200000

# The reference is the supplied original A–G plan, not a newly invented plan.
REFERENCE_PLAN='# Research Plan: Unlabeled Integrity Monitoring for Frozen Edge IoT IDS Under Evasion\n\n**Status:** Development roadmap — not a submission-ready manuscript  \n**Target venue:** IEEE Internet of Things Journal, regular submission  \n**Special issue decision:** Do **not** target the current AI-Driven Network Forensics special issue unless a genuine evidence-acquisition, provenance, and post-incident reconstruction component is added.  \n**Primary framing:** Edge-IoT integrity monitoring under adversarial telemetry manipulation.  \n**Not the framing:** Generic drift detection, generic IDS classification, universal accuracy certification, or end-to-end digital forensics.\n\n---\n\n## 1. Executive decision\n\nThe rejected KARAT manuscript should **not** be revised into this paper. Its CKA-triggered teacher--student blend, synthetic cloud-disaster-recovery task, semantic IDS-to-cloud label mappings, and teacher-cost narrative are retired as central contributions.\n\nThe new work keeps only the motivating observation:\n\n> A deployed model may be wrong while multiple monitoring models appear mutually consistent; unlabeled output agreement alone does not establish that the detector remains trustworthy.\n\nThe new paper must be written as a **new manuscript**. It will study the conditions under which an edge IoT IDS can or cannot monitor the trustworthiness of its own labels without ground truth during an attack.\n\n### Proposed final title\n\n**Unlabeled Integrity Monitoring of Frozen Edge IoT Intrusion Detectors Under Evasion**\n\nAlternative after semantic provenance work is complete:\n\n**Can an Unlabeled Edge Monitor Detect Evasion? Identifiability Limits and Provenance-Aware Multi-View Integrity Monitoring for IoT IDS**\n\nThe second title is stronger, but use it only if the semantic-view/provenance component is actually implemented and evaluated.\n\n---\n\n## 2. Problem statement\n\nAn IoT intrusion detector is deployed at an edge node. During operation, labels are delayed, unavailable, or costly to obtain. The detector can therefore receive manipulated telemetry while the operator has no direct way to know whether the detector\'s labels remain reliable.\n\nLet a frozen detector be decomposed into \\(G\\) view models. At time or window \\(t\\), view \\(g\\) produces probabilities \\(p_g(x)\\) for records in the current telemetry window. The monitor observes the view-output matrix but not the true labels.\n\nThe task is **not** to retrain the IDS and **not** to detect every malicious flow. The task is to decide whether the current detector outputs remain sufficiently trustworthy for an operator or downstream response policy to use.\n\nThe monitor must output an integrity record:\n\n\\[\n\\mathcal{I}_t = (\\widehat A_t,\\,\\mathbf{w}_t,\\,\\mathbf{d}_t,\\,\\mathcal{V}_{\\mathrm{suspect}},\\,\\rho_t,\\,h_t),\n\\]\n\nwhere:\n\n- \\(\\widehat A_t\\) is a conditional estimate of detector accuracy;\n- \\(\\mathbf{w}_t\\) are view weights;\n- \\(\\mathbf{d}_t\\) are view-level drift statistics;\n- \\(\\mathcal{V}_{\\mathrm{suspect}}\\) identifies suspect telemetry/evidence channels;\n- \\(\\rho_t\\) is an integrity or abstention score;\n- \\(h_t\\) hashes the reference-window configuration, view schema, and monitor version.\n\nThe monitor does **not** claim universal or certified recovery of true accuracy. It either reports a conditional estimate under explicit assumptions or abstains when those assumptions are not met.\n\n---\n\n## 3. Research gap and position\n\n### 3.1 What existing work already covers\n\n1. **Unlabeled concept-drift detection.** MD3 tracks the density of samples near a classifier\'s decision margin. It detects drift without labels, but it does not estimate IDS accuracy under adversarially induced correlated errors.\n2. **Adversarial concept drift.** Predict-Detect and later adversarial-drift studies examine attackers who evade or poison drift detectors. They do not directly solve the narrow problem of determining whether a frozen IoT IDS\'s labels remain trustworthy without labels.\n3. **Adversarial IDS robustness.** Realistic black-box traffic attacks and constrained evasion studies show that feature-space attacks can overstate practical risk; attack constraints must be explicit.\n4. **IoT feature grouping and multi-view IDS.** Feature grouping is used for lightweight/high-accuracy IoT intrusion detection. It is not normally tied to telemetry provenance, attacker control, unlabeled label-trust estimation, or monitor abstention.\n5. **IoT forensics.** IoT forensic work addresses evidence acquisition, source identification, provenance, storage, chain-of-custody, and reconstruction. The present work does not yet implement those functions.\n\n### 3.2 Narrow novelty claim\n\nThe novelty claim is **not** that drift detection, adversarial IDS defense, feature grouping, or weighted voting is new.\n\nThe claim to test is:\n\n> The intersection of (i) unlabeled post-deployment label-trust estimation, (ii) test-time evasive manipulation of IoT telemetry, and (iii) telemetry-provenance-aware multi-view integrity monitoring is underexplored.\n\nThe paper contributes an identifiability limit, a provenance-aware monitor, a realistic attack/evaluation protocol, and a failure map.\n\n### 3.3 Scope language\n\nUse **integrity monitoring** or **forensic-ready integrity evidence**, not full "network forensics."\n\n"Forensics-ready" is permitted only for the monitor evidence record: view schema, provenance mapping, drift evidence, timestamps, hashes, and suspect channels. Do not claim post-incident reconstruction, chain-of-custody, evidence acquisition, or causal attribution unless those are implemented.\n\n---\n\n## 4. Core contributions to prove\n\n### C1. Output-only non-identifiability theorem\n\nFormalize an unlabeled multi-view monitor observing only prediction outputs \\(P\\). Construct two worlds with the same observable output matrix but different true labels and therefore different detector accuracies.\n\nTarget conclusion:\n\n\\[\n\\nexists\\,\\widehat{A}(P)\\quad\\text{that uniformly recovers true accuracy from unlabeled outputs alone.}\n\\]\n\nThis theorem must be written precisely. It should state what is observed, what attacker control is allowed, which labels differ, and why the two worlds are indistinguishable to every output-only monitor.\n\n**Purpose:** This distinguishes the paper from ordinary drift detection. It explains why output agreement, confidence, entropy, correlation, and similar unlabeled quantities can fail under coordinated evasion.\n\n### C2. Provenance-aware semantic views\n\nReplace correlation-balanced/random feature partitions with semantic telemetry views.\n\nEach feature must be mapped to a primitive source channel, for example:\n\n| Semantic view | Example primitive telemetry | Example derived flow features | Attacker-control status |\n|---|---|---|---|\n| Size/volume | packet sizes, packet count | bytes, packets, mean packet length | partly mutable |\n| Timing | packet timestamps, pacing | duration, IAT, packet/s, byte/s | partly mutable |\n| Directionality | forward/reverse traffic | Fwd/Bwd packets, Fwd/Bwd bytes | partly mutable |\n| TCP state | SYN/ACK/FIN/RST events | flag counts and state measures | constrained |\n| Protocol/service | protocol number, destination service | protocol, port class | normally immutable for a fixed flow |\n| Derived statistics | rates, averages, ratios | flow rates, average size | recompute; do not directly perturb |\n\nThe feature schema, mapping, units, mutability and constraints must be released as a machine-readable CSV.\n\n### C3. Drift-gated integrity monitor\n\nThe method begins with the current drift-gated voting evidence but becomes semantic:\n\n1. Train one lightweight model bank for each provenance view.\n2. Calibrate each view using a clean, trusted reference window.\n3. Measure the drift of each view\'s predicted positive rate and output behavior from that reference.\n4. Downweight suspect views.\n5. Estimate conditional accuracy or return **abstain** if monitor integrity is insufficient.\n6. Emit the integrity evidence record.\n\nA sufficient weighted-integrity condition is:\n\n\\[\n\\sum_{g\\in\\mathcal{C}} w_g(1-2e_g)\n>\n\\sum_{g\\in\\mathcal{A}}w_g,\n\\]\n\nwhere \\(\\mathcal{C}\\) denotes clean views, \\(\\mathcal{A}\\) attacked views, \\(w_g\\) the inferred weights, and \\(e_g\\) the conditional clean-view error.\n\nThis is a sufficient condition for the weighted decision to remain dominated by clean evidence. It is **not** an unconditional accuracy guarantee.\n\n### C4. Stealth--damage frontier\n\nA detector-aware adversary optimizes two conflicting objectives:\n\n\\[\n\\max_{\\delta}\\;\n\\mathcal{L}_{\\mathrm{evasion}}(x+\\delta)\n-\n\\lambda\\mathcal{L}_{\\mathrm{monitor}}(x+\\delta).\n\\]\n\nIt must be shown that preserving monitor statistics reduces attainable attack damage, or else that the monitor fails and abstains.\n\n### C5. Boundary condition and abstention\n\nThe final study must explain when the method works and when it does not. The development result suggests view-level accuracy under natural shift is a candidate boundary variable. Test the preregistered prediction:\n\n> When mean semantic-view accuracy under natural shift is at least 0.80, the monitor will improve differential estimation error over the fixed primary baseline; otherwise, it may abstain or provide no advantage.\n\nThe fifth dataset must test this prediction without changing it after results are known.\n\n---\n\n## 5. Current development evidence\n\n### 5.1 What has been completed\n\nThe development experiments include:\n\n- CICIoMT2024, CICIoT2023, CSE-CIC-IDS2018 and NSL-KDD;\n- three seeds for the primary monitor experiments;\n- random/correlation-balanced disjoint view construction;\n- white-box feature-space PGD;\n- surrogate transfer PGD;\n- rate-matched monitor-aware attacks;\n- soft-surrogate estimator-aware PGD;\n- sparse feature attacks;\n- range clipping, low-cardinality freezing, and integer rounding;\n- output-only estimator baselines: AC, DoC, ATC, GDE, ALine, majority and reweighted majority;\n- domain-AUC proxy, KS-max proxy, and margin-density proxy;\n- drift-gate ablation (`ANCH`, `W_ACC`, `DRIFT_ONLY`);\n- differential accuracy-estimation error;\n- decision-level damage detection;\n- attack frontier;\n- view memory/latency measurements.\n\n### 5.2 Development findings that can be retained as exploratory evidence\n\n- Output-only estimators over-report accuracy under successful evasion.\n- A soft estimator-aware attack still leaves positive gains on CICIoMT2024 and CICIoT2023.\n- The drift term explains most of the gain on the positive datasets; competence-only weighting does not.\n- Transfer attacks remain effective against the monitor but do not erase the monitor gain on the positive IoT datasets.\n- Sparse attacks can touch most views, yet the monitor still improves differential error on the two positive IoT datasets.\n- The monitor has explicit negative/failure cases on CSE-CIC-IDS2018 and weak/inconclusive outcomes on NSL-KDD.\n\n### 5.3 Development results that must not be final claims\n\n- Current partitions are not semantic/provenance-based.\n- Current D3 and MD3 implementations are proxies, not reproductions.\n- The gradient score is a proxy, not a verified reproduction of GdScore.\n- Integer rounding/range clipping is not packet-semantic validity.\n- The present Holm-corrected primary family was chosen after development results were visible.\n- The present estimator-aware attack uses a differentiable soft surrogate, not a full hard-objective and gradient-free adaptive attack.\n\n---\n\n## 6. Experiments needed for the complete study\n\n### Experiment group A: protocol freeze and confirmatory replication\n\n**Goal:** Separate exploratory results from confirmatory evidence.\n\n1. Freeze source code under a Git tag: `v1-development-freeze`.\n2. Create `protocol-confirmatory.yaml` containing:\n   - datasets;\n   - sample seed;\n   - model settings;\n   - semantic view schema version;\n   - attacks;\n   - attack strengths;\n   - metrics;\n   - primary hypotheses;\n   - correction family;\n   - seeds.\n3. Use fresh settings:\n   - `RUN = "confirm"`\n   - `SEEDS = [10, 11, 12]`\n   - `BLIND_SEEDS = [10]`\n   - `POOL_SEED = 1`\n4. Do not tune any parameter after the first confirmatory result.\n\n**Primary confirmatory family:**\n\n| Dataset | Attack |\n|---|---|\n| CICIoMT2024 | constrained semantic white-box |\n| CICIoMT2024 | constrained transfer |\n| CICIoMT2024 | constrained sparse/provenance attack |\n| CICIoT2023 | constrained semantic white-box |\n| CICIoT2023 | constrained transfer |\n| CICIoT2023 | constrained sparse/provenance attack |\n\n**Primary metric:** differential absolute accuracy-estimation error.\n\n**Statistical test:** paired, seed/pair clustered bootstrap, one-sided gain test, Holm correction over exactly six primary tests.\n\n### Experiment group B: semantic provenance views\n\n**Goal:** Replace artificial feature partitions.\n\nFor each target IoT dataset:\n\n1. Read official feature definitions.\n2. Mark every predictor as:\n   - primitive telemetry feature,\n   - derived feature,\n   - immutable field,\n   - categorical/protocol field,\n   - integer count,\n   - mutable under a valid attacker action.\n3. Build views from semantic channels, not correlation alone.\n4. Compare:\n   - random/correlation partitions,\n   - semantic provenance partitions,\n   - one monolithic model.\n5. Measure:\n   - view accuracy;\n   - feature overlap;\n   - attacker exposure per primitive channel;\n   - monitor estimation error;\n   - suspect-channel attribution precision/recall.\n\n**Required table:** `feature_provenance_schema.csv`.\n\nColumns:\n\n```text\nfeature,dataset,semantic_view,primitive_source,derived_from,mutable,integer,categorical,immutable_reason,validity_rule\n```\n\n### Experiment group C: realistic attack validity\n\n**Goal:** Ensure the attack remains plausible after constraints.\n\nFor each semantic view, define allowed transformations.\n\n| Attack primitive | Allowed operations | Recompute afterward |\n|---|---|---|\n| Packet padding | add bytes within MTU/payload bounds | total bytes, packet-size statistics, rates |\n| Timing/pacing | nonnegative delay with bounded jitter | duration, IAT, rates |\n| Packet injection | add valid dummy packets subject to protocol constraints | counts, bytes, timing, averages |\n| TCP flags | no direct arbitrary flipping | derive from valid state transitions |\n| Protocol/service | immutable per flow | none |\n\nReport:\n\n\\[\n\\text{ValidityRate} = \\frac{\\text{valid adversarial records}}{\\text{all generated adversarial records}}.\n\\]\n\nAlso report damage before and after projection/recomputation. If constrained damage vanishes, state that directly.\n\n### Experiment group D: baseline correctness\n\n**Goal:** Prevent a reviewer from rejecting the work for incorrect comparisons.\n\nImplement the actual published procedures or explicitly exclude them.\n\n| Current proxy | Action |\n|---|---|\n| `d3_auc` | Rename `Domain-AUC proxy`; do not call it D3 |\n| `md3` | Rename `Margin-density proxy`; implement actual MD3 or exclude citation |\n| `gd_score` | Rename `LastLayer-Gradient-Norm proxy`; reproduce exact GdScore only after method/code verification |\n\nRequired final baselines:\n\n1. Frozen detector confidence: AC.\n2. Difference of confidence: DoC.\n3. Accuracy-threshold confidence: ATC.\n4. Agreement/generalization estimator: GDE/ALine.\n5. Actual MD3.\n6. Actual D3 or explicitly named domain-classifier monitor.\n7. Exact gradient-based estimator, if reproducible.\n8. Drift-gated majority monitor.\n9. Drift-only ablation.\n10. Competence-only ablation.\n\n### Experiment group E: adaptive attacks\n\n**Goal:** Test the actual defense mechanism, as required by adaptive-evaluation practice.\n\nRequired attacks:\n\n1. White-box constrained semantic attack.\n2. Surrogate-transfer constrained attack.\n3. Sparse primitive-channel attack.\n4. Rate-matched attack.\n5. Estimator-aware attack using a differentiable surrogate.\n6. Gradient-free estimator-aware verification (SPSA or NES).\n\nFor the adaptive attack, optimize both detector damage and monitor deception:\n\n\\[\n\\max_{\\delta} \\;\n\\mathrm{Damage}(\\delta)\n- \\lambda_1\\mathrm{MonitorDeviation}(\\delta)\n- \\lambda_2\\mathrm{ConstraintViolation}(\\delta).\n\\]\n\nThe gradient-free verification is mandatory because the hard gate, discrete feature constraints, and feature recomputation may invalidate a purely differentiable attack result.\n\n### Experiment group F: fifth dataset boundary test\n\n**Goal:** Test generalization rather than add another table.\n\nCandidate: TON_IoT or NF-ToN-IoT-V2.\n\nBefore loading the data, commit the prediction:\n\n> If mean semantic-view accuracy under natural shift is at least 0.80, the monitor will obtain a positive, clustered confidence interval for its differential estimation-error gain under the primary constrained attack; otherwise, it will not claim a gain.\n\nThe fifth dataset must not choose parameters. It is a held-out boundary test.\n\n### Experiment group G: model-family and resource checks\n\n1. Re-run the primary attack family using gradient-boosted view models.\n2. Report semantic-view MLP and GBDT results separately.\n3. Report:\n   - parameter count;\n   - float32/INT8 size estimate;\n   - per-1,000-record inference time;\n   - monitor overhead;\n   - energy is not claimed without hardware measurement.\n4. If GBDT views fail, report the result as a model-family boundary.\n\n---\n\n## 7. Metrics\n\n### Primary metric\n\nFor estimator \\(m\\), attack state \\(a\\), and clean reference state \\(0\\):\n\n\\[\nE_m(a) = \\left|[\\widehat A_m(a) - A(a)] - [\\widehat A_m(0) - A(0)]\\right|.\n\\]\n\nThis differential error separates attack-induced monitoring error from natural-shift calibration bias.\n\n### Secondary metrics\n\n- True accuracy damage: \\(A(0)-A(a)\\).\n- Relative differential-error reduction against a fixed baseline.\n- AUROC for detecting accuracy damage greater than 5 percentage points.\n- TPR at 5% FPR.\n- False alarms on clean and natural-shift windows.\n- Attack frontier: largest damage hidden while monitor-estimated accuracy drop remains below \\(\\tau\\).\n- View/channel attribution precision, recall and F1.\n- Validity rate and damage retention after constraint projection.\n- Memory and latency.\n- Abstention rate and abstention precision.\n\n### Do not use as primary claims\n\n- Raw detector classification accuracy.\n- Attack success without a validity audit.\n- Mean results without pair/seed clustering.\n- “Best baseline” selected separately after observing each result unless described as an oracle comparison.\n\n---\n\n## 8. Statistical plan\n\n1. The independent unit is a **pair × seed** combination, not an attack strength, view count, or estimator row.\n2. Bootstrap confidence intervals resample pair × seed units.\n3. Holm correction is applied to the frozen six-test confirmatory primary family.\n4. Development results remain exploratory.\n5. Negative results remain visible in the main text.\n6. Report effect sizes and complete result files, not only selected significant rows.\n\n---\n\n## 9. Manuscript structure\n\n1. **Introduction**\n   - Frozen edge detectors, delayed labels, adversarial telemetry.\n   - Why confidence and agreement alone do not establish trust.\n   - Contributions and scope.\n\n2. **Related Work**\n   - IDS evasion and realistic traffic attacks.\n   - Unlabeled drift and performance monitoring.\n   - Agreement-based accuracy estimation.\n   - Multi-view and lightweight IoT IDS.\n   - IoT forensic evidence integrity, clearly differentiated.\n\n3. **Problem and Threat Model**\n   - Detector, views, trusted reference window.\n   - Telemetry provenance and attacker control.\n   - White-box, transfer, sparse and adaptive attacker capabilities.\n\n4. **Identifiability Limit**\n   - Theorem 1 and proof.\n\n5. **Provenance-Aware Integrity Monitor**\n   - Semantic views.\n   - Drift evidence.\n   - Weighted vote.\n   - Integrity record.\n   - Abstain condition.\n   - Proposition/weighted integrity condition.\n\n6. **Experimental Protocol**\n   - Data, schema, feature provenance, natural shifts.\n   - Validity-constrained attacks.\n   - Baselines, primary metric, confirmation protocol.\n\n7. **Results**\n   - Output-only blindness.\n   - Main primary-family comparison.\n   - Adaptive and transfer attacks.\n   - Stealth--damage frontier.\n   - Semantic partition ablation.\n   - Decision-level detection.\n   - Attribution and edge footprint.\n   - Negative controls and boundary map.\n\n8. **Limitations and Ethics**\n   - Feature/flow-level rather than packet-level semantics.\n   - Trusted reference window assumption.\n   - Dataset-specific results.\n   - No full digital-forensics chain-of-custody claim.\n\n9. **Conclusion**\n\n---\n\n## 10. Initial reference inventory\n\n### Verified or strongly relevant\n\n- Sethi and Kantardzic, *On the Reliable Detection of Concept Drift from Streaming Unlabeled Data*, Expert Systems with Applications, 2017. DOI: 10.1016/j.eswa.2017.04.008.\n- Sethi and Kantardzic, *Handling Adversarial Concept Drift in Streaming Data*, Expert Systems with Applications, 2018.\n- Korycki and Krawczyk, *Adversarial Concept Drift Detection Under Poisoning Attacks for Robust Data Stream Mining*, Machine Learning, 2022. DOI: 10.1007/s10994-022-06177-w.\n- Debicha et al., *Adv-Bot: Realistic Adversarial Botnet Attacks Against Network Intrusion Detection Systems*, Computers & Security 128, 2023. DOI: 10.1016/j.cose.2023.103176.\n- Yan et al., *Automatic Evasion of Machine-Learning-Based Network Intrusion Detection Systems*, IEEE Transactions on Dependable and Secure Computing 21, 2024. DOI: 10.1109/TDSC.2023.3247585.\n- He et al., *A Lightweight and Efficient IoT Intrusion Detection Method Based on Feature Grouping*, IEEE Internet of Things Journal 11(2), 2024. DOI: 10.1109/JIOT.2023.3294259.\n- Zoppi et al., *Which Algorithm Can Detect Unknown Attacks?*, Computers & Security 127, 2023.\n- Stoyanova et al., *A Survey on the Internet of Things Forensics*, IEEE Communications Surveys & Tutorials 22, 2020. DOI: 10.1109/COMST.2019.2962586.\n- Ruiz-Villafranca et al., *A Forensic Tool for the Identification, Acquisition and Analysis of Sources of Evidence in IoT Investigations*, Internet of Things 27, 2024.\n\n### Candidate references supplied by the user; verify bibliographic details before citation\n\n- Alatawi (2026), adversarial evasion review.\n- Maseno et al. (2026), explainable adversarial-evasion detection.\n- Apruzzese et al. (2024), adversarial perturbations and concept drift.\n- Nie et al. (2024), multi-task multi-view IoT IDS.\n- Yuan et al. (2026), adaptive drift-aware IDS.\n\n### Citation rule\n\nDo not cite arXiv versions where a journal or proceedings version exists. Verify every DOI, publication year, venue, page range, and author list in Crossref, IEEE Xplore, the publisher page, or the final PDF before submission.\n\n---\n\n## 11. Decision gates\n\n### Continue toward regular IoT-J only if all are satisfied\n\n- Confirmatory primary-family gains remain positive after Holm correction.\n- Fifth-dataset boundary prediction is correctly evaluated and reported.\n- Semantic provenance views replace random/correlation partitions.\n- Validity-constrained attacks retain nontrivial damage.\n- Actual MD3 and at least one additional published unlabeled monitor are included.\n- The adaptive attack cannot trivially invalidate the monitor without a documented damage cost or abstention.\n- The final paper reports the IDS2018 and NSL-KDD failures openly.\n\n### Submit to the special issue only if all are additionally satisfied\n\n- Integrity records are implemented with timestamps, configuration hashes and provenance metadata.\n- View-level evidence channels are attributable to telemetry sources.\n- An explicit evidence acquisition/storage/provenance component exists.\n- The manuscript includes post-incident evidence correlation or reconstruction, not merely monitoring.\n\nOtherwise, use **regular IEEE Internet of Things Journal**.\n\n---\n\n## 12. Immediate next task\n\n1. Attach TON_IoT or NF-ToN-IoT-V2.\n2. Print and archive its schema.\n3. Build `feature_provenance_schema.csv`.\n4. Replace correlation-balanced views with semantic provenance views.\n5. Freeze the confirmatory protocol.\n6. Only then run the final confirmatory experiment.\n\nThis ordering is deliberate. More random attack variants will not make the paper more novel. Semantic provenance, realistic constraints, a formal limit, and an independent confirmation are what convert the current promising development evidence into a serious IoT-J submission.\n'
(OUT/'REFERENCE_ORIGINAL_PLAN.md').write_text(REFERENCE_PLAN,encoding='utf-8')

FILES=[];ASSETS=[];ARCHIVES=[];ERRORS=[];EVIDENCE=[];FLAGS=[];TABLES=[];DOCS=[]
content={};seen=set();bytes_retained=0;budget_exhausted=False
PLAN_RE=re.compile(r'plan|protocol|prereg|claim|theorem|lemma|proof|provenance|source.*review|source.*quot|integrity.*record|README_RESTORE',re.I)
CSV_RE=re.compile(r'coverage|evidence|ledger|schema|manifest|summary|interval|bank_units|remaining|resource|quantization|risk.coverage|frontier|replay|constraint|validity|retention|definition|provenance|attribution|md3_results|comparison|calibration|paired_rule|comparison_rule',re.I)
RAW_RE=re.compile(r'(^|[_ -])(train|test_df|validation_df|attack_records|source_test|target_windows|target_estimator_windows|pool)([_ .-]|$)',re.I)
ASSET_RE=re.compile(r'\.(pcap|pcapng)(\.gz)?$|(^|/)(conn\.log\.labeled|zeek-conn\.log\.labeled|labels?\.config)$',re.I)


def digest(b):return hashlib.sha256(b).hexdigest()
def norm(v):return re.sub(r'[^a-z0-9]','',str(v).lower())
def truth(v):return str(v).strip().lower() in {'true','1','yes'}
def eligible(name):
 base=Path(name).name;suffix=Path(base).suffix.lower()
 if suffix=='.json':return not re.search(r'credential|secret|token|cookie',base,re.I)
 if suffix=='.csv':return bool(CSV_RE.search(base)) and not RAW_RE.search(base)
 if suffix in {'.yaml','.yml','.md','.txt'}:return bool(PLAN_RE.search(base))
 return False

def flag_walk(obj,source,path='',depth=0):
 if depth>10:return
 if isinstance(obj,dict):
  for k,v in obj.items():
   p=(path+'.' if path else '')+str(k)
   if isinstance(v,(dict,list)):flag_walk(v,source,p,depth+1)
   elif isinstance(v,(bool,int,float,str)) and re.search(r'confirm|prospect|valid|approved|independ|packet|trace|source|freeze|threshold|seed|scope|retrain|attack|labels|zeek|status|complete|sha256',str(k),re.I):
    FLAGS.append({'evidence_sha256':source,'key':p,'value':str(v)[:2500]})
 elif isinstance(obj,list) and len(obj)<=100:
  for i,v in enumerate(obj):flag_walk(v,source,f'{path}[{i}]',depth+1)

def retain(locator,name,blob):
 global bytes_retained,budget_exhausted
 h=digest(blob)
 EVIDENCE.append({'locator':locator,'name':Path(name).name,'bytes':len(blob),'sha256':h})
 if h in seen:return
 if bytes_retained+len(blob)>MAX_TOTAL:
  budget_exhausted=True;ERRORS.append({'locator':locator,'issue':'METADATA_BUDGET_EXHAUSTED'});return
 seen.add(h);bytes_retained+=len(blob);content[h]=blob
 suffix=Path(name).suffix.lower();(COPY/(h+suffix)).write_bytes(blob)
 if suffix=='.json':
  try:obj=json.loads(blob.decode('utf-8-sig'));flag_walk(obj,h)
  except Exception as e:ERRORS.append({'locator':locator,'issue':'JSON_PARSE: '+str(e)})
 elif suffix=='.csv':
  try:
   table=pd.read_csv(io.BytesIO(blob),keep_default_na=False,nrows=MAX_CSV_ROWS+1)
   partial=len(table)>MAX_CSV_ROWS
   if partial:table=table.iloc[:MAX_CSV_ROWS]
   TABLES.append((h,Path(name).name,table,partial))
   if partial:ERRORS.append({'locator':locator,'issue':'CSV_ROW_CAP; table not fully inspected'})
  except Exception as e:ERRORS.append({'locator':locator,'issue':'CSV_PARSE: '+str(e)})
 else:
  try:DOCS.append((h,Path(name).name,blob.decode('utf-8-sig')))
  except Exception as e:ERRORS.append({'locator':locator,'issue':'TEXT_DECODE: '+str(e)})

def scan_zip(source,locator,depth=0):
 if depth>MAX_DEPTH:
  ERRORS.append({'locator':locator,'issue':'NESTED_ARCHIVE_DEPTH_LIMIT'});return
 try:
  with zipfile.ZipFile(source) as z:
   infos=z.infolist()
   ARCHIVES.append({'locator':locator,'kind':'ZIP','members':len(infos),'inspection':'CENTRAL_DIRECTORY_AND_SELECTED_METADATA_ONLY'})
   for info in infos:
    if info.is_dir():continue
    member=f'{locator}!{info.filename}'
    if ASSET_RE.search(info.filename):ASSETS.append({'locator':member,'bytes':info.file_size,'kind':'ARCHIVED_ASSET_NOT_REPLAYED','header_hex':''})
    if eligible(info.filename):
     if info.file_size>MAX_ENTRY:
      ERRORS.append({'locator':member,'issue':'SELECTED_METADATA_ENTRY_TOO_LARGE'});continue
     if budget_exhausted:continue
     try:retain(member,info.filename,z.read(info))
     except Exception as e:ERRORS.append({'locator':member,'issue':'ZIP_ENTRY_READ: '+str(e)})
    elif info.filename.lower().endswith('.zip'):
     if info.file_size<=MAX_NESTED_ZIP and depth<MAX_DEPTH and not budget_exhausted:
      try:scan_zip(io.BytesIO(z.read(info)),member,depth+1)
      except Exception as e:ERRORS.append({'locator':member,'issue':'NESTED_ZIP_READ: '+str(e)})
     else:ERRORS.append({'locator':member,'issue':'NESTED_ZIP_NOT_OPENED_SIZE_OR_DEPTH_LIMIT'})
    elif re.search(r'\.(tar|tgz|tar\.gz|7z|rar)$',info.filename,re.I):
     ERRORS.append({'locator':member,'issue':'NON_ZIP_CONTAINER_INVENTORIED_NOT_CONTENT_INSPECTED'})
 except Exception as e:ERRORS.append({'locator':locator,'issue':'ZIP_OPEN: '+str(e)})

for root in [WORK,INPUT]:
 if not root.is_dir():continue
 for directory,dirs,names in os.walk(root,followlinks=False):
  d=Path(directory)
  dirs[:]=sorted(x for x in dirs if not (d/x).is_symlink() and (d/x)!=OUT and not x.startswith('PLAN_CLOSURE_AUDIT_'))
  for name in sorted(names):
   p=d/name
   if p.is_symlink():continue
   try:
    size=p.stat().st_size
    FILES.append({'locator':str(p),'bytes':size,'suffix':p.suffix.lower()})
    if ASSET_RE.search(str(p)):
     header=''
     if re.search(r'\.pcap(ng)?(\.gz)?$',name,re.I):
      try:
       opener=gzip.open if name.lower().endswith('.gz') else open
       with opener(p,'rb') as f:header=f.read(16).hex()
      except Exception as e:ERRORS.append({'locator':str(p),'issue':'CAPTURE_HEADER_READ: '+str(e)})
     ASSETS.append({'locator':str(p),'bytes':size,'kind':'FILESYSTEM_ASSET_NOT_REPLAYED','header_hex':header})
    if eligible(name):
     if size<=MAX_ENTRY and not budget_exhausted:retain(str(p),name,p.read_bytes())
     elif size>MAX_ENTRY:ERRORS.append({'locator':str(p),'issue':'SELECTED_METADATA_FILE_TOO_LARGE'})
    elif name.lower().endswith('.zip'):scan_zip(p,str(p))
    elif re.search(r'\.(tar|tgz|tar\.gz|7z|rar)$',name,re.I):
     ARCHIVES.append({'locator':str(p),'kind':'OTHER_ARCHIVE','members':'','inspection':'NOT_CONTENT_INSPECTED'})
     ERRORS.append({'locator':str(p),'issue':'NON_ZIP_CONTAINER_INVENTORIED_NOT_CONTENT_INSPECTED'})
   except Exception as e:ERRORS.append({'locator':str(p),'issue':'FILESYSTEM_READ: '+str(e)})

# Content diagnostics: do not approve methods merely because files exist.
DIAGNOSTICS=[]
for h,name,t,partial in TABLES:
 row={'sha256':h,'name':name,'rows_inspected':len(t),'full_table_inspected':not partial,'columns':'|'.join(map(str,t.columns))}
 for col in ['dataset','status','review_decision','source_verified','confirmatory_test','independent_whole_bank_runs','interval_scope','oracle_labels_consumed','packet_validity_established','NetFlow_cross_field_validity_established','models_trained']:
  if col in t:
   counts=t[col].astype(str).value_counts(dropna=False)
   row[col+'_counts']=json.dumps({str(k):int(v) for k,v in counts.head(25).items()})
 DIAGNOSTICS.append(row)

TASKS=[
 ('A','A1','Development freeze/reproduction','ALREADY_DONE_IF_EVIDENCE_CONFIRMS','final_development_receipt.json|clean_primary_reproduction.csv|reproduction_status.csv','Preserve frozen development; no blanket retraining.'),
 ('A','A2','Final prospective six-test protocol and results','REQUIRED_FINAL','protocol-confirmatory.yaml|protocol_confirmatory.yaml|confirmatory_protocol.json|primary_hypothesis_tests.csv|holm_primary_results.csv','Choose original CIC primary family versus IoT-23 amendment explicitly; prove outcome chronology and sampling units.'),
 ('B','B1','Reviewed source/dependency contract','REQUIRED_FINAL','primary_feature_contract_REVIEW.csv|feature_provenance_schema.csv|quality_corrected_feature_ledger.csv|definition_excerpts_with_explicit_reconciliation.csv|CICIoT_documentary_provenance_review.csv','Review source identity, units, primitive/derived fields and executable constraints; coverage alone is not approval.'),
 ('B','B2','Capture/extractor/label/model-row linkage','REQUIRED_TRACE_TRACK','A0_protocol_reset_and_next_step.json|A0_scenario_asset_provenance_manifest.csv|A2_clean_replay_receipt.json|trace_to_model_row_mapping.csv|record_mapping_review.csv','Resolve label rules, capture/log mapping, clean replay and row identity.'),
 ('C','C1','Existing feature-space consistency/retention','DEVELOPMENT_REUSE','damage_retention_overview.csv|report_constraint_checks.csv','Reuse candidate algebraic/type/range checks; not packet validity.'),
 ('C','C2','Valid primitive transformations and re-extraction','REQUIRED_TRACE_TRACK','trace_attack_validity.csv|packet_transformation_receipt.json|trace_damage_retention.csv|transformed_capture_replay.csv','Actual transformations, extraction, protocol checks and label-preservation review; file presence is insufficient.'),
 ('D','D1','Published baseline/label-use fidelity','DEVELOPMENT_REUSE_AND_FINAL_ADAPTERS','all_datasets_md3_results.csv|all_datasets_corrected_direct_target_summary.csv|baseline_fidelity_ledger.csv','Separate MD3 warning from label-assisted confirmation; bind each estimate to its actual target; name proxies honestly.'),
 ('E','E1','Existing hard-gate/adaptive/neural replay','DEVELOPMENT_REUSE','configuration_summary.csv|all_datasets_corrected_direct_target_summary.csv|neural_replay_status.csv','Reuse inspected feature-space development attacks and failures.'),
 ('E','E2','Adaptive final constrained monitor evaluation','REQUIRED_FINAL','final_adaptive_frontier.csv|final_hard_gate_query_results.csv|trace_adaptive_evaluation.csv','Evaluate the final approved action space and hard gate with fixed query budgets.'),
 ('F','F1','Locked NF same-parent boundary result','REUSE_SEALED_NEGATIVE','boundary_result.json|evaluation_receipt.json|primary_paired_family_errors.csv','Retain negative NF result; do not retune; it does not establish independent-corpus confirmation.'),
 ('F','F2','Independent boundary requirement','REQUIRED_OR_EXPLICIT_PLAN_AMENDMENT','independent_boundary_protocol.json|independent_boundary_results.csv','Audit exposure and physical/data dependencies; do not claim independent corpora from family panels.'),
 ('G','G1','Existing model-family/resource development','DEVELOPMENT_REUSE','resource_summary.csv|resource_audit.csv|resource_precision_summary.csv|model_family_summary.csv','Reuse existing banks/resources; deterministic duplicate predictions are not fresh independent units.'),
 ('G','G2','Final pipeline attribution/resource check','REQUIRED_IF_FINAL_IMPLEMENTATION_CHANGES','final_resource_audit.csv|final_channel_attribution.csv','Measure changed final pipeline only; source attribution requires verified channel truth; no unsupported energy claims.'),
 ('THEORY','T1','Generic output-only lemma','EXISTS_AWAITING_FINAL_PROOF_REVIEW','output_only_nonidentifiability_lemma.md|generic_nonidentifiability_lemma.md','Distinguish generic abstract worlds from IDS-specific attack attainability.'),
 ('THEORY','T2','IDS assumptions and weighted-integrity proposition','REQUIRED_FINAL','weighted_integrity_proposition.md|IDS_admissible_worlds_proof.md','Give precise observation/threat assumptions and probabilistic guarantee; no uniform accuracy certificate.'),
 ('STATS','S1','Final independent-unit inference','REQUIRED_FINAL','paired_conditional_bank_intervals.csv|primary_hypothesis_tests.csv|holm_primary_results.csv','Conditional bank intervals are not final source-domain confirmation; report clustered effect sizes and frozen correction family.'),
 ('PACKAGE','P1','Claim/version/reproduction closure','REQUIRED_FINAL','manuscript_claim_and_limitation_matrix.csv|protocol-confirmatory.yaml|baseline_fidelity_ledger.csv','Bind schemas, banks, threshold operators, profiles, code and each claim to a reproducible version.')]

index_by_name={}
for item in EVIDENCE:index_by_name.setdefault(item['name'].lower(),[]).append(item)
ledger=[];matches=[]
for group,task,requirement,category,candidates,rule in TASKS:
 hits=[]
 for name in candidates.split('|'):hits.extend(index_by_name.get(name.lower(),[]))
 unique={r['sha256']:r for r in hits}
 state='CANDIDATE_EVIDENCE_FOUND_REVIEW_CONTENT'
 if not hits:state='NO_MATCHING_ARTIFACT_NAME; REVIEW_INDEX_BEFORE_DECLARING_ABSENT'
 for r in unique.values():matches.append({'task':task,**r})
 ledger.append({'group':group,'task':task,'requirement':requirement,'plan_category':category,'audit_state':state,
  'distinct_candidate_contents':len(unique),'completion_gate':rule,'scientific_completion_auto_approved':False})

# Source contract: report exact values, never transfer definitions between datasets.
source_rows=[]
for h,name,t,partial in TABLES:
 if name=='source_contract_coverage.csv':
  for row in t.to_dict('records'):source_rows.append({'sha256':h,'table':name,**row})

# Find conflicting approvals/statuses for human review, preserving provenance.
contradictions=[]
for h,name,t,partial in TABLES:
 if 'view_membership_approved' in t and 'dataset' in t:
  for row in t.to_dict('records'):
   if truth(row.get('view_membership_approved')):contradictions.append({'sha256':h,'item':str(row.get('dataset')),'issue':'Structural view approval found; does not establish source semantics or that saved banks were trained with this schema.'})
 if 'confirmatory_test' in t:
  contradictions.append({'sha256':h,'item':name,'issue':'Confirmatory labels must be checked against protocol chronology and actual independent units; no automatic acceptance.'})

write_csv=lambda filename,rows,columns:pd.DataFrame(rows,columns=columns).to_csv(OUT/filename,index=False)
write_csv('filesystem_inventory.csv',FILES,['locator','bytes','suffix'])
write_csv('raw_asset_inventory.csv',ASSETS,['locator','bytes','kind','header_hex'])
write_csv('archive_scope.csv',ARCHIVES,['locator','kind','members','inspection'])
write_csv('evidence_index.csv',EVIDENCE,['locator','name','bytes','sha256'])
write_csv('decision_flags.csv',FLAGS,['evidence_sha256','key','value'])
pd.DataFrame(DIAGNOSTICS).to_csv(OUT/'table_content_diagnostics.csv',index=False)
pd.DataFrame(ledger).to_csv(OUT/'PLAN_TASK_LEDGER.csv',index=False)
write_csv('task_evidence_matches.csv',matches,['task','locator','name','bytes','sha256'])
pd.DataFrame(source_rows).to_csv(OUT/'recovered_source_contract_coverage.csv',index=False)
write_csv('interpretation_warnings.csv',contradictions,['sha256','item','issue'])
write_csv('audit_limits_and_errors.csv',ERRORS,['locator','issue'])

report='# Kaggle A–G plan closure: evidence audit\n\n'
report+='This is an evidence-content workbench, not scientific approval. Completed development must not be rerun blindly. Missing filename matches may indicate naming differences or uninspected containers.\n\n'
report+='## Relevant remaining gates\n\n'
for row in ledger:
 report+=f"- {row['task']} — {row['requirement']}: {row['audit_state']}. Gate: {row['completion_gate']}\n"
report+='\n## Content evidence\n\n'
for h,name,t,partial in TABLES:
 if any(re.search(p,name,re.I) for p in ['source_contract','coverage','A_to_G','remaining','reproduction_status','semantic_definition','validity','damage_retention','baseline_fidelity','holm','primary_hypothesis','primary_paired_family','resource_summary','resource_audit']):
  report+=f'\n### {name} / SHA256 {h}\n\n'+t.head(35).to_csv(index=False)+'\n'
for item in FLAGS:
 if re.search(r'confirm|valid|approved|independent|prospect|zeek|labels_config|packet|original_A_to_G|high_competence|mean_semantic|equal_family_mean_gain|precommitted',item['key'],re.I):
  report+=f"\n- {item['evidence_sha256']} / {item['key']}: {item['value']}"
report+='\n\n## Audit limits\n\n'+json.dumps(ERRORS,indent=2)
(OUT/'KAGGLE_PLAN_AUDIT.md').write_text(report,encoding='utf-8')

receipt={'output_directory':str(OUT),'active_development_base':str(ACTIVE/'development'),
 'reference_plan_sha256':digest(REFERENCE_PLAN.encode()),'filesystem_files_inventoried':len(FILES),
 'archive_indexes_inspected':len(ARCHIVES),'raw_assets_inventoried':len(ASSETS),
 'evidence_locators':len(EVIDENCE),'unique_evidence_contents_retained':len(seen),
 'metadata_bytes_retained':bytes_retained,'tables_content_inspected':len(TABLES),'decision_flags_extracted':len(FLAGS),
 'budget_exhausted':budget_exhausted,'audit_limit_or_error_records':len(ERRORS),
 'model_bundles_loaded':False,'models_trained':False,'predictions_computed':False,
 'attacks_rerun':False,'NF_settings_changed':False,'source_or_packet_validity_auto_approved':False,
 'scientific_completion_determined':False,'requires_review_of_actual_evidence':True,
 'note':'Do not rerun completed experiments. Review evidence and limits to select only the next missing plan-linked task.'}
(OUT/'AUDIT_RECEIPT.json').write_text(json.dumps(receipt,indent=2))

# Create one private review ZIP with actual retained evidence, not datasets/models.
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
if shutil.disk_usage(WORK).free < bytes_retained+128*1024**2:raise RuntimeError('Insufficient space for review ZIP; audit outputs remain saved.')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED,compresslevel=3,allowZip64=True) as z:
 for p in sorted(OUT.rglob('*')):
  if p.is_file():z.write(p,str(p.relative_to(OUT)))
with zipfile.ZipFile(package) as z:
 bad=z.testzip()
 if bad:raise RuntimeError('Review ZIP integrity failure: '+bad)
h=hashlib.sha256()
with package.open('rb') as f:
 for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
package.with_suffix('.zip.sha256').write_text(h.hexdigest()+'  '+package.name+'\n')
receipt.update({'private_review_zip':str(package),'review_zip_bytes':package.stat().st_size,'review_zip_CRC_verified':True,'review_zip_sha256':h.hexdigest()})
(OUT/'PACKAGE_RECEIPT.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print('\nPLAN TASK LEDGER — CANDIDATE ARTIFACTS ARE NOT AUTOMATIC APPROVAL')
print(pd.DataFrame(ledger)[['group','task','plan_category','distinct_candidate_contents','audit_state']].to_string(index=False))
print('\nCURRENT SOURCE-CONTRACT TABLES')
print(pd.DataFrame(source_rows).to_string(index=False) if source_rows else 'No matching coverage table; review the evidence index.')
print('\nRAW ASSETS BY KIND')
print(pd.DataFrame(ASSETS).groupby('kind').size().to_string() if ASSETS else 'No assets discovered in this audit scope; inspect unexamined archive limits before declaring absent.')
print('\nUPLOAD THE PRIVATE REVIEW ZIP FOR CONTENT-BASED TASK SIGN-OFF.')
