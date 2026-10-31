import ast
import hashlib
import json
from pathlib import Path
import joblib
import pandas as pd

ROOT = Path("/kaggle/working")
BASE = ROOT / "fresh_all_datasets_v1"
SOURCE_DIR = ROOT / "group_B_third_party_pcap2csv_mirror_audit_v1" / "source"
OUT = ROOT / "group_B_static_formula_dependency_audit_v1"
OUT.mkdir(parents=True, exist_ok=True)
BUNDLE_PATH = BASE / "CICIoT2023" / "CICIoT2023_bundle.joblib"
EXPECTED_BUNDLE = "29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88"
HASHES = {
    "Communication_features.py": "e9bc5ba242c6d7e0509eaaf82c71077818f908e4614e563d583b33ce304b9880",
    "Connectivity_features.py": "381a548a92246c9c295de99440ca46050e995a43808879eb91a64d569ba8ba60",
    "Dynamic_features.py": "e8fdeae9b5bb374979902ebfe12b926e8d1bb1cceca5da5a258f75f43c69b637",
    "Feature_extraction.py": "6452e125c56ba15a03f78e1295a5dedba7a76d5cbd6cb98c2c6469127c4e6586",
    "Generating_dataset.py": "be7ea67fd1d63f37c3643afbbfb96ec9d0b72afa751ef589c9055462c8524e9b",
    "Layered_features.py": "e60da2c632e7ffecfb949101517763c5986fd336691cb2cc1bb77784c8f60b3b",
    "Supporting_functions.py": "97e7b2e831bda60853810e01c3bca1e2f1aaa8f03acd89dd0276cc7619d0ea84",
    "allinone.py": "29cebd01e37b72e000fd6d88d4e8632bd7a0beb38ea607100df9da1dd6cbdb03",
    "attack_simulator.py": "ca21fac408d75de76925ee0786fd2feafee2fb21556aa563be35ea2062683302",
}
MUTABLE = {"Header_Length", "Tot sum", "Tot size", "Number", "Min", "Max", "AVG", "Std"}

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

def save(x, path):
    df = x.copy() if isinstance(x, pd.DataFrame) else pd.DataFrame(x)
    tmp = path.with_suffix(".tmp")
    df.to_csv(tmp, index=False)
    tmp.replace(path)

def norm(x):
    return "".join(c for c in str(x).lower() if c.isalnum())

def text(node):
    try:
        return ast.unparse(node)
    except Exception:
        return "<unparseable>"

def deps(node):
    result = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name):
            result.add(item.id)
        elif isinstance(item, ast.Attribute):
            result.add(text(item))
    return "|".join(sorted(result))

if digest(BUNDLE_PATH) != EXPECTED_BUNDLE:
    raise RuntimeError("Frozen CICIoT2023 bundle hash mismatch")
for name, expected in HASHES.items():
    path = SOURCE_DIR / name
    if not path.is_file():
        raise FileNotFoundError(path)
    if digest(path) != expected:
        raise RuntimeError("Mirror source hash mismatch: " + name)

bundle = joblib.load(BUNDLE_PATH)
features = list(bundle["primary_features"])
lookup = {norm(f): f for f in features}
formula_rows = []
manifest = []
source_texts = {}

class Visitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.stack = []
    def owner(self):
        return self.stack[-1] if self.stack else "<module>"
    def add(self, literal, value, kind, line):
        if not isinstance(literal, str) or norm(literal) not in lookup:
            return
        formula_rows.append({
            "frozen_feature": lookup[norm(literal)],
            "source_literal": literal,
            "source_file": self.filename,
            "enclosing_function": self.owner(),
            "assignment_kind": kind,
            "source_line": line,
            "expression": text(value),
            "expression_dependencies": deps(value),
            "third_party_static_only": True,
            "publisher_identity_verified": False,
            "packet_attack_approved": False,
        })
    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()
    def visit_AsyncFunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()
    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self.add(key.value, value, "dictionary_literal", getattr(value, "lineno", node.lineno))
        self.generic_visit(node)
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.add(target.id, node.value, "named_assignment", node.lineno)
            elif isinstance(target, ast.Subscript):
                if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                    self.add(target.slice.value, node.value, "subscript_assignment", node.lineno)
        self.generic_visit(node)

for filename in HASHES:
    path = SOURCE_DIR / filename
    source = path.read_text(encoding="utf-8", errors="replace")
    source_texts[filename] = source
    tree = ast.parse(source, filename=filename)
    imports, functions = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imports += [(node.module or "") + "." + a.name for a in node.names]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
    manifest.append({
        "source_file": filename,
        "source_sha256": digest(path),
        "bytes": path.stat().st_size,
        "ast_parse_passed": True,
        "source_role": "EXCLUDED_ATTACK_SIMULATOR" if filename == "attack_simulator.py" else "THIRD_PARTY_EXTRACTOR_MIRROR",
        "imports": "|".join(sorted(set(imports))),
        "functions": "|".join(sorted(set(functions))),
        "executed": False,
    })
    if filename != "attack_simulator.py":
        Visitor(filename).visit(tree)

formulae = pd.DataFrame(formula_rows)
if formulae.empty:
    formulae = pd.DataFrame(columns=["frozen_feature", "source_literal", "source_file", "enclosing_function", "assignment_kind", "source_line", "expression", "expression_dependencies"])
save(manifest, OUT / "source_static_manifest.csv")
save(formulae, OUT / "all_static_formula_candidates.csv")

summary, contexts = [], []
for feature in features:
    matches = formulae[formulae["frozen_feature"].eq(feature)]
    summary.append({
        "frozen_feature": feature,
        "historically_mutable": feature in MUTABLE,
        "static_formula_candidates": len(matches),
        "source_files": "|".join(sorted(matches["source_file"].dropna().unique())),
        "functions": "|".join(sorted(matches["enclosing_function"].dropna().unique())),
        "expressions": " || ".join(sorted(matches["expression"].dropna().unique())),
        "static_formula_status": "STATIC_CANDIDATE_FOUND" if len(matches) else "NO_DIRECT_STATIC_ASSIGNMENT_FOUND",
        "direct_csv_edit_approved": False,
        "packet_valid_attack_approved": False,
    })
    for _, row in matches.iterrows():
        lines = source_texts[row["source_file"]].splitlines()
        line = int(row["source_line"])
        start, end = max(1, line - 5), min(len(lines), line + 5)
        contexts.append({
            "frozen_feature": feature,
            "source_file": row["source_file"],
            "enclosing_function": row["enclosing_function"],
            "assignment_kind": row["assignment_kind"],
            "source_line": line,
            "expression": row["expression"],
            "source_context": "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1)),
            "static_context_only": True,
        })
summary = pd.DataFrame(summary)
contexts = pd.DataFrame(contexts)
save(summary, OUT / "frozen_feature_static_formula_summary.csv")
save(contexts, OUT / "static_source_context.csv")
mutable = summary[summary["historically_mutable"]].copy()
mutable["required_next_evidence"] = "Authorized PCAP + extractor identity + clean re-extraction + trace-to-CSV mapping"
mutable["direct_csv_edit_approved"] = False
mutable["packet_valid_attack_approved"] = False
save(mutable, OUT / "historical_mutable_formula_contract.csv")

status = {
    "dataset": "CICIoT2023",
    "frozen_predictors": len(features),
    "predictors_with_static_formula_candidates": int(summary["static_formula_candidates"].gt(0).sum()),
    "historical_mutable_predictors": len(MUTABLE),
    "historical_mutable_with_static_formula_candidates": int(mutable["static_formula_candidates"].gt(0).sum()),
    "third_party_mirror_commit": "bf4ab0debcad530a941172f3fea6899859cc6896",
    "source_code_executed": False,
    "publisher_extractor_identity_verified": False,
    "capture_to_csv_mapping_verified": False,
    "clean_reextraction_verified": False,
    "group_B_static_formula_audit": "COMPLETE_FOR_CURRENT_FEATURE_SPACE_SCOPE",
    "group_C_packet_valid_attack_status": "NOT_AVAILABLE_WITH_CURRENT_INPUTS",
}
(OUT / "group_B_static_formula_status.json").write_text(json.dumps(status, indent=2))
print(json.dumps(status, indent=2))
print("\nHISTORICAL MUTABLE FEATURES")
print(mutable[["frozen_feature", "static_formula_candidates", "source_files", "functions", "static_formula_status"]].to_string(index=False))
print("\nFILES WRITTEN")
for item in sorted(OUT.iterdir()):
    if item.is_file():
        print("-", item.name)
