import os, sys, json, csv, re, time, shutil, zipfile, struct, hashlib
from pathlib import Path
from datetime import datetime, timezone
from importlib import metadata

RAW = {
    "CICIoMT2024": "/kaggle/input/datasets/amineipad/cic-iomt-dataset-2024",
    "CICIoT2023": "/kaggle/input/datasets/himadri07/ciciot2023",
    "IoT_named_corpus_VERIFY_IDENTITY": "/kaggle/input/datasets/sonalimishra3/iot-2023-dataset-full",
    "TONIoT": "/kaggle/input/datasets/fadiabuzwayed/ton-iot-train-test-network",
    "NFToNIoTv2": "/kaggle/input/datasets/dhoogla/nftoniotv2",
    "CSE": "/kaggle/input/datasets/dhoogla/csecicids2018",
    "NSL": "/kaggle/input/datasets/shamstahzib/nsl-kdd-dataset",
}
BACKUPS = {name: "/kaggle/input/datasets/mdhamidborkottulla/" + name for name in (
    "all-kaggle-work", "complete-backup", "full-backup", "last-day-backup",
    "one-last", "ran-files", "the-last-update", "whole-in-one", "the-last-days-backup")}
SUPPORT = {name: "/kaggle/input/datasets/mdhamidborkottulla/" + name for name in (
    "pcaps-of-ciciot-23-and-24", "research-closing-code",
    "research-experiment-suite", "githubnids")}
ROOTS = {**RAW, **BACKUPS, **SUPPORT}
MAX_FILES = 150000
MAX_SECONDS = 180
MAX_ZIPS = 32
MAX_MEMBERS_PER_ZIP = 100000
MAX_TOTAL_MEMBERS = 400000
MAX_CENTRAL_BYTES = 32 * 1024**2
MAX_RECEIPTS = 80
MAX_RECEIPT_BYTES = 256 * 1024

RULES = {
    "TRACE_SOURCE_MODELS": r"frozen_source_models\.joblib$",
    "TABULAR_BUNDLE": r"(?:CICIoT2023|CICIoMT2024|CSE|NSL|TONIoT)_bundle\.joblib$",
    "VIEW_BANK": r"(?:aligned_)?view_bank\.joblib$",
    "SOURCE_REFERENCE": r"source_reference_sample\.csv(?:\.gz)?$",
    "SOURCE_PREDICTIONS": r"source_reference_frozen_outputs\.npz$",
    "SOURCE_CALIBRATION": r"(?:source_seed_calibration_statistics\.csv|calibration_contract\.json)$",
    "FULL4_RAW_RESULTS": r"results_(?:main|blind)_full4_seed.*\.csv$",
    "TABULAR_ATTACK_OFFSETS": r"spsa.*\.npz$",
    "COMPACT_TRACE_FEATURES": r"(?:attacked_selected_features|candidate_selected_features|frozen_clean_target_sample)\.csv(?:\.gz)?$",
    "TRACE_PREDICTIONS": r"(?:primary_outputs|.*clean_outputs|.*window_outputs)\.npz$",
    "PAIRED_WINDOW_RESULTS": r"(?:paired_window_results|matched_coverage_window_results)\.csv$",
    "SOURCE_SPLIT_RECORDS": r"(?:.*split.*manifest|source_data_manifest)\.csv$",
    "PROTOCOL_OR_EXPOSURE": r"(?:.*protocol.*|.*exposure.*|.*roster.*|.*target.*manifest.*)\.(?:json|yaml|yml|csv|md)$",
    "NF_BOUNDARY": r"(?:boundary_result\.json|NF_target_panels\.joblib|NF_calibrated_source_bundle\.joblib)$",
    "SOURCE_CODE": r"\.(?:py|ipynb)$",
    "RECEIPT_OR_MANIFEST": r"(?:.*receipt.*|.*manifest.*)\.json$",
    "PCAP": r"\.(?:pcap|pcapng)(?:\.gz)?$",
    "ZEEK_CONNECTION_LOG": r"conn\.log(?:\.labeled|\.gz|\.labeled\.gz)?$",
}
RULES = {k: re.compile(v, re.I) for k, v in RULES.items()}
SAFE_FIELDS = {
    "status", "version", "scope", "receipt_kind", "runkind", "run_kind",
    "models_retrained", "models_trained", "deployed_models_retrained",
    "target_predictions_computed", "target_outcomes_inspected", "target_outcomes_now_inspected",
    "blind_target_rows_read", "target_pcap_or_log_opened", "independent_confirmation",
    "independent_confirmation_performed", "independent_confirmation_completed",
    "prospective_confirmation", "post_exposure_analysis", "post_exposure_definition",
    "reference_training_disjointness_verified", "original_files_overwritten",
    "PCAP_replays", "Zeek_rerun", "NF_records_inspected", "NF_changed",
    "packet_validity_established", "TCP_semantic_validity_certified",
    "application_functionality_tested", "source_group_independence_status",
    "scientific_completion_inferred", "all_study_requirements_complete",
}

def csv_write(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

def categories(name):
    return [k for k, p in RULES.items() if p.search(Path(name).name)]

def ram_info():
    vals = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            if k in ("MemTotal", "MemAvailable"):
                vals[k + "_GiB"] = round(int(v.split()[0]) / 1024**2, 3)
    except Exception as e:
        vals["error"] = str(e)
    return vals

def central_directory_size(path):
    size = path.stat().st_size
    with path.open("rb") as f:
        f.seek(max(0, size - 65557)); tail = f.read(65557)
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or pos + 22 > len(tail):
        raise ValueError("EOCD not found; archive inspection deferred")
    fields = struct.unpack_from("<4s4H2LH", tail, pos)
    if pos + 22 + fields[-1] != len(tail):
        raise ValueError("EOCD/comment layout unresolved")
    if fields[1] != 0 or fields[2] != 0:
        raise ValueError("Multi-disk ZIP deferred")
    if fields[4] == 65535 or fields[5] == 0xffffffff or fields[6] == 0xffffffff:
        raise ValueError("ZIP64 metadata inspection deferred")
    return fields[5]

def main():
    start = time.monotonic()
    work = Path("/kaggle/working")
    if not work.is_dir():
        raise RuntimeError("Run this cell in Kaggle; /kaggle/working is absent")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = work / ("CLOSING_E0A_INVENTORY_" + run_id)
    out.mkdir(exist_ok=False)
    env = {"python": sys.version, "platform": sys.platform, "cpu_count": os.cpu_count(),
           "ram": ram_info(), "disk": {k + "_GiB": round(v / 1024**3, 3)
           for k, v in zip(("total", "used", "free"), shutil.disk_usage(work))}}
    env["packages"] = {}
    for pkg in ("numpy", "pandas", "scipy", "scikit-learn", "joblib", "torch", "menelaus", "pyarrow", "psutil"):
        try: env["packages"][pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError: env["packages"][pkg] = None
    env["zeek_candidates"] = list(dict.fromkeys(str(p) for p in (
        Path("/opt/zeek/bin/zeek"), Path("/usr/bin/zeek"),
        Path(shutil.which("zeek") or "/nonexistent_zeek")) if p.is_file()))
    root_rows, file_rows, artifact_rows, archives, archive_rows, receipt_rows, errors = [], [], [], [], [], [], []
    receipt_candidates = []
    stopped = False
    for label, root_text in ROOTS.items():
        root = Path(root_text)
        row = {"root_label": label, "group": "raw" if label in RAW else "backup" if label in BACKUPS else "support",
               "path": root_text, "exists": root.is_dir(), "files_seen": 0, "bytes_seen": 0, "scan_complete": False}
        root_rows.append(row)
        if not row["exists"]: continue
        if stopped: continue
        def walk_error(e):
            errors.append({"stage": "walk", "path": str(getattr(e, "filename", root)), "error": str(e)})
        try:
            for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
                dirs.sort(); files.sort()
                for filename in files:
                    if len(file_rows) >= MAX_FILES or time.monotonic() - start > MAX_SECONDS:
                        stopped = True; break
                    path = Path(directory) / filename
                    try:
                        st = path.stat()
                        if not path.is_file(): continue
                        item = {"root_label": label, "path": str(path), "relative_path": str(path.relative_to(root)),
                                "bytes": st.st_size, "suffix": path.suffix.lower(), "is_symlink": path.is_symlink()}
                        file_rows.append(item); row["files_seen"] += 1; row["bytes_seen"] += st.st_size
                        for cat in categories(filename):
                            artifact_rows.append({"category": cat, "root_label": label, "container": "",
                                "location": str(path), "bytes": st.st_size, "source": "direct_file"})
                        lower = filename.lower()
                        if lower.endswith(".zip"):
                            archives.append((label, path))
                        elif lower.endswith((".tar", ".tar.gz", ".tgz", ".7z")):
                            archive_rows.append({"root_label": label, "path": str(path), "status": "DEFERRED_NON_ZIP",
                                                 "members": None, "reason": "No extraction/decompression in E0-A"})
                        if label not in RAW and st.st_size <= MAX_RECEIPT_BYTES and re.search(r"receipt.*\.json$", filename, re.I):
                            receipt_candidates.append((label, path))
                    except Exception as e:
                        errors.append({"stage": "stat", "path": str(path), "error": str(e)})
                if stopped: break
            row["scan_complete"] = not stopped
        except Exception as e:
            errors.append({"stage": "root", "path": root_text, "error": str(e)})
        print(f"SCANNED {label}: exists={row['exists']} files={row['files_seen']} complete={row['scan_complete']}", flush=True)
    total_members = 0
    for index, (label, path) in enumerate(archives):
        entry = {"root_label": label, "path": str(path), "status": "DEFERRED_LIMIT", "members": None, "reason": "Inspection budget"}
        if index < MAX_ZIPS and total_members < MAX_TOTAL_MEMBERS and time.monotonic() - start <= MAX_SECONDS:
            try:
                central_bytes = central_directory_size(path)
                if central_bytes > MAX_CENTRAL_BYTES:
                    raise ValueError(f"Central directory {central_bytes} exceeds bounded metadata budget")
                with zipfile.ZipFile(path) as z:
                    infos = z.infolist(); entry["members"] = len(infos)
                    limit = min(len(infos), MAX_MEMBERS_PER_ZIP, MAX_TOTAL_MEMBERS - total_members)
                    inspected = 0
                    for info in infos[:limit]:
                        if time.monotonic() - start > MAX_SECONDS: break
                        inspected += 1
                        if info.is_dir(): continue
                        for cat in categories(info.filename):
                            artifact_rows.append({"category": cat, "root_label": label, "container": str(path),
                                "location": info.filename, "bytes": info.file_size, "source": "zip_member_index_only"})
                    total_members += inspected
                    entry["status"] = "INDEXED" if inspected == len(infos) else "PARTIAL_INDEX"
                    entry["reason"] = f"Inspected {inspected}; no members extracted; CRC not verified"
            except Exception as e:
                entry["status"] = "DEFERRED_OR_UNREADABLE"; entry["reason"] = str(e)
        archive_rows.append(entry)
    for label, path in receipt_candidates[:MAX_RECEIPTS]:
        if time.monotonic() - start > MAX_SECONDS: break
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_RECEIPT_BYTES: continue
            obj = json.loads(raw)
            fields = {k: obj[k] for k in SAFE_FIELDS if isinstance(obj, dict) and k in obj}
            receipt_rows.append({"root_label": label, "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                                 "safe_scope_flags": json.dumps(fields, sort_keys=True, default=str)})
        except Exception as e:
            errors.append({"stage": "receipt", "path": str(path), "error": str(e)})
    csv_write(out / "roots.csv", root_rows, ["root_label", "group", "path", "exists", "files_seen", "bytes_seen", "scan_complete"])
    csv_write(out / "file_inventory.csv", file_rows, ["root_label", "path", "relative_path", "bytes", "suffix", "is_symlink"])
    csv_write(out / "artifact_candidates.csv", artifact_rows, ["category", "root_label", "container", "location", "bytes", "source"])
    csv_write(out / "archives.csv", archive_rows, ["root_label", "path", "status", "members", "reason"])
    csv_write(out / "receipt_scope_flags.csv", receipt_rows, ["root_label", "path", "sha256", "safe_scope_flags"])
    csv_write(out / "errors.csv", errors, ["stage", "path", "error"])
    counts = {cat: sum(r["category"] == cat for r in artifact_rows) for cat in RULES}
    receipt = {
        "stage": "E0-A", "status": "BOUNDED_INVENTORY_RECORDED",
        "output_directory": str(out), "elapsed_seconds": round(time.monotonic() - start, 2),
        "roots_requested": len(ROOTS), "roots_present": sum(r["exists"] for r in root_rows),
        "missing_roots": [r["path"] for r in root_rows if not r["exists"]],
        "uncompleted_root_scans": [r["root_label"] for r in root_rows if r["exists"] and not r["scan_complete"]],
        "direct_files_indexed": len(file_rows), "zip_members_indexed": total_members,
        "archive_status_counts": {status: sum(r["status"] == status for r in archive_rows) for status in sorted({r["status"] for r in archive_rows})},
        "scope_receipts_read": len(receipt_rows), "explicit_errors": len(errors), "artifact_category_counts": counts,
        "limits": {"seconds": MAX_SECONDS, "files": MAX_FILES, "zips": MAX_ZIPS, "total_zip_members": MAX_TOTAL_MEMBERS},
        "input_files_modified": False, "archives_extracted": False, "models_loaded": False,
        "models_trained": False, "target_predictions_computed": False,
        "tabular_or_pcap_record_contents_read": False, "receipt_metadata_only_read": True,
        "installed_packages_changed": False, "zeek_executed": False, "files_deleted": False,
        "artifact_validity_verified": False, "scientific_experiments_completed": [],
        "next_step": "Review inventory; resolve artifact versions before minimal preparation E0-B/C"
    }
    (out / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    (out / "inventory_receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print("\n=== E0-A ENVIRONMENT ===\n" + json.dumps(env, indent=2))
    print("\n=== E0-A RECEIPT ===\n" + json.dumps(receipt, indent=2))
    print("\n=== CRITICAL CANDIDATES (up to 3 per category; paths are not acceptance) ===")
    critical = [k for k in RULES if k not in ("SOURCE_CODE", "RECEIPT_OR_MANIFEST", "PCAP", "ZEEK_CONNECTION_LOG", "PROTOCOL_OR_EXPOSURE")]
    for cat in critical:
        candidates = [r for r in artifact_rows if r["category"] == cat]
        print(cat + ": " + str(len(candidates)))
        for r in candidates[:3]:
            print("  " + (r["container"] + " :: " if r["container"] else "") + r["location"])
    print("\n=== INVENTORY ERRORS (up to 10) ===")
    for e in errors[:10]: print(json.dumps(e))
    if not errors: print("None recorded")
    print("\nE0-A recorded. This is metadata discovery, not artifact validation or experiment completion.")
    return str(out)

E0A_OUTPUT_DIRECTORY = main()
