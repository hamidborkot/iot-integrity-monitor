# What to upload, folder by folder

| Folder | Upload here | Do not put here |
|---|---|---|
| code/ | Maintained .py modules, CLI runners, plotting scripts, environment/export utilities | Every obsolete failed notebook cell |
| notebooks/ | Executed .ipynb and clean reproduction notebooks | Multi-GB embedded data dumps |
| configs/ | Exact saved .json/.yaml settings: model bank, predictor columns/order, source split, frozen cutoff/comparator, seeds, cohort IDs, observation horizons, extractor settings and package environment | Invented example settings presented as the executed configuration |
| results/paper/ | The manuscript-facing table CSVs and numerical figure inputs | Raw packet captures or backup ZIPs |
| results/supporting/ | Supplementary/supporting CSVs; the existing S1-S8 PDF/LaTeX may stay here | Unscoped mixtures of banks or populations |
| results/original/ | Small byte-original machine-generated CSV/JSON outputs, retaining original names and hashes | Reconstructed manuscript tables mislabeled as originals |
| docs/ | Reproduction instructions, installation notes, data-access instructions, schema explanations, assumptions and result interpretation | Duplicate datasets or all experiment code |
| manuscript/ | Final .tex, .bib, figure source/PDFs, compiled paper and submission-ready supplement | Experimental outputs renamed as a manuscript |
| artifacts/manifests/ | ZIP inventory, external access URLs, sizes, SHA-256 values, frozen receipts, cohort/model identities and paper mappings | The20+GB archive collection itself |
| artifacts/archives/ | README/index describing externally stored ZIPs and recovery procedure | Bulk backups committed to ordinary Git history |
| archive/ | Superseded development results, earlier scripts and failed/intermediate variants retained for provenance | Current canonical paper tables or an indiscriminate dump of all ZIPs |

## Your ZIP backups
Keep the original downloaded ZIPs intact in retained external storage. For each archive record the filename, byte size, SHA-256, access URL or documented restricted-access location, dataset license/access restrictions, and which experiments/files it contains. Do not infer that two backups are identical from their names. Never expose Kaggle/API tokens or personal information.

## Which original outputs are still needed
- Five-dataset96-row operating-point and42-row monitor originals and fixed probabilities/labels.
- Fresh48 55,296 per-unit rows; Historical49 18,432 per-unit rows, with their original schemas and identities.
- MD3 576 joined evaluation rows and its saved source/reference configuration; the48 displayed summaries are already exported.
- Capture35 M4_windows_REPRODUCTION.csv, M4_period_AUROC_REPRODUCTION.csv, verdict inputs and score provenance; summary exports do not recreate every window row.
- Exact file-order56-row stress results and200 conditional split details.
- Packet/cohort manifests, models and configurations required by the final reproduction runners.

These are upload/packaging tasks, not authorization to rerun completed experiments. The existing S1-S8 supplement is present under results/supporting/ and need not be uploaded again merely to change its folder.
