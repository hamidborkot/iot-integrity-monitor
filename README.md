# IoT Integrity Monitor

## Paper and purpose
From Flow Records to Original Connections: Extraction-Aware Auditing of Frozen IoT Intrusion Detectors.

This repository audits frozen intrusion detectors at the original-connection level. It separates flow-record predictions, packet attribution, admissible descendant alarms, reporting coverage, and unscored extractor controls. It does not claim a newly improved detector or independent expert packet-ownership ground truth.

## Main findings
- Historical49:512/512 malicious units detected clean;157/512 detected and355 with no admissible alarm at10s under validated descendant accounting. Selected-start scoring instead gives0/512 at10s.
- Fresh48 at10s: MG gives263 detected/249 unresolved; PW gives511 detected/1 unresolved. The model predictions do not change between these evidence rules. Attribution intervals are not sampling confidence intervals.
- Fresh benign-unit alarms:21/512 HGB and22/512 LR. Historical benign results retain one unresolved unit.
- Continuous MD3 condition warnings:3/24 harmful appearances in each hash ordering,3/12 in saved order; condition-only warnings identify none. Reused orderings/seeds are dependent appearances.
- Full-row and exact-pattern metrics use different weights: TONIoT AUROC0.764541 full-row versus0.886 pattern-weighted. Do not substitute one for the other.
- Timer controls:32 unscored runs. Paired Zeek/NFStream comparison:8 packet conditions,24 extractions. Counts are not detector-recall measurements.
- Capture35 is post-exposure reproduction. Period2 AUROC is undefined. The legacy count statistic is not a certified realized attack count.

## Paper CSVs
| Component | File under results/ |
|---|---|
| Tables I-II | paper/tables/table_1_related_work_tasks.csv; table_2_experimental_tracks.csv |
| Table III A/B | paper/tables/table_3a_malicious_unit_outcomes.csv; table_3b_benign_unit_outcomes.csv |
| Table IV | paper/tables/table_4_continuous_md3.csv |
| Figure2 | paper/figures/figure_2_pattern_balanced_operating_points.csv |
| Full-row comparison | paper/figures/five_dataset_full_row_operating_points.csv |
| Figure3 | paper/figures/figure_3_warning_counts_and_coverage.csv |
| Figure4 and S6 | paper/figures/figure_4_period_composition_and_auroc.csv; figure_4_temporal_window_summary.csv |
| S1 | supporting/S1_membership_diagnosis.csv |
| S2 | supporting/S2a_timer_configurations.csv; S2b_exported_record_counts.csv |
| S3 | supporting/paired_zeek_nfstream_record_counts.csv |
| S4a-c | supporting/S4_matched_MD3_all_48_summary_rows.csv |
| S5 | supporting/S5_legacy_warnings_and_coverage.csv |
| S7 | supporting/raw_only_pilot_detection_bounds.csv |
| S8 support | supporting/S8_clean_family_metrics.csv and supporting/nf_ton_iot_v2/ |

The existing results/supporting/Supplementary_Material_S1-S8.pdf and .tex are retained. Figure1 is conceptual artwork, not numerical data.

## Uploads and evidence status
See [the local upload map](docs/LOCAL_UPLOAD_MAP.md), [CSV semantics](docs/CSV_SEMANTICS.md), and [CSV inventory](artifacts/manifests/PAPER_CSV_INDEX.csv).

These CSVs export the supplied manuscript, consolidated register and printed outputs. All displayed rows for each named export are retained, at the supplied precision; they are not byte-original experimental CSVs. NA/blank is not zero. No experiments were rerun.

The downloadable preparation package additionally contains complete printed NF estimator-summary160 rows and target-window400 rows; those two detailed files are not in this direct CSV commit. Original per-unit rows, probabilities, packets, configurations and executable runners remain author uploads. This is not yet a turnkey independently reproduced release. Existing code licensing and third-party dataset redistribution terms remain distinct.
