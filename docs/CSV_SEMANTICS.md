# CSV semantics and reproducibility scope

## Export types
Manuscript tables preserve reported rows and rounding. Register exports preserve a secondary reported summary. Printed NF exports retain all displayed rows for their named tables but do not reproduce original CSV bytes or establish independent validation.

## Columns and units
- detected/no_admissible_alarm/unresolved are mutually exclusive original-unit outcomes. Include unresolved units in N; do not impute a prediction.
- lower_percent/upper_percent use0-100 percentage units in TableIII exports. Rates in other source tables are fractions unless explicitly labeled percent.
- TableIV sensitivity_percent and control_FP_percent are percentages. FP fraction is FP/(FP+TN), not FP/TN.
- Coverage is a fraction in S4/S5 and explicitly a percentage in the Figure3 and TableIV exports.
- S4 CF is continuous first-request MD3; WR is the reset diagnostic. Delay10s is harmful;0/1/3s are no-damage controls, not benign-only populations.
- Blank or NA outcomes have a zero denominator or are non-evaluable; neither means zero performance.
- Raw0.5 accuracy, Source5 recall/FPR, full-row weighting and pattern-balanced weighting are distinct estimands.
- Controls in S5 use72/72/36 appearances, as in the uploaded supplement. Older pooled120-control register summaries are not substituted for these per-order denominators.
- Source6-decimal or3-decimal rounding is not hidden full precision. The text '0.000 rounded' in the pattern table means reported rounding, not evidence of a mathematically exact zero.
- NF family-transfer errors and semantic views are from same-parent tabular reports. They are not Zeek/NFStream cross-extractor attack recall.
- S6 aggregate pass counts are empirical checks, not proven sampling assumptions or finite-window attack-count guarantees.

## Reproduction boundary
The dataset uploads, exact configurations and final runner code are supplied separately by the author. This update creates readable CSV exports and documentation only. No detector is trained, no threshold is selected, no capture is transformed or rescored, and no completed experiment is rerun.
