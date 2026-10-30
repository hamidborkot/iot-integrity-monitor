# Paper artifact upload guide

Paper: From Flow Records to Original Connections: Extraction-Aware Auditing of Frozen IoT Intrusion Detectors.

This adds an upload structure without replacing existing files.

- code/: maintained Python modules and entry points.
- configs/: frozen model, cohort, schema, cutoff, extractor and environment configurations.
- notebooks/: executed and clean reproduction notebooks.
- results/paper/tables/: manuscript-facing CSV tables.
- results/paper/figures/: numerical figure inputs; Figure 1 is conceptual artwork.
- results/supporting/: scoped supporting tables.
- results/original/: small original machine-generated CSV/JSON files.
- manuscript/: final LaTeX, bibliography, artwork and PDF.
- manuscript/supplementary/: final supplement and S1-S8 mapping.
- artifacts/manifests/: provenance, checksums, archive inventories and access links.
- artifacts/archives/: bulk-archive location documentation, not Git-tracked backup ZIPs.

The prepared CSV package contains manuscript, consolidated-register and printed-output transcriptions, not original experimental CSV bytes or new experiments. Preserve the provenance manifest and explicit upload gaps. Do not claim independent validation from an upload receipt.

Do not commit 20+ GB of Kaggle archives to regular Git history. Retain them in an appropriate external archive and record links, bytes, SHA-256 values and access/redistribution conditions. GitHub blocks regular-Git files above 100 MiB and browser uploads above 25 MiB. Check current release-asset or LFS limits separately.

Review notebooks, JSON, scripts and logs for credentials, personal information and redistribution restrictions. The code license does not automatically license third-party datasets. No large archives or result CSVs are uploaded by this organization commit.

GitHub large-file documentation: https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github
