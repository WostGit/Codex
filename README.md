# Reproducible Vulnerability Benchmark Pipeline

This repository provides a restart-safe Python pipeline to build a unified vulnerability benchmark from exactly these four sources:

1. OSV
2. purl2cpe
3. inthewilddb
4. MoreFixes (optional)

## What the pipeline writes

Running `build_benchmark.py` creates:

- `benchmark_workspace/outputs/benchmark.csv`
- `benchmark_workspace/outputs/source_coverage.csv`
- `benchmark_workspace/outputs/join_diagnostics.csv`
- `benchmark_workspace/outputs/README.md` (build report + source audit trail)

## Quick start

```bash
python3 -m pip install pandas tabulate
python3 build_benchmark.py --workdir benchmark_workspace --verbose \
  --osv-zip /path/to/osv_all.zip \
  --purl2cpe /path/to/purl2cpe_mapping.csv \
  --inthewild /path/to/inthewilddb_export.csv \
  --morefixes /path/to/morefixes_export.csv
```

`--morefixes` is optional.

## Source handling and trust model

The script keeps an audit trail of source URLs and connectivity checks. It is intentionally conservative:

- It only references the trusted project-owned URLs configured in script constants.
- It does not scrape arbitrary websites.
- If downloads are blocked or impractical, it requires manual file placement in `benchmark_workspace/manual_inputs/` and clearly reports what is missing.

## Supported local input formats

- **OSV**: ZIP file of JSON records (e.g., `all.zip`)
- **purl2cpe**: CSV / TSV / JSON / SQLite with columns for purl and cpe
- **inthewilddb**: CSV / JSON with a CVE column
- **MoreFixes**: CSV / JSON with a CVE column and optional fix/patch reference

## Join logic

- OSV → purl2cpe via exact `purl`
- CVE → inthewilddb via normalized CVE ID
- CVE → MoreFixes via normalized CVE ID

Diagnostics include row counts, distinct CVE counts, join rates, and top purl join failure modes.
