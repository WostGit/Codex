# Benchmark Data Pipeline (OSV + purl2cpe + inthewilddb)

This repository provides a reproducible Python pipeline that downloads, normalizes, and joins vulnerability intelligence from:

1. OSV
2. purl2cpe
3. inthewilddb
4. MoreFixes (optional/manual import)

The pipeline is designed to run in GitHub Actions (`ubuntu-latest`) and publish CSV artifacts.

## Repository layout

- `scripts/download_and_build_benchmark.py`: end-to-end pipeline.
- `requirements.txt`: Python dependencies.
- `.github/workflows/build-benchmark.yml`: CI workflow.
- `data/raw/`: cached downloaded source artifacts.
- `benchmark.csv`: joined benchmark dataset (generated).
- `source_coverage.csv`: row and CVE coverage by source (generated).
- `join_diagnostics.csv`: join percentages, unmatched diagnostics, and skip reasons (generated).

## Data source policy

The script only downloads from a small allowlist of HTTPS URLs (project-owned sources):

- OSV dump (official):
  - `https://osv-vulnerabilities.storage.googleapis.com/all.zip`
  - `https://osv-vulnerabilities.storage.googleapis.com/OSV-all.zip` (legacy fallback)
  - `https://github.com/google/osv-vulnerabilities/archive/refs/heads/main.zip` (repository fallback)
- purl2cpe (project repo candidates):
  - `https://raw.githubusercontent.com/package-url/purl2cpe/main/data/purl2cpe.csv`
  - `https://raw.githubusercontent.com/package-url/purl2cpe/main/data/purl2cpe.json`
  - `https://raw.githubusercontent.com/package-url/purl2cpe/main/purl2cpe.csv`
  - `https://raw.githubusercontent.com/package-url/purl2cpe/main/purl2cpe.json`
- inthewilddb (project repo candidates):
  - `https://raw.githubusercontent.com/inthewilddb/IntheWildDB/main/data/inthewilddb.csv`
  - `https://raw.githubusercontent.com/inthewilddb/IntheWildDB/main/inthewilddb.csv`
  - `https://raw.githubusercontent.com/inthewilddb/IntheWildDB/main/data/export/inthewilddb.csv`

If all candidates for a required source fail, the script exits nonzero with a clear error.

## MoreFixes handling

MoreFixes can be too large/impractical for default CI runtime and bandwidth. Therefore:

- CI default: skip automatic MoreFixes ingestion.
- Skip decision is recorded in `join_diagnostics.csv` as `morefixes_status`.
- Manual import path is supported via `--morefixes-path` or `MOREFIXES_PATH`.

Expected manual CSV requirement: a column containing CVE IDs (any column name containing `cve`).

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/download_and_build_benchmark.py
```

Optional arguments:

- `--ci-mode`: enforce CI behavior (skip MoreFixes unless explicit path provided).
- `--osv-max-records N`: parse only first `N` OSV advisories (0 = full).
- `--morefixes-path /path/to/morefixes.csv`: include manual MoreFixes source.

## Join logic and output schema

Join flow:

1. Normalize OSV into CVE/package/purl rows.
2. Join OSV to purl2cpe by `purl`.
3. Join CVE-linked rows to inthewilddb by `cve_id`.
4. Join optional MoreFixes by `cve_id`.

`benchmark.csv` includes fields (when available):

- `cve_id`
- `osv_id`
- `published`
- `modified`
- `ecosystem`
- `package_name`
- `purl`
- `cpe`
- `in_the_wild`
- `morefixes_present`
- source flags: `has_osv`, `has_purl2cpe`, `has_inthewilddb`, `has_morefixes`

`source_coverage.csv` includes:

- source row counts
- unique CVE counts (where meaningful)

`join_diagnostics.csv` includes:

- source URL used
- join coverage percentages
- top unmatched purls/CVEs
- skip reasons (including MoreFixes in CI)

## GitHub Actions

Workflow: `.github/workflows/build-benchmark.yml`

On each run:

1. Checks out code.
2. Sets up Python 3.11.
3. Installs dependencies from `requirements.txt`.
4. Runs `python scripts/download_and_build_benchmark.py --ci-mode`.
5. Uploads `benchmark.csv`, `source_coverage.csv`, and `join_diagnostics.csv` as artifact `benchmark-artifacts`.

### Running from GitHub Actions UI

1. Open **Actions** tab.
2. Select **Build benchmark** workflow.
3. Click **Run workflow** (workflow_dispatch trigger).

