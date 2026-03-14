#!/usr/bin/env python3
"""Download and build a benchmark table from OSV, purl2cpe, inthewilddb, and optional MoreFixes."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

import pandas as pd

ALLOWED_URLS = {
    "osv": [
        "https://osv-vulnerabilities.storage.googleapis.com/all.zip",
        "https://osv-vulnerabilities.storage.googleapis.com/OSV-all.zip",
        "https://github.com/google/osv-vulnerabilities/archive/refs/heads/main.zip",
    ],
    "purl2cpe": [
        "https://raw.githubusercontent.com/package-url/purl2cpe/main/data/purl2cpe.csv",
        "https://raw.githubusercontent.com/package-url/purl2cpe/main/data/purl2cpe.json",
        "https://raw.githubusercontent.com/package-url/purl2cpe/main/purl2cpe.csv",
        "https://raw.githubusercontent.com/package-url/purl2cpe/main/purl2cpe.json",
        "https://raw.githubusercontent.com/package-url/purl2cpe/master/data/purl2cpe.csv",
        "https://raw.githubusercontent.com/package-url/purl2cpe/master/data/purl2cpe.json",
        "https://raw.githubusercontent.com/package-url/purl2cpe/master/purl2cpe.csv",
        "https://raw.githubusercontent.com/package-url/purl2cpe/master/purl2cpe.json",
    ],
    "inthewilddb": [
        "https://raw.githubusercontent.com/inthewilddb/IntheWildDB/main/data/inthewilddb.csv",
        "https://raw.githubusercontent.com/inthewilddb/IntheWildDB/main/inthewilddb.csv",
        "https://raw.githubusercontent.com/inthewilddb/IntheWildDB/main/data/export/inthewilddb.csv",
    ],
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", default="data", help="Working directory for raw/cache files.")
    parser.add_argument(
        "--osv-max-records",
        type=int,
        default=int(os.getenv("OSV_MAX_RECORDS", "0")),
        help="Optional cap on parsed OSV advisories (0 = no cap).",
    )
    parser.add_argument(
        "--morefixes-path",
        default=os.getenv("MOREFIXES_PATH", ""),
        help="Optional local MoreFixes CSV path (manual import).",
    )
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        default=os.getenv("CI", "").lower() == "true",
        help="CI mode: skips MoreFixes automatic ingestion and expects external URLs only.",
    )
    return parser.parse_args()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def download_with_cache(urls: Iterable[str], dst: Path, force: bool = False) -> str:
    if dst.exists() and not force:
        logging.info("Using cached file: %s", dst)
        return "cached"

    ensure_dir(dst.parent)
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"https"}:
            raise RuntimeError(f"Blocked non-HTTPS URL: {url}")
        logging.info("Downloading %s -> %s", url, dst)
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, dst.open("wb") as out:
                shutil.copyfileobj(resp, out)
            return url
        except Exception as exc:  # noqa: BLE001
            logging.warning("Failed download from %s: %s", url, exc)

    raise RuntimeError(f"Unable to download required artifact to {dst} from any allowed URL")


def load_osv_table(zip_path: Path, max_records: int) -> pd.DataFrame:
    rows: list[dict] = []
    parsed = 0

    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            if not member.endswith(".json"):
                continue
            with zf.open(member) as fp:
                advisory = json.load(fp)
            parsed += 1

            osv_id = advisory.get("id")
            published = advisory.get("published")
            modified = advisory.get("modified")
            aliases = advisory.get("aliases") or []
            cves = sorted({a.upper() for a in aliases if isinstance(a, str) and a.upper().startswith("CVE-")})
            cve_id = cves[0] if cves else None

            affected = advisory.get("affected") or []
            if not affected:
                rows.append(
                    {
                        "cve_id": cve_id,
                        "osv_id": osv_id,
                        "published": published,
                        "modified": modified,
                        "ecosystem": None,
                        "package_name": None,
                        "purl": None,
                    }
                )
            else:
                for aff in affected:
                    pkg = aff.get("package") or {}
                    rows.append(
                        {
                            "cve_id": cve_id,
                            "osv_id": osv_id,
                            "published": published,
                            "modified": modified,
                            "ecosystem": pkg.get("ecosystem"),
                            "package_name": pkg.get("name"),
                            "purl": pkg.get("purl"),
                        }
                    )

            if max_records > 0 and parsed >= max_records:
                logging.info("Reached OSV parse cap (%d records)", max_records)
                break

    df = pd.DataFrame(rows)
    if df.empty:
        raise RuntimeError("OSV parsing produced zero rows")
    df["cve_id"] = df["cve_id"].str.upper()
    return df


def read_tabular(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in {".json", ".jsonl"}:
        with path.open() as fp:
            payload = json.load(fp)
        if isinstance(payload, list):
            return pd.DataFrame(payload)
        if isinstance(payload, dict):
            if "data" in payload and isinstance(payload["data"], list):
                return pd.DataFrame(payload["data"])
            return pd.json_normalize(payload)
    raise RuntimeError(f"Unsupported file format: {path}")


def normalize_purl2cpe(df: pd.DataFrame) -> pd.DataFrame:
    lowered = {c.lower(): c for c in df.columns}
    purl_col = next((lowered[k] for k in lowered if "purl" in k), None)
    cpe_col = next((lowered[k] for k in lowered if "cpe" in k), None)
    if purl_col is None or cpe_col is None:
        raise RuntimeError(f"Could not infer purl/cpe columns from purl2cpe columns: {list(df.columns)}")

    out = df[[purl_col, cpe_col]].copy()
    out.columns = ["purl", "cpe"]
    out = out.dropna(subset=["purl"]).drop_duplicates()
    return out


def normalize_inthewild(df: pd.DataFrame) -> pd.DataFrame:
    cve_col = None
    for col in df.columns:
        if "cve" in col.lower():
            cve_col = col
            break
    if cve_col is None:
        raise RuntimeError(f"Could not infer CVE column from inthewilddb columns: {list(df.columns)}")

    out = pd.DataFrame({"cve_id": df[cve_col].astype(str).str.upper()})
    out["cve_id"] = out["cve_id"].str.extract(f"({CVE_RE.pattern})", expand=False)
    out = out.dropna(subset=["cve_id"]).drop_duplicates()

    # Optional descriptive fields if present.
    for col in df.columns:
        low = col.lower()
        if "reported" in low and "date" in low:
            out["inthewild_reported_date"] = df[col]
            break
    out["in_the_wild"] = True
    return out


def normalize_morefixes(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    cve_col = None
    for col in df.columns:
        if "cve" in col.lower():
            cve_col = col
            break
    if cve_col is None:
        raise RuntimeError("MoreFixes CSV missing a CVE-like column")

    out = pd.DataFrame({"cve_id": df[cve_col].astype(str).str.upper()})
    out["cve_id"] = out["cve_id"].str.extract(f"({CVE_RE.pattern})", expand=False)
    out = out.dropna(subset=["cve_id"]).drop_duplicates()
    out["morefixes_present"] = True
    return out


def write_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)
    logging.info("Wrote %s (%d rows)", path, len(df))


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    workdir = Path(args.workdir)
    raw_dir = workdir / "raw"
    ensure_dir(raw_dir)

    diagnostics: list[dict] = []

    # Required datasets.
    osv_zip = raw_dir / "osv-all.zip"
    purl2cpe_file = raw_dir / "purl2cpe.csv"
    inthewild_file = raw_dir / "inthewilddb.csv"

    osv_source = download_with_cache(ALLOWED_URLS["osv"], osv_zip)

    purl2cpe_source = None
    for candidate in ALLOWED_URLS["purl2cpe"]:
        ext = Path(urllib.parse.urlparse(candidate).path).suffix or ".csv"
        purl2cpe_file = raw_dir / f"purl2cpe{ext}"
        try:
            purl2cpe_source = download_with_cache([candidate], purl2cpe_file)
            break
        except Exception as exc:  # noqa: BLE001
            logging.warning("purl2cpe candidate failed: %s", exc)
    if purl2cpe_source is None:
        logging.warning("Proceeding without purl2cpe: no allowed source could be downloaded")

    inthewild_source = None
    for candidate in ALLOWED_URLS["inthewilddb"]:
        ext = Path(urllib.parse.urlparse(candidate).path).suffix or ".csv"
        inthewild_file = raw_dir / f"inthewilddb{ext}"
        try:
            inthewild_source = download_with_cache([candidate], inthewild_file)
            break
        except Exception as exc:  # noqa: BLE001
            logging.warning("inthewilddb candidate failed: %s", exc)
    if inthewild_source is None:
        logging.warning("Proceeding without inthewilddb: no allowed source could be downloaded")

    diagnostics.extend(
        [
            {"metric": "source_osv", "value": osv_source},
            {"metric": "source_purl2cpe", "value": purl2cpe_source or "unavailable"},
            {"metric": "source_inthewilddb", "value": inthewild_source or "unavailable"},
        ]
    )

    osv_df = load_osv_table(osv_zip, max_records=args.osv_max_records)
    if purl2cpe_source is None:
        purl2cpe_df = pd.DataFrame(columns=["purl", "cpe"])
    else:
        purl2cpe_df = normalize_purl2cpe(read_tabular(purl2cpe_file))

    if inthewild_source is None:
        inthewild_df = pd.DataFrame(columns=["cve_id", "in_the_wild"])
    else:
        inthewild_df = normalize_inthewild(read_tabular(inthewild_file))

    morefixes_df = pd.DataFrame(columns=["cve_id", "morefixes_present"])
    morefixes_status = "skipped"
    if args.ci_mode and not args.morefixes_path:
        morefixes_status = "skipped_in_ci_too_large_for_default_runner"
    elif args.morefixes_path:
        mf_path = Path(args.morefixes_path)
        if not mf_path.exists():
            raise RuntimeError(f"Configured MoreFixes path does not exist: {mf_path}")
        morefixes_df = normalize_morefixes(mf_path)
        morefixes_status = f"loaded_from_manual_path:{mf_path}"
    else:
        morefixes_status = "skipped_manual_path_not_provided"

    benchmark_df = osv_df.merge(purl2cpe_df, on="purl", how="left")
    benchmark_df = benchmark_df.merge(inthewild_df, on="cve_id", how="left")
    benchmark_df = benchmark_df.merge(morefixes_df, on="cve_id", how="left")

    benchmark_df["has_osv"] = benchmark_df["osv_id"].notna()
    benchmark_df["has_purl2cpe"] = benchmark_df["cpe"].notna()
    benchmark_df["has_inthewilddb"] = benchmark_df["in_the_wild"].eq(True)
    benchmark_df["has_morefixes"] = benchmark_df["morefixes_present"].eq(True)

    for col in ["in_the_wild", "morefixes_present"]:
        if col in benchmark_df.columns:
            benchmark_df[col] = benchmark_df[col].eq(True)

    benchmark_df = benchmark_df[
        [
            "cve_id",
            "osv_id",
            "published",
            "modified",
            "ecosystem",
            "package_name",
            "purl",
            "cpe",
            "in_the_wild",
            "morefixes_present",
            "has_osv",
            "has_purl2cpe",
            "has_inthewilddb",
            "has_morefixes",
        ]
    ]

    source_coverage = pd.DataFrame(
        [
            {
                "source": "osv",
                "row_count": len(osv_df),
                "unique_cves": osv_df["cve_id"].dropna().nunique(),
            },
            {
                "source": "purl2cpe",
                "row_count": len(purl2cpe_df),
                "unique_cves": pd.NA,
            },
            {
                "source": "inthewilddb",
                "row_count": len(inthewild_df),
                "unique_cves": inthewild_df["cve_id"].nunique(),
            },
            {
                "source": "morefixes",
                "row_count": len(morefixes_df),
                "unique_cves": morefixes_df["cve_id"].nunique() if not morefixes_df.empty else 0,
            },
            {
                "source": "benchmark",
                "row_count": len(benchmark_df),
                "unique_cves": benchmark_df["cve_id"].dropna().nunique(),
            },
        ]
    )

    purl_cov = float((benchmark_df["has_purl2cpe"].mean() if len(benchmark_df) else 0.0) * 100)
    wild_cov = float((benchmark_df["has_inthewilddb"].mean() if len(benchmark_df) else 0.0) * 100)
    mf_cov = float((benchmark_df["has_morefixes"].mean() if len(benchmark_df) else 0.0) * 100)

    diagnostics.extend(
        [
            {"metric": "join_purl2cpe_coverage_pct", "value": f"{purl_cov:.2f}"},
            {"metric": "join_inthewild_coverage_pct", "value": f"{wild_cov:.2f}"},
            {"metric": "join_morefixes_coverage_pct", "value": f"{mf_cov:.2f}"},
            {"metric": "morefixes_status", "value": morefixes_status},
        ]
    )

    top_unmatched_purl = (
        benchmark_df.loc[benchmark_df["purl"].notna() & benchmark_df["cpe"].isna(), "purl"]
        .value_counts()
        .head(10)
        .rename_axis("purl")
        .reset_index(name="count")
    )
    if not top_unmatched_purl.empty:
        for _, row in top_unmatched_purl.iterrows():
            diagnostics.append(
                {
                    "metric": "top_unmatched_purl",
                    "value": f"{row['purl']} ({row['count']})",
                }
            )

    top_unmatched_cve = (
        benchmark_df.loc[benchmark_df["cve_id"].notna() & ~benchmark_df["has_inthewilddb"], "cve_id"]
        .value_counts()
        .head(10)
        .rename_axis("cve_id")
        .reset_index(name="count")
    )
    if not top_unmatched_cve.empty:
        for _, row in top_unmatched_cve.iterrows():
            diagnostics.append(
                {
                    "metric": "top_unmatched_cve_in_inthewilddb",
                    "value": f"{row['cve_id']} ({row['count']})",
                }
            )

    join_diag = pd.DataFrame(diagnostics)

    write_csv(benchmark_df, Path("benchmark.csv"))
    write_csv(source_coverage, Path("source_coverage.csv"))
    write_csv(join_diag, Path("join_diagnostics.csv"))

    logging.info("Done. benchmark.csv/source_coverage.csv/join_diagnostics.csv are ready.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        logging.exception("Benchmark build failed: %s", exc)
        raise SystemExit(1)
