#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import os
import re
import sqlite3
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pandas as pd

LOGGER = logging.getLogger("vuln_benchmark")

SOURCES = {
    "osv": {
        "url": "https://osv-vulnerabilities.storage.googleapis.com/osv/all.zip",
        "manual_name": "osv_all.zip",
        "required": True,
    },
    "purl2cpe": {
        "url": "https://github.com/package-url/purl2cpe",
        "manual_name": "purl2cpe_mapping.(csv|json|db)",
        "required": True,
    },
    "inthewilddb": {
        "url": "https://github.com/inthewildio/inthewilddb",
        "manual_name": "inthewilddb.(csv|json)",
        "required": True,
    },
    "morefixes": {
        "url": "https://github.com/secureIT-project/MoreFixes",
        "manual_name": "morefixes.(csv|json)",
        "required": False,
    },
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")


def ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def estimate_remote_size(url: str, timeout: int = 15) -> Tuple[str, Optional[int], str]:
    try:
        req = Request(url, method="HEAD")
        with urlopen(req, timeout=timeout) as resp:
            size = resp.headers.get("Content-Length")
            return "reachable", int(size) if size and size.isdigit() else None, "HEAD success"
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        return "unreachable", None, str(exc)


def download_file(url: str, dest: Path, timeout: int = 30) -> Tuple[bool, str]:
    try:
        req = Request(url, headers={"User-Agent": "codex-vuln-benchmark/1.0"})
        with urlopen(req, timeout=timeout) as resp, dest.open("wb") as out:
            out.write(resp.read())
        return True, "downloaded"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def normalize_cve(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    match = CVE_RE.search(str(value).upper())
    return match.group(0).upper() if match else None


def extract_osv_rows_from_zip(zip_path: Path) -> pd.DataFrame:
    rows: List[Dict[str, Optional[str]]] = []
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        if not names:
            raise ValueError("No JSON files found in OSV ZIP")
        for name in names:
            with zf.open(name) as fp:
                doc = json.load(fp)
            osv_id = doc.get("id")
            published = doc.get("published")
            modified = doc.get("modified")
            aliases = doc.get("aliases", [])
            cves = sorted({a.upper() for a in aliases if isinstance(a, str) and a.upper().startswith("CVE-")})
            cve_id = cves[0] if cves else None

            affected = doc.get("affected", [])
            if not affected:
                rows.append(
                    {
                        "osv_id": osv_id,
                        "cve_id": cve_id,
                        "published": published,
                        "modified": modified,
                        "ecosystem": None,
                        "package_name": None,
                        "purl": None,
                    }
                )
                continue

            for item in affected:
                pkg = item.get("package", {}) if isinstance(item, dict) else {}
                rows.append(
                    {
                        "osv_id": osv_id,
                        "cve_id": cve_id,
                        "published": published,
                        "modified": modified,
                        "ecosystem": pkg.get("ecosystem"),
                        "package_name": pkg.get("name"),
                        "purl": pkg.get("purl"),
                    }
                )

    df = pd.DataFrame(rows)
    if df.empty:
        raise ValueError("OSV parsed to empty DataFrame")
    return df


def _read_json_records(path: Path) -> List[dict]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        return json.loads(stripped)

    records = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def _find_columns(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    lower = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c in lower:
            return lower[c]
    return None


def load_purl2cpe(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".csv", ".tsv"}:
        sep = "\t" if path.suffix.lower() == ".tsv" else ","
        raw = pd.read_csv(path, sep=sep)
    elif path.suffix.lower() == ".json":
        raw = pd.DataFrame(_read_json_records(path))
    elif path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
        conn = sqlite3.connect(path)
        try:
            tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table'", conn)["name"].tolist()
            if not tables:
                raise ValueError("No tables in sqlite file")
            best = None
            for table in tables:
                probe = pd.read_sql_query(f"SELECT * FROM {table} LIMIT 5", conn)
                cols = {c.lower() for c in probe.columns}
                if "purl" in cols and "cpe" in cols:
                    best = table
                    break
            table = best or tables[0]
            raw = pd.read_sql_query(f"SELECT * FROM {table}", conn)
        finally:
            conn.close()
    else:
        raise ValueError(f"Unsupported purl2cpe format: {path}")

    purl_col = _find_columns(raw, ["purl", "package_url"])
    cpe_col = _find_columns(raw, ["cpe", "cpe23", "cpe_uri"])
    if not purl_col or not cpe_col:
        raise ValueError(f"Could not identify purl/cpe columns in {path}")

    df = raw[[purl_col, cpe_col]].rename(columns={purl_col: "purl", cpe_col: "cpe"}).dropna(how="any")
    df = df.drop_duplicates().reset_index(drop=True)
    return df


def load_inthewild(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        raw = pd.read_csv(path)
    elif path.suffix.lower() == ".json":
        raw = pd.DataFrame(_read_json_records(path))
    else:
        raise ValueError(f"Unsupported inthewild format: {path}")

    cve_col = _find_columns(raw, ["cve", "cve_id", "vuln", "vulnerability"])
    if not cve_col:
        raise ValueError("Could not identify CVE column for inthewilddb")

    detected = raw[cve_col].map(normalize_cve)
    base = pd.DataFrame({"cve_id": detected}).dropna()
    base["inthewild_seen"] = 1

    source_col = _find_columns(raw, ["source", "reference", "url"])
    if source_col:
        base["inthewild_source_count"] = raw[source_col].notna().astype(int).values
    else:
        base["inthewild_source_count"] = 0

    agg = base.groupby("cve_id", as_index=False).agg(
        inthewild_seen=("inthewild_seen", "max"),
        inthewild_source_count=("inthewild_source_count", "sum"),
    )
    return agg


def load_morefixes(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        raw = pd.read_csv(path)
    elif path.suffix.lower() == ".json":
        raw = pd.DataFrame(_read_json_records(path))
    else:
        raise ValueError(f"Unsupported MoreFixes format: {path}")

    cve_col = _find_columns(raw, ["cve", "cve_id", "vuln", "vulnerability"])
    if not cve_col:
        raise ValueError("Could not identify CVE column for MoreFixes")

    fix_col = _find_columns(raw, ["fix", "patch", "commit", "commit_url", "pr", "pull_request"])
    cves = raw[cve_col].map(normalize_cve)
    out = pd.DataFrame({"cve_id": cves}).dropna()
    out["morefixes_seen"] = 1
    if fix_col:
        out["morefixes_fix_count"] = raw[fix_col].notna().astype(int).values
    else:
        out["morefixes_fix_count"] = 0

    agg = out.groupby("cve_id", as_index=False).agg(
        morefixes_seen=("morefixes_seen", "max"),
        morefixes_fix_count=("morefixes_fix_count", "sum"),
    )
    return agg


def build_benchmark(
    osv_df: pd.DataFrame,
    purl2cpe_df: pd.DataFrame,
    inthewild_df: pd.DataFrame,
    morefixes_df: Optional[pd.DataFrame],
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    osv_df = osv_df.copy()
    osv_df["cve_id"] = osv_df["cve_id"].map(normalize_cve)

    merged = osv_df.merge(purl2cpe_df, on="purl", how="left")
    merged = merged.merge(inthewild_df, on="cve_id", how="left")

    if morefixes_df is not None:
        merged = merged.merge(morefixes_df, on="cve_id", how="left")
    else:
        merged["morefixes_seen"] = pd.NA
        merged["morefixes_fix_count"] = pd.NA

    merged["inthewild_seen"] = merged["inthewild_seen"].fillna(0).astype("Int64")
    merged["inthewild_source_count"] = merged["inthewild_source_count"].fillna(0).astype("Int64")

    if morefixes_df is not None:
        merged["morefixes_seen"] = merged["morefixes_seen"].fillna(0).astype("Int64")
        merged["morefixes_fix_count"] = merged["morefixes_fix_count"].fillna(0).astype("Int64")

    merged["has_osv"] = 1
    merged["has_purl2cpe"] = merged["cpe"].notna().astype("Int64")
    merged["has_inthewilddb"] = (merged["inthewild_seen"] > 0).astype("Int64")
    merged["has_morefixes"] = (
        (merged["morefixes_seen"] > 0).astype("Int64") if morefixes_df is not None else pd.Series([pd.NA] * len(merged))
    )

    # add CVEs present in inthewilddb / morefixes but not OSV
    known_cves = set(merged["cve_id"].dropna().unique().tolist())
    extras = []
    for source_name, df in (("inthewilddb", inthewild_df), ("morefixes", morefixes_df)):
        if df is None:
            continue
        for cve in df["cve_id"].dropna().unique().tolist():
            if cve not in known_cves:
                extras.append({"cve_id": cve, "source_only": source_name})

    if extras:
        extra_df = pd.DataFrame(extras).drop_duplicates()
        extra_df = extra_df.merge(inthewild_df, on="cve_id", how="left")
        if morefixes_df is not None:
            extra_df = extra_df.merge(morefixes_df, on="cve_id", how="left")
        extra_df["osv_id"] = pd.NA
        extra_df["published"] = pd.NA
        extra_df["modified"] = pd.NA
        extra_df["ecosystem"] = pd.NA
        extra_df["package_name"] = pd.NA
        extra_df["purl"] = pd.NA
        extra_df["cpe"] = pd.NA
        extra_df["has_osv"] = 0
        extra_df["has_purl2cpe"] = 0
        extra_df["has_inthewilddb"] = extra_df["inthewild_seen"].fillna(0).gt(0).astype("Int64")
        if morefixes_df is not None:
            extra_df["has_morefixes"] = extra_df["morefixes_seen"].fillna(0).gt(0).astype("Int64")
        else:
            extra_df["has_morefixes"] = pd.NA
        merged = pd.concat([merged, extra_df], ignore_index=True, sort=False)

    benchmark_cols = [
        "cve_id",
        "osv_id",
        "published",
        "modified",
        "ecosystem",
        "package_name",
        "purl",
        "cpe",
        "inthewild_seen",
        "inthewild_source_count",
        "morefixes_seen",
        "morefixes_fix_count",
        "has_osv",
        "has_purl2cpe",
        "has_inthewilddb",
        "has_morefixes",
    ]
    for col in benchmark_cols:
        if col not in merged.columns:
            merged[col] = pd.NA

    benchmark = merged[benchmark_cols].copy()

    diag_rows = []
    total_osv_with_purl = int(osv_df["purl"].notna().sum())
    matched_purl = int(benchmark["cpe"].notna().sum())
    diag_rows.append(
        {
            "join_name": "OSV_to_purl2cpe_by_purl",
            "lhs_rows": int(len(osv_df)),
            "lhs_join_key_present": total_osv_with_purl,
            "matched_rows": matched_purl,
            "match_rate_over_keyed": (matched_purl / total_osv_with_purl) if total_osv_with_purl else 0.0,
        }
    )

    osv_cves = set(osv_df["cve_id"].dropna())
    iw_cves = set(inthewild_df["cve_id"].dropna())
    common_iw = len(osv_cves & iw_cves)
    diag_rows.append(
        {
            "join_name": "CVE_to_inthewilddb_by_cve",
            "lhs_rows": len(osv_cves),
            "lhs_join_key_present": len(osv_cves),
            "matched_rows": common_iw,
            "match_rate_over_keyed": (common_iw / len(osv_cves)) if osv_cves else 0.0,
        }
    )

    if morefixes_df is not None:
        mf_cves = set(morefixes_df["cve_id"].dropna())
        common_mf = len(osv_cves & mf_cves)
        diag_rows.append(
            {
                "join_name": "CVE_to_morefixes_by_cve",
                "lhs_rows": len(osv_cves),
                "lhs_join_key_present": len(osv_cves),
                "matched_rows": common_mf,
                "match_rate_over_keyed": (common_mf / len(osv_cves)) if osv_cves else 0.0,
            }
        )
    else:
        diag_rows.append(
            {
                "join_name": "CVE_to_morefixes_by_cve",
                "lhs_rows": len(osv_cves),
                "lhs_join_key_present": len(osv_cves),
                "matched_rows": 0,
                "match_rate_over_keyed": 0.0,
            }
        )

    # failure modes for purl join
    failures = Counter()
    for _, row in merged.iterrows():
        if pd.notna(row.get("cpe")):
            continue
        if pd.isna(row.get("purl")):
            failures["missing_purl_in_osv"] += 1
        else:
            failures["purl_not_found_in_purl2cpe"] += 1

    for mode, count in failures.most_common(5):
        diag_rows.append(
            {
                "join_name": "top_unmatched_failure_modes",
                "lhs_rows": int(len(merged)),
                "lhs_join_key_present": pd.NA,
                "matched_rows": int(count),
                "match_rate_over_keyed": mode,
            }
        )

    diagnostics = pd.DataFrame(diag_rows)
    return benchmark, diagnostics


def source_coverage(
    osv_df: pd.DataFrame,
    purl2cpe_df: pd.DataFrame,
    inthewild_df: pd.DataFrame,
    morefixes_df: Optional[pd.DataFrame],
) -> pd.DataFrame:
    rows = [
        {
            "source": "osv",
            "row_count": len(osv_df),
            "distinct_cve_count": int(osv_df["cve_id"].dropna().nunique()),
            "distinct_purl_count": int(osv_df["purl"].dropna().nunique()),
        },
        {
            "source": "purl2cpe",
            "row_count": len(purl2cpe_df),
            "distinct_cve_count": pd.NA,
            "distinct_purl_count": int(purl2cpe_df["purl"].dropna().nunique()),
        },
        {
            "source": "inthewilddb",
            "row_count": len(inthewild_df),
            "distinct_cve_count": int(inthewild_df["cve_id"].dropna().nunique()),
            "distinct_purl_count": pd.NA,
        },
    ]
    if morefixes_df is not None:
        rows.append(
            {
                "source": "morefixes",
                "row_count": len(morefixes_df),
                "distinct_cve_count": int(morefixes_df["cve_id"].dropna().nunique()),
                "distinct_purl_count": pd.NA,
            }
        )
    else:
        rows.append(
            {
                "source": "morefixes",
                "row_count": 0,
                "distinct_cve_count": 0,
                "distinct_purl_count": pd.NA,
            }
        )
    return pd.DataFrame(rows)


def write_readme(output_dir: Path, audit_rows: List[dict], coverage_df: pd.DataFrame, diagnostics_df: pd.DataFrame, notes: List[str]) -> None:
    readme = output_dir / "README.md"
    lines = [
        "# Vulnerability Benchmark Build Report",
        "",
        "## Data Source Audit Trail",
        "| source | url | status | size_bytes | note |",
        "|---|---|---:|---:|---|",
    ]
    for row in audit_rows:
        lines.append(
            f"| {row['source']} | {row['url']} | {row['status']} | {row.get('size_bytes','')} | {row.get('note','')} |"
        )

    lines.extend(["", "## Source Coverage", coverage_df.to_markdown(index=False), "", "## Join Diagnostics", diagnostics_df.to_markdown(index=False)])
    lines.extend(["", "## Notes"])
    for note in notes:
        lines.append(f"- {note}")

    readme.write_text("\n".join(lines), encoding="utf-8")


def find_manual_file(input_dir: Path, prefixes: List[str]) -> Optional[Path]:
    for candidate in input_dir.iterdir():
        if candidate.is_file() and any(candidate.name.lower().startswith(p) for p in prefixes):
            return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reproducible vulnerability benchmark from OSV/purl2cpe/inthewilddb/MoreFixes.")
    parser.add_argument("--workdir", default="benchmark_workspace", help="Working directory for cache and outputs")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--osv-zip", default=None, help="Path to pre-downloaded OSV all.zip")
    parser.add_argument("--purl2cpe", default=None, help="Path to purl2cpe mapping file (csv/json/sqlite)")
    parser.add_argument("--inthewild", default=None, help="Path to inthewilddb export (csv/json)")
    parser.add_argument("--morefixes", default=None, help="Path to MoreFixes export (csv/json)")
    args = parser.parse_args()

    setup_logging(args.verbose)

    root = Path(args.workdir)
    cache_dir = root / "cache"
    input_dir = root / "manual_inputs"
    output_dir = root / "outputs"
    ensure_dirs(root, cache_dir, input_dir, output_dir)

    LOGGER.info("Step 1/7: Verifying connectivity and estimating source practicality")
    audit_rows = []
    for source, meta in SOURCES.items():
        status, size, note = estimate_remote_size(meta["url"])
        audit_rows.append(
            {
                "source": source,
                "url": meta["url"],
                "status": status,
                "size_bytes": size if size is not None else "",
                "note": note,
            }
        )
        LOGGER.info("%s: %s (size=%s, note=%s)", source, status, size, note)

    LOGGER.info("Step 2/7: Loading OSV")
    notes: List[str] = []

    osv_path = Path(args.osv_zip) if args.osv_zip else cache_dir / "osv_all.zip"
    if not osv_path.exists():
        ok, msg = download_file(SOURCES["osv"]["url"], osv_path)
        if not ok:
            notes.append(f"OSV automatic download failed ({msg}). Place {SOURCES['osv']['manual_name']} under {input_dir} and rerun with --osv-zip.")
    if not osv_path.exists():
        manual = find_manual_file(input_dir, ["osv", "all"])
        if manual:
            osv_path = manual

    if not osv_path.exists():
        raise RuntimeError("OSV data unavailable. Cannot proceed without OSV.")

    osv_df = extract_osv_rows_from_zip(osv_path)

    LOGGER.info("Step 3/7: Loading purl2cpe")
    purl_path = Path(args.purl2cpe) if args.purl2cpe else find_manual_file(input_dir, ["purl2cpe", "purl"])
    if purl_path is None:
        notes.append(
            f"No local purl2cpe artifact found. Download from {SOURCES['purl2cpe']['url']} and place mapping under {input_dir}."
        )
        raise RuntimeError("purl2cpe mapping required but not found")
    purl2cpe_df = load_purl2cpe(purl_path)

    LOGGER.info("Step 4/7: Loading inthewilddb")
    inthewild_path = Path(args.inthewild) if args.inthewild else find_manual_file(input_dir, ["inthewild", "wild"])
    if inthewild_path is None:
        notes.append(
            f"No local inthewilddb export found. Download from {SOURCES['inthewilddb']['url']} and place export under {input_dir}."
        )
        raise RuntimeError("inthewilddb export required but not found")
    inthewild_df = load_inthewild(inthewild_path)

    LOGGER.info("Step 5/7: Loading MoreFixes (optional)")
    morefixes_path = Path(args.morefixes) if args.morefixes else find_manual_file(input_dir, ["morefixes", "more_fixes"])
    morefixes_df = None
    if morefixes_path is not None and morefixes_path.exists():
        morefixes_df = load_morefixes(morefixes_path)
    else:
        notes.append(
            f"MoreFixes not loaded. Optional: fetch official dump from {SOURCES['morefixes']['url']} and place file under {input_dir}."
        )

    LOGGER.info("Step 6/7: Building benchmark and diagnostics")
    benchmark_df, diagnostics_df = build_benchmark(osv_df, purl2cpe_df, inthewild_df, morefixes_df)
    coverage_df = source_coverage(osv_df, purl2cpe_df, inthewild_df, morefixes_df)

    LOGGER.info("Step 7/7: Writing outputs")
    benchmark_path = output_dir / "benchmark.csv"
    coverage_path = output_dir / "source_coverage.csv"
    diagnostics_path = output_dir / "join_diagnostics.csv"

    benchmark_df.to_csv(benchmark_path, index=False, quoting=csv.QUOTE_MINIMAL)
    coverage_df.to_csv(coverage_path, index=False)
    diagnostics_df.to_csv(diagnostics_path, index=False)
    write_readme(output_dir, audit_rows, coverage_df, diagnostics_df, notes)

    created = sorted([p.name for p in output_dir.iterdir() if p.is_file()])
    print("\n=== Pipeline Summary ===")
    print("Files created:")
    for f in created:
        print(f"  - {output_dir / f}")

    print("\nRow counts:")
    print(f"  - benchmark: {len(benchmark_df)}")
    print(f"  - source_coverage: {len(coverage_df)}")
    print(f"  - join_diagnostics: {len(diagnostics_df)}")

    print("\nWhat worked:")
    print("  - Parsed OSV")
    print("  - Loaded purl2cpe mapping")
    print("  - Loaded inthewilddb export")
    print("  - Produced merged benchmark and diagnostics")

    print("\nWhat was skipped:")
    if morefixes_df is None:
        print("  - MoreFixes ingestion (optional data not provided)")
    else:
        print("  - None")

    print("\nManual follow-up needed:")
    if notes:
        for n in notes:
            print(f"  - {n}")
    else:
        print("  - None")

    return 0


if __name__ == "__main__":
    sys.exit(main())
