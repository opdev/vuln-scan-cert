#!/usr/bin/env python3
"""Upload vulnerability scan results to the Vulnerability Analyser tool.

Designed as a standalone CLI for integration into Tekton pipelines or
manual use.  Logs progress to stderr; prints a final JSON summary to
stdout so downstream pipeline steps can parse the result.

Exit codes
----------
0  Upload (and optional analysis) succeeded
1  Local validation error (bad file, missing columns)
2  Upload / network error
3  Analysis failed or timed out (only with --wait)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time

import requests
import urllib3

REQUIRED_COLUMNS = (
    "cve_id",
    "package",
    "package_version",
    "rh_severity",
    "rh_cvss",
    "container",
    "container_tag",
    "advisory",
)

UPLOAD_TIMEOUT_S = 60
POLL_INTERVAL_S = 3
POLL_TIMEOUT_S = 600  # 10 minutes


# ---------------------------------------------------------------------------
# Logging helpers — human-readable output goes to stderr
# ---------------------------------------------------------------------------
def _log(level: str, msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", file=sys.stderr)


def info(msg: str) -> None:
    _log("INFO", msg)


def error(msg: str) -> None:
    _log("ERROR", msg)


def warn(msg: str) -> None:
    _log("WARN", msg)


# ---------------------------------------------------------------------------
# Header normalization — mirrors backend csv_parser.py exactly:
#   df.columns.str.strip().str.lower().str.replace(" ", "_")
# ---------------------------------------------------------------------------
def normalize_header(name: str) -> str:
    """strip → lower → spaces to underscores (same as backend csv_parser)."""
    return name.strip().lower().replace(" ", "_")


# ---------------------------------------------------------------------------
# CSV pre-flight validation
# ---------------------------------------------------------------------------
def validate_csv(file_path: str) -> int:
    """Validate the CSV file exists, is non-empty, and has required columns.

    Uses utf-8-sig encoding to handle BOM from Windows-exported CSVs.
    Skips blank rows when counting.

    Returns the number of data rows on success.
    Calls sys.exit(1) on failure.
    """
    if not os.path.isfile(file_path):
        error(f"File not found: {file_path}")
        sys.exit(1)

    if not file_path.lower().endswith(".csv"):
        error(f"File does not have a .csv extension: {file_path}")
        sys.exit(1)

    if os.path.getsize(file_path) == 0:
        error(f"File is empty: {file_path}")
        sys.exit(1)

    with open(file_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        try:
            raw_header = next(reader)
        except StopIteration:
            error("CSV file has no header row")
            sys.exit(1)

        if not raw_header or all(not cell.strip() for cell in raw_header):
            error("CSV header row is empty or whitespace-only")
            sys.exit(1)

        columns = [normalize_header(h) for h in raw_header if h.strip()]

        missing = [col for col in REQUIRED_COLUMNS if col not in columns]
        if missing:
            error(f"CSV is missing required columns: {', '.join(missing)}")
            error(f"Found columns: {', '.join(columns) or '(none)'}")
            sys.exit(1)

        row_count = 0
        for row in reader:
            if not row or all(not cell.strip() for cell in row):
                continue
            row_count += 1

    return row_count


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
def upload(base_url: str, file_path: str, verify_ssl: bool) -> dict:
    """POST the CSV to the /upload endpoint.

    Returns the parsed JSON response on success.
    Calls sys.exit(2) on failure.
    """
    upload_url = f"{base_url.rstrip('/')}/upload"
    filename = os.path.basename(file_path)

    info(f"Uploading {filename} to {upload_url}")

    try:
        with open(file_path, "rb") as f:
            resp = requests.post(
                upload_url,
                files={"file": (filename, f, "text/csv")},
                timeout=UPLOAD_TIMEOUT_S,
                verify=verify_ssl,
            )
    except requests.ConnectionError:
        error(f"Cannot connect to {upload_url} — is the server running?")
        sys.exit(2)
    except requests.Timeout:
        error(f"Upload timed out after {UPLOAD_TIMEOUT_S}s")
        sys.exit(2)
    except requests.RequestException as exc:
        error(f"Upload failed: {exc}")
        sys.exit(2)

    if resp.status_code not in (200, 201, 202):
        error(f"Server returned HTTP {resp.status_code}: {resp.text}")
        sys.exit(2)

    try:
        data = resp.json()
    except ValueError:
        error("Server returned non-JSON response")
        sys.exit(2)

    return data


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------
def poll_until_done(base_url: str, job_id: str, verify_ssl: bool) -> dict:
    """Poll GET /jobs/{job_id}/status until completed or failed.

    Returns the final status payload on success.
    Calls sys.exit(3) on analysis failure or timeout.
    """
    status_url = f"{base_url.rstrip('/')}/jobs/{job_id}/status"
    deadline = time.time() + POLL_TIMEOUT_S

    info(f"Waiting for analysis to complete (job {job_id})...")

    while time.time() < deadline:
        try:
            resp = requests.get(status_url, timeout=30, verify=verify_ssl)
        except requests.RequestException as exc:
            warn(f"Poll request failed: {exc} — retrying in {POLL_INTERVAL_S}s")
            time.sleep(POLL_INTERVAL_S)
            continue

        if resp.status_code != 200:
            warn(f"Poll returned HTTP {resp.status_code} — retrying")
            time.sleep(POLL_INTERVAL_S)
            continue

        try:
            data = resp.json()
        except ValueError:
            warn("Server returned non-JSON response")
            time.sleep(POLL_INTERVAL_S)
            continue

        status = data.get("status", "unknown")

        analyzers = data.get("analyzers", {})
        done = [k for k, v in analyzers.items() if v == "completed"]
        if done:
            info(f"  completed: {', '.join(done)}")

        if status == "completed":
            info("Analysis completed successfully")
            return data

        if status == "failed":
            error(f"Analysis failed: {data.get('error', 'unknown error')}")
            sys.exit(3)

        time.sleep(POLL_INTERVAL_S)

    error(f"Analysis did not complete within {POLL_TIMEOUT_S}s — timed out")
    sys.exit(3)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upload vulnerability scan results to the Analyser tool.",
        epilog="Environment variables ANALYSER_FILE and ANALYSER_URL "
        "can be used in place of --file and --url respectively.",
    )

    parser.add_argument(
        "--file",
        "-f",
        default=os.environ.get("ANALYSER_FILE"),
        help="Path to the CSV results file (env: ANALYSER_FILE)",
    )

    parser.add_argument(
        "--url",
        "-u",
        default=os.environ.get("ANALYSER_URL"),
        help="Analyser base URL (env: ANALYSER_URL)",
    )

    parser.add_argument(
        "--wait",
        "-w",
        action="store_true",
        default=os.environ.get("ANALYSER_WAIT", "").lower() in ("1", "true", "yes"),
        help="Wait for analysis to complete before exiting (env: ANALYSER_WAIT)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=os.environ.get("ANALYSER_DRY_RUN", "").lower() in ("1", "true", "yes"),
        help="Validate the CSV only; do not upload (env: ANALYSER_DRY_RUN)",
    )

    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        default=os.environ.get("ANALYSER_NO_VERIFY_SSL", "").lower() in ("1", "true", "yes"),
        help="Disable SSL certificate verification (env: ANALYSER_NO_VERIFY_SSL)",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.file:
        error("Specify --file or set ANALYSER_FILE")
        sys.exit(1)

    if not args.url:
        error("Specify --url (or set ANALYSER_URL)")
        sys.exit(1)

    # --- validate ---
    info(f"Validating {args.file}...")
    row_count = validate_csv(args.file)
    if row_count == 0:
        warn("CSV file has a header but no data rows, not uploading")
        return

    info(f"Found {row_count} records, all required columns present")

    if args.dry_run:
        info(f"Dry run — {args.file} is valid ({row_count} data rows), not uploading")
        result = {
            "status": "dry_run",
            "file": os.path.basename(args.file),
            "records": row_count,
        }
        print(json.dumps(result))
        return

    verify_ssl = not args.no_verify_ssl
    if args.no_verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warn("SSL certificate verification disabled")

    # --- upload ---
    start = time.time()
    upload_resp = upload(args.url, args.file, verify_ssl)

    report_id = upload_resp.get("report_id") or upload_resp.get("uuid")
    job_id = upload_resp.get("job_id")
    total = upload_resp.get("total_records") or upload_resp.get("recordCount", row_count)

    info(f"Upload accepted — report_id={report_id}  job_id={job_id}  records={total}")

    # --- optionally wait ---
    analysis_status = None
    if args.wait and job_id:
        analysis_status = poll_until_done(args.url, job_id, verify_ssl)

    elapsed = round(time.time() - start, 1)
    info(f"Done in {elapsed}s")

    # --- final JSON to stdout ---
    result = {
        "status": "success",
        "report_id": report_id,
        "job_id": job_id,
        "records": total,
        "duration_seconds": elapsed,
        "url": args.url,
    }

    if analysis_status:
        result["analysis"] = {
            "status": analysis_status.get("status"),
            "analyzers": analysis_status.get("analyzers", {}),
        }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
