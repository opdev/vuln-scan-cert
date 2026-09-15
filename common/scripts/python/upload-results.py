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
def _fetch_job_status(base_url: str, job_id: str, verify_ssl: bool) -> dict | None:
    """GET /jobs/{job_id}/status once. Returns parsed JSON or None if retryable."""
    status_url = f"{base_url.rstrip('/')}/jobs/{job_id}/status"
    try:
        resp = requests.get(status_url, timeout=30, verify=verify_ssl)
    except requests.RequestException as exc:
        warn(f"Poll request failed (job {job_id}): {exc} — retrying")
        return None

    if resp.status_code != 200:
        warn(f"Poll returned HTTP {resp.status_code} (job {job_id}) — retrying")
        return None

    try:
        return resp.json()
    except ValueError:
        warn(f"Server returned non-JSON response (job {job_id})")
        return None


def poll_jobs_until_done(
    base_url: str,
    job_ids: list[str],
    verify_ssl: bool,
    deadline: float,
) -> dict[str, dict]:
    """Poll GET /jobs/{job_id}/status for every job until all complete or one fails.

    Uses a single shared deadline for the whole wait (not per job).
    Returns job_id -> final status payload on success.
    Calls sys.exit(3) on analysis failure or timeout.
    """
    if not job_ids:
        return {}

    pending = set(job_ids)
    results: dict[str, dict] = {}

    if len(job_ids) == 1:
        info(f"Waiting for analysis to complete (job {job_ids[0]})...")
    else:
        info(f"Waiting for analysis to complete ({len(job_ids)} jobs)...")

    while pending and time.time() < deadline:
        for job_id in list(pending):
            data = _fetch_job_status(base_url, job_id, verify_ssl)
            if data is None:
                continue

            status = data.get("status", "unknown")
            analyzers = data.get("analyzers", {})
            done = [k for k, v in analyzers.items() if v == "completed"]
            if done:
                info(f"  job {job_id} completed: {', '.join(done)}")

            if status == "completed":
                pending.discard(job_id)
                results[job_id] = data
                info(f"Analysis completed successfully (job {job_id})")
                continue

            if status == "failed":
                error(f"Analysis failed (job {job_id}): {data.get('error', 'unknown error')}")
                sys.exit(3)

        if pending:
            time.sleep(POLL_INTERVAL_S)

    if pending:
        error(f"Analysis did not complete within {POLL_TIMEOUT_S}s — timed out")
        sys.exit(3)

    return results


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def resolve_file_paths(workspace: str, positional: list[str]) -> list[str]:
    """Return absolute paths for each CSV to process."""
    paths: list[str] = []
    for rel in positional:
        if not rel.strip():
            continue
        if workspace:
            paths.append(os.path.join(workspace, rel))
        else:
            paths.append(rel)

    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upload vulnerability scan results to the Analyser tool.",
        epilog="Pass CSV paths as positional arguments (relative to "
        "ANALYSER_WORKSPACE when set). ANALYSER_URL can replace --url.",
    )

    parser.add_argument(
        "paths",
        nargs="*",
        help="CSV paths relative to ANALYSER_WORKSPACE",
    )

    parser.add_argument(
        "--workspace",
        default=os.environ.get("ANALYSER_WORKSPACE", ""),
        help="Results workspace root for relative paths (env: ANALYSER_WORKSPACE)",
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
def process_file(
    file_path: str,
    base_url: str,
    *,
    dry_run: bool,
    verify_ssl: bool,
) -> dict:
    """Validate and optionally upload a single CSV; return a per-file result dict."""
    info(f"Validating {file_path}...")
    row_count = validate_csv(file_path)
    if row_count == 0:
        warn(f"CSV file has a header but no data rows, skipping: {file_path}")
        return {
            "status": "skipped",
            "file": os.path.basename(file_path),
            "records": 0,
            "reason": "no_data_rows",
        }

    info(f"Found {row_count} records, all required columns present")

    if dry_run:
        info(f"Dry run — {file_path} is valid ({row_count} data rows), not uploading")
        return {
            "status": "dry_run",
            "file": os.path.basename(file_path),
            "records": row_count,
        }

    upload_resp = upload(base_url, file_path, verify_ssl)

    report_id = upload_resp.get("report_id") or upload_resp.get("uuid")
    job_id = upload_resp.get("job_id")
    total = upload_resp.get("total_records") or upload_resp.get("recordCount", row_count)

    info(f"Upload accepted — report_id={report_id}  job_id={job_id}  records={total}")

    return {
        "status": "success",
        "file": os.path.basename(file_path),
        "report_id": report_id,
        "job_id": job_id,
        "records": total,
    }


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    file_paths = resolve_file_paths(args.workspace, args.paths)
    if not file_paths:
        error("Specify at least one CSV path")
        sys.exit(1)

    if not args.url:
        error("Specify --url (or set ANALYSER_URL)")
        sys.exit(1)

    verify_ssl = not args.no_verify_ssl
    if args.no_verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warn("SSL certificate verification disabled")

    start = time.time()
    uploads: list[dict] = []
    for file_path in file_paths:
        uploads.append(
            process_file(
                file_path,
                args.url,
                dry_run=args.dry_run,
                verify_ssl=verify_ssl,
            )
        )

    if args.wait and not args.dry_run:
        job_ids = [entry["job_id"] for entry in uploads if entry.get("status") == "success" and entry.get("job_id")]
        if job_ids:
            deadline = time.time() + POLL_TIMEOUT_S
            analysis_by_job = poll_jobs_until_done(args.url, job_ids, verify_ssl, deadline)
            for entry in uploads:
                job_id = entry.get("job_id")
                if job_id not in analysis_by_job:
                    continue
                analysis_status = analysis_by_job[job_id]
                entry["analysis"] = {
                    "status": analysis_status.get("status"),
                    "analyzers": analysis_status.get("analyzers", {}),
                }

    elapsed = round(time.time() - start, 1)
    info(f"Done in {elapsed}s ({len(uploads)} file(s))")

    if len(uploads) == 1:
        result = uploads[0]
        result["duration_seconds"] = elapsed
        result["url"] = args.url
    else:
        if args.dry_run:
            status = "dry_run"
        elif all(u.get("status") == "skipped" for u in uploads):
            status = "skipped"
        else:
            status = "success"
        result = {
            "status": status,
            "uploads": uploads,
            "duration_seconds": elapsed,
            "url": args.url,
        }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
