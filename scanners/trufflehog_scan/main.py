#!/usr/bin/env python3
"""
WhiteHat - Secret Multiscanner Entry Point
===============================================
Runs ONE TruffleHog source for one project and writes its findings to JSON.

This is the dirty half of the dirty/clean split: the container parses
attacker-controlled bytes (a malicious image layer, a hostile repo) with exactly
one source credential in env and nothing else — no Neo4j credentials, no scanner
API key, no HTTP call back to the webapp. Graph ingest is a separate clean step
performed by the orchestrator once this process exits.

Usage:
    TRUFFLEHOG_JOB=/run/job.json python trufflehog_scan/main.py
"""

import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from trufflehog_scan.job_config import load_job
    from trufflehog_scan.sources import get_source, redact
    from trufflehog_scan.trufflehog_runner import TrufflehogRunner
except ImportError:
    from job_config import load_job
    from sources import get_source, redact
    from trufflehog_runner import TrufflehogRunner


def run_trufflehog_scan(job) -> dict:
    """Run one source and return a summary. Never raises for a config problem —
    the caller turns the returned ``error`` into a non-zero exit."""
    try:
        source = get_source(job.source)
    except KeyError as exc:
        return {"error": str(exc)}

    print("\n" + "=" * 70)
    print("           WhiteHat - Secret Multiscanner")
    print("=" * 70)
    print(f"  Source:              {source.label} ({source.id})")
    print(f"  Project:             {job.project_id}")
    print(f"  Verification:        {'on' if job.verification_enabled else 'off'}")
    print(f"  Output:              {job.output_file}")
    print("=" * 70 + "\n")

    runner = TrufflehogRunner(job)
    try:
        findings = runner.run()
    except ValueError as exc:
        return {"error": redact(str(exc))}

    print("\n" + "=" * 70)
    print("                    SCAN SUMMARY")
    print("=" * 70)
    print(f"  Total findings:      {runner.stats['total_findings']}")
    print(f"  Live (validated):    {runner.stats['validated']}")
    print(f"  Dead (unvalidated):  {runner.stats['unvalidated']}")
    print(f"  Verify errors:       {runner.stats['verify_error']}")
    print(f"  Never checked:       {runner.stats['unverified']}")
    print(f"  Assets scanned:      {runner.stats['assets_scanned']}")
    if runner.stats["detector_types"]:
        print("  Detector breakdown:")
        for det, count in sorted(runner.stats["detector_types"].items(), key=lambda x: -x[1]):
            print(f"    {det}: {count}")
    print("=" * 70 + "\n")

    return {
        "source": source.id,
        "target": runner.target,
        "findings_count": len(findings),
        "statistics": runner.stats,
        "output_file": runner.output_file,
    }


def main() -> int:
    job = load_job()

    if not job.project_id:
        print("[!] ERROR: PROJECT_ID / job file project_id not set")
        return 1
    if not job.source:
        print("[!] ERROR: no source selected (set TRUFFLEHOG_SOURCE or the job file)")
        return 1

    start_time = datetime.now()
    try:
        results = run_trufflehog_scan(job)
        if "error" in results:
            print(f"\n[!] Scan failed: {results['error']}")
            return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as exc:
        print(f"\n[!] Unexpected error: {redact(str(exc))}")
        raise

    print(f"\n[*] Total scan time: {(datetime.now() - start_time).total_seconds():.2f} seconds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
