#!/usr/bin/env python3
"""
validate_reports.py — Check all audit reports for structural validity.

Usage:
    python scripts/validate_reports.py [--dir results/audit_reports]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def validate(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return False, "file_not_found"
    if path.stat().st_size == 0:
        return False, "empty_file"
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        return False, f"invalid_json ({e})"
    if "events" not in data:
        return False, "missing_events_key"
    if "report_meta" not in data:
        return False, "missing_report_meta_key"
    meta = data["report_meta"]
    missing = [k for k in ("session_id", "scenario", "total_events", "generated_at") if k not in meta]
    if missing:
        return True, f"ok_legacy (missing meta fields: {missing})"
    n_events = len(data["events"])
    if n_events != meta["total_events"]:
        return True, f"ok_count_mismatch (meta={meta['total_events']} actual={n_events})"
    return True, "ok"


def main():
    parser = argparse.ArgumentParser(description="Validate audit report JSON files")
    parser.add_argument("--dir", default=None,
                        help="Directory to scan (default: results/audit_reports, then audit_reports/)")
    args = parser.parse_args()

    if args.dir:
        search_dirs = [Path(args.dir)]
    else:
        search_dirs = [ROOT / "results" / "audit_reports", ROOT / "audit_reports"]

    reports: list[Path] = []
    for d in search_dirs:
        if d.exists():
            reports.extend(sorted(d.glob("audit_report_*.json")))

    if not reports:
        print("No audit reports found.")
        sys.exit(0)

    ok_count = fail_count = 0
    for p in reports:
        valid, reason = validate(p)
        tag = "OK  " if valid else "FAIL"
        print(f"  [{tag}] {p.name}  ({reason})")
        if valid:
            ok_count += 1
        else:
            fail_count += 1

    print(f"\n  Total: {len(reports)}   OK: {ok_count}   Failed: {fail_count}")
    sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()
