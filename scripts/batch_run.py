"""
batch_run.py — Repeated experiment runner for RASP Dynamic Analyzer v2.0

Runs the full attack simulation N times, collects audit JSON reports,
and produces experiment_results.csv and batch_results_<ts>.json.

Usage:
    cd /path/to/rasp-banking
    source venv/bin/activate
    python scripts/batch_run.py --scenario all --runs 20

Output:
    results/experiment_results.csv
    results/batch_results_<timestamp>.json
    results/audit_reports/audit_report_<run_id>.json  (one per run)
    results/logs/analyzer_<run_id>.log
    results/logs/simulator_<run_id>.log
    results/logs/server_<run_id>.log

Environment:
    ANDROID_HOME must be set (or ~/Android/Sdk is used as fallback).
    The emulator must already be booted and frida-server running.
"""

import argparse
import csv
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
SRC     = ROOT / "src"
RESULTS = ROOT / "results"

ANDROID_HOME = os.environ.get("ANDROID_HOME", str(Path.home() / "Android/Sdk"))
ADB          = str(Path(ANDROID_HOME) / "platform-tools" / "adb")

_venv_bin = Path(sys.executable).parent
FRIDA_PS  = str(_venv_bin / "frida-ps") if (_venv_bin / "frida-ps").exists() else "frida-ps"

SCENARIOS = ("all", "real_overlay", "ats", "overlay", "c2")

# ATS threshold for scenario "all" — matches thesis table expectation
ATS_THRESHOLD_ALL = 6
ATS_THRESHOLD_DEDICATED = 1

CSV_FIELDS = [
    "run_id", "scenario", "valid_report", "report_file",
    "ats_detected", "overlay_proxy_detected", "real_overlay_detected", "c2_detected",
    "hook_1_2b_present", "hook_2_present", "hook_3a_present", "hook_3b_present",
    "shutdown_mode", "reason", "notes",
]


# ── subprocess helpers ────────────────────────────────────────────────────────

def adb(*args):
    return subprocess.run([ADB, *args], capture_output=True, text=True)


def start_background(cmd: list[str], log_path: Path,
                     env: dict | None = None, cwd=None) -> subprocess.Popen:
    _env = {**os.environ, "PYTHONUNBUFFERED": "1", **(env or {})}
    return subprocess.Popen(
        cmd,
        stdout=log_path.open("w"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
        env=_env,
        cwd=cwd,
    )


def kill_proc(proc: subprocess.Popen, sig: int = signal.SIGTERM) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError):
        pass


def graceful_shutdown(proc: subprocess.Popen, timeout: int = 30) -> str:
    """
    SIGINT → wait `timeout` s → SIGTERM → wait 5 s → SIGKILL.
    Returns one of: "clean", "sigterm", "sigkill", "already_dead".
    """
    if proc.poll() is not None:
        return "already_dead"
    kill_proc(proc, signal.SIGINT)
    try:
        proc.wait(timeout=timeout)
        return "clean"
    except subprocess.TimeoutExpired:
        pass
    kill_proc(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
        return "sigterm"
    except subprocess.TimeoutExpired:
        pass
    kill_proc(proc, signal.SIGKILL)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    return "sigkill"


# ── report helpers ────────────────────────────────────────────────────────────

def wait_for_hooks(log_path: Path, timeout: int = 60) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            if "All hooks active" in log_path.read_text():
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def parse_report_saved(log_path: Path) -> Path | None:
    """Scan analyzer log for REPORT_SAVED=<abs-path> emitted by analyzer.py."""
    try:
        for line in log_path.read_text().splitlines():
            if line.startswith("REPORT_SAVED="):
                return Path(line.split("=", 1)[1].strip())
    except OSError:
        pass
    return None


def wait_for_report(path: Path, timeout: int = 30) -> tuple[bool, str]:
    """
    Wait until `path` exists, has stable non-zero size for ≥2 consecutive
    half-second checks, and contains valid JSON with expected keys.
    Returns (ok, reason).
    """
    deadline   = time.time() + timeout
    prev_size  = -1
    stable_cnt = 0

    while time.time() < deadline:
        # Also check for leftover .tmp to detect mid-write state
        if not path.exists():
            time.sleep(0.5)
            continue
        try:
            size = path.stat().st_size
        except OSError:
            time.sleep(0.5)
            continue
        if size == 0:
            time.sleep(0.5)
            continue
        if size == prev_size:
            stable_cnt += 1
        else:
            stable_cnt = 0
            prev_size  = size
        if stable_cnt >= 2:
            try:
                data = json.loads(path.read_text())
                if "events" in data and "report_meta" in data:
                    return True, "ok"
                # Has content but unexpected shape — still usable
                return True, "ok_partial"
            except (json.JSONDecodeError, OSError):
                pass  # still writing — keep polling
        time.sleep(0.5)

    if not path.exists():
        return False, "report_timeout"
    try:
        json.loads(path.read_text())
        return True, "ok_late"
    except (json.JSONDecodeError, OSError):
        return False, "invalid_json"


def parse_report(path: Path) -> dict:
    data   = json.loads(path.read_text())
    events = data.get("events", [])

    ats     = [e for e in events
               if e.get("threat") == "ATS Bot Activity" and e.get("level") == "critical"]
    overlay = [e for e in events
               if e.get("threat") == "Overlay-proxy"    and e.get("level") == "alert"]
    c2      = [e for e in events
               if e.get("threat") == "C2 Exfiltration"  and e.get("level") == "critical"]

    _obscured_kw = ("FLAG_WINDOW_IS_OBSCURED", "FLAG_WINDOW_IS_PARTIALLY_OBSCURED", "obscured")
    real_overlay = [
        e for e in events
        if e.get("threat") == "Overlay Attack"
        and e.get("level") == "critical"
        and any(kw in e.get("details", "") for kw in _obscured_kw)
    ]

    return {
        "ats_count":          len(ats),
        "overlay_count":      len(overlay),
        "real_overlay_count": len(real_overlay),
        "c2_count":           len(c2),
    }


def parse_hooks(log_path: Path) -> dict:
    try:
        text = log_path.read_text()
    except OSError:
        return {}
    return {
        "hook_1_2b": ("Hook #1+#2b" in text) or ("Hook #1" in text and "Hook #2b" in text),
        "hook_2":    "Hook #2"  in text,
        "hook_3a":   "Hook #3a" in text,
        "hook_3b":   "Hook #3b" in text,
    }


def ats_detected(count: int, scenario: str) -> bool:
    threshold = ATS_THRESHOLD_ALL if scenario == "all" else ATS_THRESHOLD_DEDICATED
    return count >= threshold


# ── UI helper ─────────────────────────────────────────────────────────────────

def ensure_login_focused(timeout: int = 15) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        r = adb("shell", "dumpsys", "window")
        lines      = r.stdout.splitlines()
        focus      = next((l for l in lines if "mCurrentFocus" in l), "")
        focused_app = next((l for l in lines if "mFocusedApp"   in l), "")

        # Success: LoginActivity has current focus
        if "insecurebankv2" in focus and "LoginActivity" in focus:
            return True

        # Also accept: LoginActivity is the focused app even if a system dialog
        # sits on top — dismiss the dialog first, then re-check next iteration
        if "insecurebankv2" in focused_app and "LoginActivity" in focused_app:
            # If only a dismissable system dialog is on top, dismiss and continue
            if not any(bad in focus for bad in ("insecurebankv2", "kz.aitu")):
                # "Application Not Responding" dialog
                if "Not Responding" in focus or "ANR" in focus:
                    adb("shell", "input", "tap", "540", "1363")   # "Wait" button
                    time.sleep(0.5)
                    continue
                # No blocking dialog — treat as success
                return True

        # Other known blockers
        if "DeprecatedTargetSdkVersion" in focus or "aerr" in focus.lower():
            adb("shell", "input", "keyevent", "66")
            time.sleep(0.5)
            adb("shell", "input", "tap", "894", "1428")
        elif "Not Responding" in focus or "ANR" in focus or "isn" in focus:
            adb("shell", "input", "tap", "540", "1363")   # "Wait" button

        time.sleep(1)
    return False


# ── CSV ───────────────────────────────────────────────────────────────────────

def append_csv(csv_path: Path, row: dict) -> None:
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with csv_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


def _skip_row(run_id: str, scenario: str, reason: str) -> dict:
    return {
        "run_id": run_id, "scenario": scenario,
        "valid_report": False, "report_file": "",
        "ats_detected": False, "overlay_proxy_detected": False,
        "real_overlay_detected": False, "c2_detected": False,
        "hook_1_2b_present": False, "hook_2_present": False,
        "hook_3a_present": False, "hook_3b_present": False,
        "shutdown_mode": "n/a", "reason": reason, "notes": "skipped",
        # raw counts for JSON
        "ats_count": 0, "overlay_count": 0, "real_overlay_count": 0, "c2_count": 0,
    }


# ── single run ────────────────────────────────────────────────────────────────

def run_once(run_index: int, python: str, scenario: str, results_dir: Path) -> dict:
    ts_str  = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id  = f"run_{run_index:03d}_{ts_str}"
    audit_dir = results_dir / "audit_reports"
    logs_dir  = results_dir / "logs"
    audit_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    expected_report = audit_dir / f"audit_report_{run_id}.json"

    print(f"\n{'─' * 56}")
    print(f"  Run {run_index:03d}  [id={run_id}  scenario={scenario}]")
    print(f"{'─' * 56}")

    # 1. Clean device state
    adb("shell", "rm", "-f", "/data/local/tmp/c2_trigger")
    adb("shell", "am", "force-stop", "com.android.insecurebankv2")
    adb("shell", "am", "force-stop", "kz.aitu.overlaytest")
    if scenario == "real_overlay":
        adb("shell", "appops", "set", "kz.aitu.overlaytest", "SYSTEM_ALERT_WINDOW", "allow")
    time.sleep(2)

    # 2. Launch app
    adb("shell", "am", "start", "-n", "com.android.insecurebankv2/.LoginActivity")
    time.sleep(4)
    if not ensure_login_focused(timeout=20):
        print("  [!] LoginActivity did not get focus — skipping run")
        return _skip_row(run_id, scenario, "login_focus_timeout")

    result = subprocess.run([FRIDA_PS, "-U"], capture_output=True, text=True)
    if "InsecureBankv2" not in result.stdout:
        print("  [!] App not started — skipping run")
        return _skip_row(run_id, scenario, "app_not_started")

    # 3. Start server
    server_log = logs_dir / f"server_{run_id}.log"
    srv = start_background([python, "-u", str(SRC / "server.py")], server_log)
    time.sleep(2)

    # 4. Start analyzer — pass run_id so report filename is deterministic
    analyzer_log = logs_dir / f"analyzer_{run_id}.log"
    ana = start_background(
        [python, "-u", str(SRC / "analyzer.py"),
         "--output-dir", str(audit_dir),
         "--session-id", run_id,
         "--scenario",   scenario],
        analyzer_log,
        env={"ANDROID_HOME": ANDROID_HOME},
        cwd=SRC,
    )

    # 5. Wait for hooks
    print("  Waiting for hooks...", end="", flush=True)
    if not wait_for_hooks(analyzer_log, timeout=60):
        print(" TIMEOUT")
        kill_proc(ana)
        kill_proc(srv)
        hooks = parse_hooks(analyzer_log)
        row = _skip_row(run_id, scenario, "hooks_timeout")
        row.update({k: v for k, v in {
            "hook_1_2b_present": hooks.get("hook_1_2b", False),
            "hook_2_present":    hooks.get("hook_2",    False),
            "hook_3a_present":   hooks.get("hook_3a",   False),
            "hook_3b_present":   hooks.get("hook_3b",   False),
        }.items()})
        return row
    print(" OK")

    # 6. Run attack simulation
    adb("shell", "rm", "-f", "/data/local/tmp/c2_trigger")
    time.sleep(0.5)
    sim_log = logs_dir / f"simulator_{run_id}.log"
    subprocess.run(
        [python, str(SRC / "simulate_attack.py"), scenario],
        stdout=sim_log.open("w"), stderr=subprocess.STDOUT,
        cwd=SRC,
    )
    time.sleep(5)   # allow C2 poll cycle to complete

    # 7. Graceful shutdown — wait for actual process exit, no guessing
    shutdown_mode = graceful_shutdown(ana, timeout=30)
    print(f"  Analyzer shutdown: {shutdown_mode}")

    # 8. Determine report path from REPORT_SAVED= line in log (exact path)
    #    Fall back to the deterministic expected name if line is missing
    report_path = parse_report_saved(analyzer_log) or expected_report

    # 9. Wait until report is fully written and JSON-valid
    ok, reason = wait_for_report(report_path, timeout=30)

    hooks = parse_hooks(analyzer_log)
    hook_row = {
        "hook_1_2b_present": hooks.get("hook_1_2b", False),
        "hook_2_present":    hooks.get("hook_2",    False),
        "hook_3a_present":   hooks.get("hook_3a",   False),
        "hook_3b_present":   hooks.get("hook_3b",   False),
    }

    if not ok:
        print(f"  [!] No valid report: {reason}")
        kill_proc(srv)
        time.sleep(1)
        row = _skip_row(run_id, scenario, reason)
        row.update(hook_row)
        row["shutdown_mode"] = shutdown_mode
        row["report_file"]   = str(report_path)
        row["notes"] = ""
        return row

    counts = parse_report(report_path)
    print(
        f"  ATS={counts['ats_count']}  "
        f"Overlay={counts['overlay_count']}  "
        f"RealOverlay={counts['real_overlay_count']}  "
        f"C2={counts['c2_count']}  → {report_path.name}"
    )

    kill_proc(srv)
    time.sleep(1)

    return {
        "run_id":                 run_id,
        "scenario":               scenario,
        "valid_report":           True,
        "report_file":            str(report_path),
        "ats_detected":           ats_detected(counts["ats_count"], scenario),
        "overlay_proxy_detected": counts["overlay_count"] >= 1,
        "real_overlay_detected":  counts["real_overlay_count"] >= 1,
        "c2_detected":            counts["c2_count"] >= 1,
        **hook_row,
        "shutdown_mode": shutdown_mode,
        "reason":        reason,
        "notes":         "",
        # raw counts preserved in JSON (not in CSV)
        "ats_count":          counts["ats_count"],
        "overlay_count":      counts["overlay_count"],
        "real_overlay_count": counts["real_overlay_count"],
        "c2_count":           counts["c2_count"],
    }


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Batch experiment runner")
    parser.add_argument("--runs",        type=int, default=20)
    parser.add_argument("--scenario",    type=str, default="all", choices=list(SCENARIOS))
    parser.add_argument("--results-dir", type=str, default=None,
                        help="Override results directory (default: results/)")
    args = parser.parse_args()

    python      = sys.executable
    results_dir = Path(args.results_dir) if args.results_dir else RESULTS
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "audit_reports").mkdir(exist_ok=True)
    (results_dir / "logs").mkdir(exist_ok=True)

    csv_path    = results_dir / "experiment_results.csv"
    all_results = []

    for i in range(1, args.runs + 1):
        row = run_once(i, python, args.scenario, results_dir)
        row["run"] = i
        all_results.append(row)
        append_csv(csv_path, row)

    # ── summary table ─────────────────────────────────────────────────────────
    valid   = [r for r in all_results if r.get("valid_report")]
    invalid = [r for r in all_results if not r.get("valid_report")]
    total_v = len(valid)
    total   = len(all_results)

    if not total_v:
        print("  No valid runs — nothing to summarise.")
        return

    ats_det          = sum(1 for r in valid if r["ats_detected"])
    overlay_det      = sum(1 for r in valid if r["overlay_proxy_detected"])
    real_overlay_det = sum(1 for r in valid if r["real_overlay_detected"])
    c2_det           = sum(1 for r in valid if r["c2_detected"])

    print(f"\n{'═' * 62}")
    print(f"  BATCH RESULTS  scenario={args.scenario}  ({total_v} valid / {total} attempted)")
    print(f"{'═' * 62}")
    print(f"  {'Scenario':<32} {'Valid':>5} {'Det':>5} {'Miss':>5} {'Rate':>8}")
    print(f"  {'─' * 57}")

    if args.scenario in ("all", "ats"):
        thr = ATS_THRESHOLD_ALL if args.scenario == "all" else ATS_THRESHOLD_DEDICATED
        print(f"  {f'ATS (≥{thr} events per run)':<32} {total_v:>5} {ats_det:>5} {total_v-ats_det:>5} {ats_det/total_v*100:>7.1f}%")
    if args.scenario in ("all", "overlay"):
        print(f"  {'Overlay-proxy (≥1)':<32} {total_v:>5} {overlay_det:>5} {total_v-overlay_det:>5} {overlay_det/total_v*100:>7.1f}%")
    if args.scenario == "real_overlay":
        print(f"  {'Real Overlay/FLAG_OBSCURED (≥1)':<32} {total_v:>5} {real_overlay_det:>5} {total_v-real_overlay_det:>5} {real_overlay_det/total_v*100:>7.1f}%")
    if args.scenario in ("all", "c2"):
        print(f"  {'C2 Exfiltration (≥1)':<32} {total_v:>5} {c2_det:>5} {total_v-c2_det:>5} {c2_det/total_v*100:>7.1f}%")

    if invalid:
        print(f"\n  Failed runs ({len(invalid)}):")
        for r in invalid:
            print(f"    {r['run_id']}  reason={r['reason']}")

    print(f"{'═' * 62}")

    # Save batch JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_path = results_dir / f"batch_results_{ts}.json"
    batch_report = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "tool":         "RASP Dynamic Analyzer v2.0 — batch runner",
            "target_app":   "com.android.insecurebankv2",
            "scenario":     args.scenario,
            "total_runs":   total,
            "valid_runs":   total_v,
            "invalid_runs": total - total_v,
        },
        "summary": {
            "ATS":         {"detected": ats_det,          "missed": total_v - ats_det,          "rate_pct": round(ats_det / total_v * 100, 1)},
            "OverlayProxy":{"detected": overlay_det,      "missed": total_v - overlay_det,      "rate_pct": round(overlay_det / total_v * 100, 1)},
            "RealOverlay": {"detected": real_overlay_det, "missed": total_v - real_overlay_det, "rate_pct": round(real_overlay_det / total_v * 100, 1)},
            "C2":          {"detected": c2_det,           "missed": total_v - c2_det,           "rate_pct": round(c2_det / total_v * 100, 1)},
        },
        "runs": all_results,
    }
    batch_path.write_text(json.dumps(batch_report, indent=2))
    print(f"\n  CSV:  {csv_path}")
    print(f"  JSON: {batch_path}")


if __name__ == "__main__":
    main()
