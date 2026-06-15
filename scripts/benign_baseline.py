"""
benign_baseline.py — False-positive baseline test for RASP Dynamic Analyzer v2.0

Tests normal (benign) user actions and records whether the analyzer
incorrectly raises CRITICAL alerts. Used to populate the FP column of the
confusion matrix in the thesis.

Usage:
    cd /path/to/rasp-banking
    source venv/bin/activate
    python scripts/benign_baseline.py

What is tested:
    1. Keyboard open / close (IME visible → Overlay hook should NOT fire)
    2. App background → foreground  (no ADB tap involved)
    3. Legitimate bank network request to 10.0.2.2:8888 (WARNING, not CRITICAL)
    4. App screen rotation (focus change with no overlay)

What is NOT tested automatically (must be done manually):
    - Manual touch via emulator window (DeviceID ≥ 0 → no ATS alert)
      Open:  ~/Android/Sdk/emulator/emulator -avd rasp_pixel6_api35 &
      Click the Login button with the mouse. ATS should NOT fire.

Expected results:
    All automated checks → level = "warning" or "info" only (no "critical").
    The [Overlay-proxy] ALERT from background/foreground is an acknowledged
    limitation documented in the thesis (false positive rate = 1/N for overlay).
"""

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
REPORTS = ROOT / "audit_reports"

ANDROID_HOME = os.environ.get("ANDROID_HOME", str(Path.home() / "Android/Sdk"))
ADB = str(Path(ANDROID_HOME) / "platform-tools" / "adb")


def adb(*args, **kw):
    return subprocess.run([ADB, *args], capture_output=True, text=True, **kw)


def start_background(cmd, log_path, env=None, cwd=None):
    e = {**os.environ, "PYTHONUNBUFFERED": "1", **(env or {})}
    return subprocess.Popen(
        cmd,
        stdout=log_path.open("w"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
        env=e,
        cwd=cwd,
    )


def kill_proc(proc, sig=signal.SIGTERM):
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError):
        pass


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


def latest_report(before: float) -> Path | None:
    candidates = sorted(
        REPORTS.glob("audit_report_*.json"),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    for p in candidates:
        if p.stat().st_mtime > before:
            return p
    return None


# ── benign actions ────────────────────────────────────────────────────────────

def action_keyboard_open_close():
    """Open a text field, trigger keyboard, close it."""
    # Tap on username field (approximately center-top of login form)
    adb("shell", "input", "tap", "540", "800")
    time.sleep(1)
    # Type something (this is NOT a programmatic ATS tap — it's text input)
    adb("shell", "input", "text", "testuser")
    time.sleep(0.5)
    # Close keyboard with BACK
    adb("shell", "input", "keyevent", "4")
    time.sleep(1)


def action_background_foreground():
    """Send app to background (HOME), wait, return to foreground."""
    adb("shell", "input", "keyevent", "3")     # HOME
    time.sleep(2)
    adb("shell", "am", "start", "-n", "com.android.insecurebankv2/.LoginActivity")
    time.sleep(2)


def action_legitimate_network():
    """Send a real HTTP request to the bank server (trusted host)."""
    adb("shell",
        "printf '%s\\r\\n%s\\r\\n\\r\\n' "
        "'GET /login HTTP/1.0' "
        "'Host: 10.0.2.2:8888' "
        "| /system/bin/nc -w 3 10.0.2.2 8888")
    time.sleep(1)


def action_screen_rotation():
    """Rotate screen and rotate back."""
    adb("shell", "settings", "put", "system", "accelerometer_rotation", "0")
    adb("shell", "settings", "put", "system", "user_rotation", "1")   # landscape
    time.sleep(1)
    adb("shell", "settings", "put", "system", "user_rotation", "0")   # portrait
    adb("shell", "settings", "put", "system", "accelerometer_rotation", "1")
    time.sleep(1)


BENIGN_ACTIONS = [
    ("Keyboard open/close (text input)",    action_keyboard_open_close),
    ("App background → foreground",         action_background_foreground),
    ("Legitimate GET /login to bank:8888",  action_legitimate_network),
    ("Screen rotation (portrait↔landscape)", action_screen_rotation),
]


# ── analysis ─────────────────────────────────────────────────────────────────

def analyse_events(events: list) -> dict:
    """Classify events as TP/FP/TN for benign scenario."""
    critical = [e for e in events if e.get("level") == "critical" and e.get("threat") != "SYSTEM"]
    alert    = [e for e in events if e.get("level") == "alert"    and e.get("threat") != "SYSTEM"]
    warning  = [e for e in events if e.get("level") == "warning"  and e.get("threat") != "SYSTEM"]
    return {
        "critical_count": len(critical),
        "alert_count":    len(alert),
        "warning_count":  len(warning),
        "critical_events": critical,
        "alert_events":    alert,
    }


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    python = sys.executable
    REPORTS.mkdir(exist_ok=True)

    print("=" * 62)
    print("  BENIGN BASELINE TEST — RASP Dynamic Analyzer v2.0")
    print("=" * 62)

    # Clean start
    adb("shell", "rm", "-f", "/data/local/tmp/c2_trigger")
    adb("shell", "am", "force-stop", "com.android.insecurebankv2")
    time.sleep(2)
    adb("shell", "am", "start", "-n", "com.android.insecurebankv2/.LoginActivity")
    time.sleep(4)

    # Start server
    server_log = REPORTS / "server_benign.log"
    srv = start_background([python, "-u", str(SRC / "server.py")], server_log)
    time.sleep(2)

    # Start analyzer
    analyzer_log = REPORTS / "analyzer_benign.log"
    ana = start_background([python, "-u", str(SRC / "analyzer.py")], analyzer_log,
                           env={"ANDROID_HOME": ANDROID_HOME}, cwd=SRC)

    print("\nWaiting for hooks...", end="", flush=True)
    if not wait_for_hooks(analyzer_log, timeout=60):
        print(" TIMEOUT — aborting")
        kill_proc(ana); kill_proc(srv)
        sys.exit(1)
    print(" OK\n")

    # Run each benign action and record events
    results = []
    for label, fn in BENIGN_ACTIONS:
        print(f"  [{label}]")
        snapshot_before = analyzer_log.stat().st_size
        fn()
        time.sleep(2)

        # Read new lines since snapshot
        new_text = analyzer_log.read_text()[snapshot_before:]
        # Parse events from log lines (quick parse — full JSON is in report)
        critical_lines = [l for l in new_text.splitlines() if "[CRITICAL]" in l and "SYSTEM" not in l]
        alert_lines    = [l for l in new_text.splitlines() if "[ALERT   ]" in l and "SYSTEM" not in l]
        warning_lines  = [l for l in new_text.splitlines() if "[WARNING ]" in l]

        fp = len(critical_lines) > 0
        known_fp = len(alert_lines) > 0  # alert = known limitation, discussed in thesis

        status = "FP ✗" if fp else ("ALERT (known)" if known_fp else "TN ✓")
        print(f"    critical={len(critical_lines)}  alert={len(alert_lines)}  warning={len(warning_lines)}  → {status}")
        if critical_lines:
            for l in critical_lines:
                print(f"    ! {l.strip()}")

        results.append({
            "action":        label,
            "critical":      len(critical_lines),
            "alert":         len(alert_lines),
            "warning":       len(warning_lines),
            "false_positive": fp,
            "known_fp":      known_fp,
        })
        time.sleep(0.5)

    # SIGINT → write JSON report
    ts_before = time.time()
    kill_proc(ana, signal.SIGINT)
    time.sleep(3)
    kill_proc(srv)

    # Summary
    report_path = latest_report(ts_before)
    total_fp = sum(1 for r in results if r["false_positive"])
    known_alerts = sum(1 for r in results if r["known_fp"])

    print(f"\n{'═' * 62}")
    print(f"  BENIGN BASELINE SUMMARY")
    print(f"{'═' * 62}")
    print(f"  {'Action':<42} {'Result'}")
    print(f"  {'─' * 58}")
    for r in results:
        if r["false_positive"]:
            verdict = "FP ✗"
        elif r["known_fp"]:
            verdict = "ALERT (known limitation)"
        else:
            verdict = "TN ✓"
        print(f"  {r['action']:<42} {verdict}")
    print(f"  {'─' * 58}")
    print(f"  Total false positives (unexpected CRITICAL): {total_fp}")
    print(f"  Known alerts (Overlay, discussed in thesis): {known_alerts}")
    print(f"{'═' * 62}")

    # Save report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORTS / f"benign_baseline_{ts}.json"
    out.write_text(json.dumps({
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "tool": "RASP Dynamic Analyzer v2.0 — benign baseline",
            "target_app": "com.android.insecurebankv2",
        },
        "summary": {
            "total_actions": len(results),
            "false_positives": total_fp,
            "known_alerts": known_alerts,
        },
        "actions": results,
        "audit_report": str(report_path) if report_path else None,
    }, indent=2))
    print(f"\n  Report saved: {out}")

    print("""
  ─── MANUAL CHECK (required for thesis) ────────────────────
  Open emulator window:
    ~/Android/Sdk/emulator/emulator -avd rasp_pixel6_api35 &

  With analyzer running, click Login button with the MOUSE
  (not ADB). deviceId ≥ 0 → ATS hook must NOT fire → TN.
  ────────────────────────────────────────────────────────────
""")


if __name__ == "__main__":
    main()
