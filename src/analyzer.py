# Run: python src/analyzer.py [--output-dir DIR] [--session-id ID] [--scenario NAME]
import argparse
import atexit
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

LEVEL_COLORS = {
    "critical": Fore.RED,
    "alert":    Fore.MAGENTA,
    "warning":  Fore.YELLOW,
    "info":     Fore.CYAN,
}

session_logs: list[dict] = []
_report_written = False


def normalize_json(raw: str) -> str:
    raw = raw.replace("'", '"')
    raw = re.sub(r'\bNone\b',  'null',  raw)
    raw = re.sub(r'\bTrue\b',  'true',  raw)
    raw = re.sub(r'\bFalse\b', 'false', raw)
    return raw


def write_report(output_dir: str, session_id: str, scenario: str) -> str | None:
    global _report_written
    if _report_written:
        return None
    _report_written = True

    os.makedirs(output_dir, exist_ok=True)
    final_path = os.path.abspath(os.path.join(output_dir, f"audit_report_{session_id}.json"))
    tmp_path   = final_path + ".tmp"

    report = {
        "report_meta": {
            "generated_at": datetime.now().isoformat(),
            "tool":         "RASP Dynamic Analyzer v2.0",
            "target_app":   "com.android.insecurebankv2",
            "session_id":   session_id,
            "scenario":     scenario,
            "total_events": len(session_logs),
        },
        "events": session_logs,
    }

    with open(tmp_path, "w") as f:
        json.dump(report, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)

    # Machine-readable marker — batch_run.py parses this from the log
    print(f"REPORT_SAVED={final_path}", flush=True)
    print(f"\n{Fore.GREEN}[+] Audit report saved: {final_path}{Style.RESET_ALL}", flush=True)
    return final_path


def main() -> None:
    parser = argparse.ArgumentParser(description="RASP Dynamic Analyzer")
    parser.add_argument("--output-dir", default=None,
                        help="Directory for audit reports (default: ../audit_reports)")
    parser.add_argument("--session-id", default=None,
                        help="Unique session ID used in report filename")
    parser.add_argument("--scenario",   default="unknown",
                        help="Attack scenario name recorded in report metadata")
    args = parser.parse_args()

    output_dir = os.path.abspath(
        args.output_dir if args.output_dir
        else os.path.join(os.path.dirname(__file__), "..", "audit_reports")
    )
    session_id = args.session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario   = args.scenario

    def _signal_handler(_sig, _frame):
        write_report(output_dir, session_id, scenario)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    # Fallback: if frida exits on its own and main() returns normally
    atexit.register(lambda: write_report(output_dir, session_id, scenario))

    _venv_frida = os.path.join(os.path.dirname(sys.executable), "frida")
    _frida_bin  = _venv_frida if os.path.isfile(_venv_frida) else "frida"
    cmd = [_frida_bin, "-U", "InsecureBankv2", "-l", "agent.js"]
    print(f"{Fore.CYAN}[*] Launching: {' '.join(cmd)}{Style.RESET_ALL}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    pattern = re.compile(r"message: (\{.*?\}) data:", re.DOTALL)
    buf = ""

    if proc.stdout is None:
        return

    for line in proc.stdout:
        buf += line
        last_end = 0
        for m in pattern.finditer(buf):
            raw      = m.group(1)
            last_end = m.end()
            try:
                frida_msg = json.loads(normalize_json(raw))
            except json.JSONDecodeError:
                continue
            payload = frida_msg.get("payload", frida_msg)
            if not isinstance(payload, dict):
                continue
            level   = payload.get("type",    "info")
            threat  = payload.get("threat",  "?")
            message = payload.get("message", "")
            color   = LEVEL_COLORS.get(level, Fore.WHITE)
            print(f"{color}[{level.upper():8}] [{threat}] {message}{Style.RESET_ALL}")
            session_logs.append({
                "timestamp": datetime.now().isoformat(),
                "level":     level,
                "threat":    threat,
                "details":   message,
            })
        if last_end > 0:
            buf = buf[last_end:]
        elif len(buf) > 8192:
            buf = buf[-4096:]

    proc.wait()
    if proc.returncode != 0:
        print(f"{Fore.RED}[!] frida exited with code {proc.returncode}{Style.RESET_ALL}", flush=True)


if __name__ == "__main__":
    main()
