import sys, json, datetime, subprocess, re
from colorama import init, Fore, Style
init(autoreset=True)

PACKAGE    = "InsecureBankv2"
TARGET_APK = "com.android.insecurebankv2"
session_logs = []


def save_audit_log():
    filename = f"audit_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        "report_meta": {
            "generated_at": datetime.datetime.now().isoformat(),
            "tool": "RASP Dynamic Analyzer v2.0",
            "target_app": TARGET_APK,
            "total_events": len(session_logs)
        },
        "events": session_logs
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print(Fore.GREEN + Style.BRIGHT + f"\n[+] Audit report saved: {filename}")
    print(Fore.GREEN + f"[+] Total events captured: {len(session_logs)}")


def on_message(payload):
    m_type  = payload.get("type", "info")
    threat  = payload.get("threat", "SYSTEM")
    details = payload.get("message", "")
    session_logs.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "level":     m_type.upper(),
        "threat":    threat,
        "details":   details
    })
    if m_type == "info":
        print(Fore.CYAN    + f"[*] {details}")
    elif m_type == "warning":
        print(Fore.YELLOW  + f"[!] {threat} | {details}")
    elif m_type == "alert":
        print(Fore.MAGENTA + f"[-] ALERT: {threat} | {details}")
    elif m_type == "critical":
        print(Fore.RED + Style.BRIGHT + f"[!!!] CRITICAL — {threat} | {details}")
    elif m_type == "error":
        print(Fore.RED + f"[ERR] {details}")


def main():
    print(Fore.GREEN + Style.BRIGHT + "=" * 50)
    print(Fore.GREEN + Style.BRIGHT + "  RASP Dynamic Analyzer v2.0")
    print(Fore.GREEN + Style.BRIGHT + f"  Target: {TARGET_APK}")
    print(Fore.GREEN + Style.BRIGHT + "=" * 50)

    cmd = ["frida", "-U", PACKAGE, "-l", "agent.js"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)

    pattern = re.compile(r"message: (\{.*?\}) data:", re.DOTALL)

    print(Fore.GREEN + "[*] Monitoring active. Press Ctrl+C to stop and save JSON audit...\n")

    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            match = pattern.search(line)
            if match:
                try:
                    raw = (match.group(1)
                           .replace("'", '"')
                           .replace("None", "null")
                           .replace("True", "true")
                           .replace("False", "false"))
                    msg = json.loads(raw)
                    if msg.get("type") == "send" and isinstance(msg.get("payload"), dict):
                        on_message(msg["payload"])
                except Exception:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        save_audit_log()


if __name__ == "__main__":
    main()