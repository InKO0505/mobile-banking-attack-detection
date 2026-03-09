# mobile-banking-attack-detection

> A thesis project on the development of a method for detecting attacks on mobile banking applications using dynamic analysis of their behavior.

This repository contains a **Runtime Application Self-Protection (RASP)** system built with Frida that detects and blocks three real-world attack vectors against mobile banking applications in real time, and generates a structured JSON audit report for SOC analysts.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Android Emulator                   │
│                                                 │
│  ┌──────────────────────┐   ┌────────────────┐  │
│  │   InsecureBankv2     │   │  frida-server  │  │
│  │  (target APK)        │◄──│  (x86_64)      │  │
│  │                      │   └────────────────┘  │
│  │  ┌────────────────┐  │                       │
│  │  │   agent.js     │  │                       │
│  │  │  (RASP hooks)  │  │                       │
│  │  └────────────────┘  │                       │
│  └──────────────────────┘                       │
└────────────────────┬────────────────────────────┘
                     │ ADB / Frida RPC
┌────────────────────▼────────────────────────────┐
│              Host Machine (Linux)               │
│                                                 │
│  analyzer.py ──► JSON audit report              │
│  simulate_attack.py (attack vectors)            │
│  server.py (mock backend)                       │
└─────────────────────────────────────────────────┘
```

## Detected Attack Vectors

| # | Vector | Method | Response |
|---|--------|--------|----------|
| 1 | **ATS** (Automated Touch Simulation) | `View.dispatchTouchEvent` hook — detects `deviceId < 0` | **Block** — event consumed, app never receives it |
| 2 | **Overlay Attack** | `Activity.onWindowFocusChanged` hook — detects focus loss | **Alert** — logged, keyboard excluded from false positives |
| 3 | **Network Exfiltration** | `DefaultHttpClient.execute` + `URL.$init` hooks | **Log** — full URL and method captured |

---

## Requirements

### System
- Linux (tested on CachyOS / Arch)
- Android Studio with AVD: **Pixel 6, API 35, Google APIs** (no Play Store — required for root)
- Java 17+
- `adb` in PATH

### Python
```
frida==17.7.3
frida-tools==14.6.0
objection==1.11.0
colorama==0.4.6
flask==3.1.0
```

Install:
```bash
pip install -r requirements.txt
```

### Android tools
```bash
# Arch / CachyOS
sudo pacman -S android-tools jdk17-openjdk
```

---

## File Structure

```
mobile-banking-attack-detection/
├── agent.js              # Frida RASP agent (hooks)
├── analyzer.py           # Controller — runs agent, captures events, generates audit
├── simulate_attack.py    # Attack simulation script (3 vectors)
├── server.py             # Mock backend server (Flask)
├── requirements.txt
└── README.md
```

---

## Setup Guide

### Step 1 — Create Android Emulator with root access

1. Open **Android Studio → Device Manager → Add Device**
2. Select **Pixel 6**
3. System image: **API 35, Google APIs, x86_64** (must be Google APIs, NOT Google Play)
4. Finish and start the emulator
5. Verify root access:
```bash
adb root
# Expected: restarting adbd as root
```

### Step 2 — Install frida-server on emulator

```bash
# Download frida-server for x86_64 Android
wget https://github.com/frida/frida/releases/download/17.7.3/frida-server-17.7.3-android-x86_64.xz
xz -d frida-server-17.7.3-android-x86_64.xz

# Push and run
adb push frida-server-17.7.3-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Step 3 — Install target application

```bash
# Download InsecureBankv2
wget https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk

# Install (bypass old SDK warning)
adb install --bypass-low-target-sdk-block InsecureBankv2.apk
```

### Step 4 — Set up Python environment

```bash
mkdir ~/mobile-banking-attack-detection && cd ~/mobile-banking-attack-detection
python -m venv venv
source venv/bin/activate        # bash
# source venv/bin/activate.fish  # fish shell
pip install -r requirements.txt
```

---

## Running the Test

### Terminal 1 — Start mock backend server
```bash
python server.py
# Running on http://0.0.0.0:8888
```

### Terminal 2 — Start RASP analyzer
```bash
# 1. Make sure frida-server is running on emulator
adb shell /data/local/tmp/frida-server &

# 2. Open InsecureBankv2 on the emulator manually
#    Set server: 10.0.2.2, port: 8888

# 3. Start analyzer
python analyzer.py
```

Expected output:
```
==================================================
  RASP Dynamic Analyzer v2.0
  Target: com.android.insecurebankv2
==================================================
[*] Monitoring active. Press Ctrl+C to stop and save JSON audit...
[*] RASP Agent injected. Installing hooks...
[*] Hook #1 (ATS / View.dispatchTouchEvent) — OK
[*] Hook #2 (Overlay / onWindowFocusChanged) — OK
[*] Hook #3a (Network / DefaultHttpClient.execute) — OK
[*] Hook #3b (Network / URL.$init) — OK
[*] === All hooks active. Monitoring started. ===
```

### Terminal 3 — Run attack simulation
```bash
python simulate_attack.py
```

### Terminal 2 — Expected detection output
```
[!!!] CRITICAL — BLOCKED: ATS Bot Activity | Programmatic click BLOCKED! Source: 4098, DeviceID: -1
[!!!] CRITICAL — BLOCKED: ATS Bot Activity | Programmatic click BLOCKED! Source: 4098, DeviceID: -1
[!!!] CRITICAL — BLOCKED: ATS Bot Activity | Programmatic click BLOCKED! Source: 4098, DeviceID: -1
[-]   ALERT: Overlay Attack | Window focus lost — possible overlay covering the screen.
[!]   Network Request | HTTP POST → http://10.0.2.2:8888/login
```

### Stop and generate audit
Press `Ctrl+C` in Terminal 2. A JSON audit file will be saved automatically:
```
[+] Audit report saved: audit_report_20260307_171411.json
[+] Total events captured: 12
```

---

## JSON Audit Report

Each session produces a structured audit report:

```json
{
    "report_meta": {
        "generated_at": "2026-03-07T17:10:39.938469",
        "tool": "RASP Dynamic Analyzer v2.0",
        "target_app": "com.android.insecurebankv2",
        "total_events": 12
    },
    "events": [
        {
            "timestamp": "2026-03-07T17:07:48.534435",
            "level": "INFO",
            "threat": "SYSTEM",
            "details": "RASP Agent injected. Installing hooks..."
        },
        {
            "timestamp": "2026-03-07T17:08:14.002265",
            "level": "CRITICAL",
            "threat": "ATS Bot Activity",
            "details": "Programmatic click BLOCKED! Source: 4098, DeviceID: -1"
        },
        {
            "timestamp": "2026-03-07T17:08:20.633312",
            "level": "ALERT",
            "threat": "Overlay Attack",
            "details": "Window focus lost — possible overlay covering the screen."
        }
    ]
}
```

---

## How Detection Works

### ATS (Automated Touch Simulation)
Bots and malware simulate user input programmatically via `adb shell input tap` or accessibility services. These events have `deviceId = -1` (virtual device). The hook on `View.dispatchTouchEvent` checks every touch event — if `deviceId < 0`, the event is **consumed and never reaches the application**.

### Overlay Attack
Malware draws a transparent window over the banking UI to intercept credentials (tapjacking). When this happens, the Activity loses window focus. The hook on `Activity.onWindowFocusChanged` detects this, with a filter to exclude the soft keyboard (which also causes focus loss).

### Network Exfiltration
Any HTTP request made from inside the app process is intercepted via hooks on `DefaultHttpClient.execute()` and `URL.$init()`. This captures both legitimate bank requests and any malicious C2 communication that malware injected into the process would make using the same HTTP client.

---

## Limitations & Future Work

- RASP agent requires frida-server (root access) — production deployment would use repackaged APK with Frida Gadget
- Network hook covers `DefaultHttpClient` and `java.net.URL`; apps using `OkHttp` or `Retrofit` require additional hooks
- Overlay detection via focus loss may produce false positives in complex multi-window scenarios
- Future: ML-based behavioral scoring, cross-process monitoring via OS-level hooks

---

## References

- Singh et al. (2024) — *Interpretable Dynamic Analysis for Android Malware*
- Tsobdjou et al. — *Security metrics framework for mobile banking applications* (Polytechnique Montréal)
- [Frida Documentation](https://frida.re/docs/)
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2)
