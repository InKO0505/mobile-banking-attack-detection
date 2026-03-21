# mobile-banking-attack-detection

> **Thesis:** Development of a Method for Detecting Attacks on Mobile Banking Applications Using Dynamic Analysis
> **Автор / Author:** Igor Zaitsev · Astana IT University, School of Cybersecurity, 2025

A **Runtime Application Self-Protection (RASP)** system built with Frida that detects and blocks three real-world attack vectors against mobile banking applications in real time, and generates a structured JSON audit report for SOC analysts.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Android Emulator                    │
│                                                      │
│  ┌─────────────────────────┐   ┌──────────────────┐  │
│  │     InsecureBankv2      │   │  frida-server    │  │
│  │  (target APK)           │◄──│  (x86_64, root)  │  │
│  │                         │   └──────────────────┘  │
│  │  ┌───────────────────┐  │                         │
│  │  │     agent.js      │  │                         │
│  │  │   (RASP hooks)    │  │                         │
│  │  └───────────────────┘  │                         │
│  └─────────────────────────┘                         │
└─────────────────────┬────────────────────────────────┘
                      │ ADB / Frida RPC
┌─────────────────────▼────────────────────────────────┐
│               Host Machine (Linux)                   │
│                                                      │
│  analyzer.py      ──►  JSON audit report             │
│  simulate_attack.py    (3 attack vectors)            │
│  server.py             (bank :8888 + C2 :9999)       │
└──────────────────────────────────────────────────────┘
```

---

## Detected Attack Vectors

| # | Vector | Hook | Trigger | Response |
|---|--------|------|---------|----------|
| 1 | **ATS** (Automated Touch Simulation) | `View.dispatchTouchEvent` | `deviceId < 0` | **CRITICAL - BLOCKED** |
| 2 | **Overlay Attack** | `Activity.onWindowFocusChanged` | focus loss (keyboard excluded) | **ALERT - DETECTED** |
| 3 | **C2 Network Exfiltration** | `DefaultHttpClient.execute` + `URL.$init` | host not in TRUSTED_HOSTS | **CRITICAL - DETECTED** |

---

## Requirements

### System
- Linux (tested on CachyOS / Arch)
- Android Studio AVD: **Pixel 6, API 35, Google APIs** (no Play Store - required for root)
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

```bash
pip install -r requirements.txt
```

### Android tools
```bash
sudo pacman -S android-tools jdk17-openjdk  # Arch / CachyOS
```

---

## File Structure

```
mobile-banking-attack-detection/
├── agent.js              # Frida RASP agent - 4 hooks (ATS, Overlay, Network x2)
├── analyzer.py           # Controller - launches agent, parses events, saves audit
├── simulate_attack.py    # Attack simulator - 3 vectors (ATS + Overlay + C2)
├── server.py             # Mock server - port 8888 (bank) + port 9999 (C2)
├── start.sh              # Setup helper - adb root + frida-server launch
├── requirements.txt
└── README.md
```

---

## Setup Guide

### Step 1 - Create Android Emulator with root access

1. Open **Android Studio → Device Manager → Add Device**
2. Select **Pixel 6**
3. System image: **API 35, Google APIs, x86_64** - must be **Google APIs**, NOT Google Play
4. Finish and start the emulator
5. Verify root:
```bash
adb root
# Expected: restarting adbd as root
```

### Step 2 - Install frida-server on emulator

```bash
wget https://github.com/frida/frida/releases/download/17.7.3/frida-server-17.7.3-android-x86_64.xz
xz -d frida-server-17.7.3-android-x86_64.xz

adb push frida-server-17.7.3-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Step 3 - Install target application

```bash
wget https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk
adb install --bypass-low-target-sdk-block InsecureBankv2.apk
```

### Step 4 - Python environment

```bash
python -m venv venv
source venv/bin/activate        # bash
# source venv/bin/activate.fish  # fish shell
pip install -r requirements.txt
```

---

## Running the Experiment

> **Each new session:** run `bash start.sh` first - it restarts frida-server after emulator reboot.

### Terminal 1 - Mock servers (bank + C2)
```bash
python server.py
# Bank API running on :8888
# C2 server running on  :9999
```

### Terminal 2 - RASP Analyzer
```bash
# Open InsecureBankv2 on the emulator
# Set server address: 10.0.2.2, port: 8888
python analyzer.py
```

Expected startup output:
```
==================================================
  RASP Dynamic Analyzer v2.0
  Target: com.android.insecurebankv2
==================================================
[*] Monitoring active. Press Ctrl+C to stop and save JSON audit...
[*] RASP Agent injected. Installing hooks...
[*] Hook #1 (ATS / View.dispatchTouchEvent) - OK
[*] Hook #2 (Overlay / onWindowFocusChanged) - OK
[*] Hook #3a (Network / DefaultHttpClient.execute) - OK
[*] Hook #3b (Network / URL.$init) - OK
[*] === All hooks active. Monitoring started. ===
```

### Terminal 3 - Attack Simulation
```bash
python simulate_attack.py
```

### Terminal 2 - Real detection output
```
[!!!] CRITICAL - ATS Bot Activity | Programmatic click BLOCKED! Source: 4098, DeviceID: -1
[!!!] CRITICAL - ATS Bot Activity | Programmatic click BLOCKED! Source: 4098, DeviceID: -1
[!!!] CRITICAL - ATS Bot Activity | Programmatic click BLOCKED! Source: 4098, DeviceID: -1
[-] ALERT: Overlay Attack | Window focus lost - possible overlay covering the screen.
[!!!] CRITICAL - C2 Exfiltration | SUSPICIOUS URL inside process: http://10.0.2.2:9999/exfiltrate?login=jack&pass=Jack%40123&card=4111111111111111 [NOT a bank server!]
```

Press `Ctrl+C` → JSON audit saved automatically.

---

## JSON Audit Report

```json
{
    "report_meta": {
        "generated_at": "2026-03-21T13:29:46.417715",
        "tool": "RASP Dynamic Analyzer v2.0",
        "target_app": "com.android.insecurebankv2",
        "total_events": 12
    },
    "events": [
        {
            "timestamp": "2026-03-21T13:29:10.205025",
            "level": "CRITICAL",
            "threat": "ATS Bot Activity",
            "details": "Programmatic click BLOCKED! Source: 4098, DeviceID: -1"
        },
        {
            "timestamp": "2026-03-21T13:29:16.820879",
            "level": "ALERT",
            "threat": "Overlay Attack",
            "details": "Window focus lost - possible overlay covering the screen."
        },
        {
            "timestamp": "2026-03-21T13:29:20.858902",
            "level": "CRITICAL",
            "threat": "C2 Exfiltration",
            "details": "SUSPICIOUS URL inside process: http://10.0.2.2:9999/exfiltrate?login=jack&... [NOT a bank server!]"
        }
    ]
}
```

---

## How Detection Works

### Hook #1 - ATS (Automated Touch Simulation)
Bots simulate input programmatically via `adb shell input tap` or accessibility services. These events have `deviceId = -1` (virtual device, no physical hardware). The hook on `View.dispatchTouchEvent` checks every touch event - if `deviceId < 0`, the event is **consumed before reaching the application**.

### Hook #2 - Overlay Attack
Malware draws a transparent window over the banking UI to intercept credentials (tapjacking). The `Activity.onWindowFocusChanged` hook detects focus loss. The soft keyboard is excluded from false positives via `WindowInsets.Type.ime()`.

### Hook #3 - Network Exfiltration (C2 Detection)
Every HTTP request from inside the app process passes through `DefaultHttpClient.execute()` and `URL.$init()`. Requests to `TRUSTED_HOSTS` (the bank server) are logged as `WARNING`. Requests to any other host are classified as `CRITICAL - C2 Exfiltration`.

**Key insight:** malware injected into the banking process uses the same Java system classes for network connections. The agent intercepts any non-standard request, making silent data exfiltration impossible.

---

## Limitations & Future Work

- `frida-server` requires root → production deployment would use **Frida Gadget** embedded in a repackaged APK (no root required)
- Network hooks cover `DefaultHttpClient` and `java.net.URL`; apps using `OkHttp` or `Retrofit` require additional hooks
- Overlay detection via focus loss may produce edge-case false positives in complex multi-window layouts
- **Future:** ML-based behavioral scoring, cross-process monitoring, SIEM/CEF export

---

## Why frida-server and not Gadget?

This work focuses on **research and method verification**. `frida-server` allows rapid iterative development - hooks in `agent.js` can be modified and reloaded without repackaging the APK on every change.

The developed hooks represent standalone detection logic. For production deployment, this logic can be:
1. **Integrated natively** by the bank's developers directly into the app source (Java/Kotlin)
2. **Deployed via Frida Gadget** - APK repackaged with `libgadget.so`, no root required
3. **Used as reference** for a Mobile Threat Defense (MTD) platform (Zimperium, Lookout, etc.)

---

## References

- Singh et al. (2024) - *Interpretable Dynamic Analysis for Android Malware*
- Tsobdjou et al. - *Security metrics framework for mobile banking applications* (Polytechnique Montréal)
- [Frida Documentation](https://frida.re/docs/)
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2)
