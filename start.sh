#!/usr/bin/env bash
# start.sh — run this at the start of every session
# frida-server does not survive emulator reboot

set -e

echo "[*] Checking ADB device..."
adb devices

echo "[*] Granting root to ADB..."
adb root
sleep 1

echo "[*] Killing old frida-server if any..."
adb shell pkill frida-server 2>/dev/null || true
sleep 1

echo "[*] Starting frida-server..."
adb shell /data/local/tmp/frida-server &
sleep 2

echo "[*] Verifying frida-server..."
adb shell ps | grep frida-server

echo ""
echo "[+] Ready. Now:"
echo "    1. Open InsecureBankv2 on the emulator"
echo "    2. Set server: 10.0.2.2  port: 8888"
echo "    3. Terminal 1: python server.py"
echo "    4. Terminal 2: python analyzer.py"
echo "    5. Terminal 3: python simulate_attack.py"
