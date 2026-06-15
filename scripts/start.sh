#!/usr/bin/env bash
set -e

echo "[*] Enabling ADB root..."
adb root

echo "[*] Checking frida-server on device..."
if ! adb shell ls /data/local/tmp/frida-server &>/dev/null; then
  echo ""
  echo "ERROR: frida-server not found on device."
  echo "  1. Download: frida-server-17.7.3-android-x86_64"
  echo "     from https://github.com/frida/frida/releases/tag/17.7.3"
  echo "  2. Unpack: xz -d frida-server-17.7.3-android-x86_64.xz"
  echo "  3. Push:   adb push frida-server-17.7.3-android-x86_64 /data/local/tmp/frida-server"
  echo "  4. chmod:  adb shell chmod 755 /data/local/tmp/frida-server"
  echo ""
  exit 1
fi

echo "[*] Stopping any existing frida-server..."
adb shell pkill frida-server || true

echo "[*] Starting frida-server in background..."
adb shell "/data/local/tmp/frida-server &"

sleep 1

echo "[*] Verifying with frida-ps -U..."
frida-ps -U

echo ""
echo "=== frida-server is running. Next steps ==="
echo "  Terminal A: cd src && python server.py"
echo "  Terminal B: cd src && python analyzer.py"
echo "  Terminal C: cd src && python simulate_attack.py"
echo "  Then Ctrl+C in Terminal B to generate audit_reports/audit_report_*.json"
