import time
import subprocess


def run_adb(cmd):
    full = f"adb shell {cmd}"
    print(f"    $ {full}")
    result = subprocess.run(full, shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"    > {result.stdout.strip()}")


def check_adb_device():
    result = subprocess.run("adb devices", shell=True, capture_output=True, text=True)
    return len([l for l in result.stdout.splitlines() if "\t" in l]) > 0


print("=" * 50)
print("  Attack Simulation Script")
print("  Vectors: ATS + Overlay + C2 Network")
print("=" * 50)

if not check_adb_device():
    print("[!] No ADB device found.")
    exit(1)

print("\n[*] Starting simulation in 3 seconds...")
time.sleep(3)


print("\n[VECTOR 1] ATS — Programmatic tap via ADB input...")
for i in range(3):
    print(f"  Tap #{i+1}")
    run_adb("input tap 400 600")
    time.sleep(1.5)
time.sleep(2)


print("\n[VECTOR 2] Overlay — launching Settings on top of app...")
run_adb("am start -a android.settings.SETTINGS")
time.sleep(2)
run_adb("am start -n com.android.insecurebankv2/.LoginActivity")
time.sleep(2)


print("\n[VECTOR 3] C2 Network — placing trigger inside device...")
run_adb("touch /data/local/tmp/c2_trigger")
print("    [*] Trigger placed — agent will execute C2 request from inside bank process")
time.sleep(3)

print("\n[*] Simulation complete.")
print("[*] Check analyzer.py window for results and JSON audit.")