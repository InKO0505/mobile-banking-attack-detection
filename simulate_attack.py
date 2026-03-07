"""
simulate_attack.py — имитация вредоносного поведения
для тестирования RASP-агента.
Запуск (в отдельном терминале, пока analyzer.py работает):
    python simulate_attack.py
"""
import time
import subprocess


def run_adb(cmd: str) -> None:
    full = f"adb shell {cmd}"
    print(f"    $ {full}")
    result = subprocess.run(full, shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"    > {result.stdout.strip()}")
    if result.returncode != 0 and result.stderr.strip():
        print(f"    [stderr] {result.stderr.strip()}")


def check_adb_device() -> bool:
    result = subprocess.run("adb devices", shell=True, capture_output=True, text=True)
    lines = [l for l in result.stdout.strip().splitlines() if "\t" in l]
    return len(lines) > 0


print("=" * 50)
print("  Attack Simulation Script")
print("  Vectors: ATS + Overlay + C2 Network")
print("=" * 50)

if not check_adb_device():
    print("\n[!] No ADB device found. Start the emulator first.")
    exit(1)

print("\n[*] ADB device confirmed. Starting simulation in 3 seconds...")
time.sleep(3)

# ── Вектор 1: ATS ─────────────────────────────────────────
print("\n[VECTOR 1] ATS — Programmatic tap via ADB input...")
for i in range(3):
    print(f"  Tap #{i+1} (coordinates 400 600)")
    run_adb("input tap 400 600")
    time.sleep(1.5)
time.sleep(2)

# ── Вектор 2: Overlay ─────────────────────────────────────
print("\n[VECTOR 2] Overlay — launching system Settings on top of app...")
run_adb("am start -a android.settings.SETTINGS")
time.sleep(2)
run_adb("am start -n com.android.insecurebankv2/.LoginActivity")
time.sleep(2)

# ── Вектор 3: C2 Network ──────────────────────────────────
# Используем am startactivity с data URL чтобы InsecureBankv2
# сам инициировал запрос через свой DefaultHttpClient.
# Триггерим Login через автозаполнение credentials + tap на кнопку.
print("\n[VECTOR 3] C2 Network — triggering HTTP request from app process...")

# Заполняем поля через adb input text и симулируем нажатие Login
# Сначала тапаем на поле Username
run_adb("input tap 540 320")
time.sleep(0.5)
run_adb("input text 'jack'")
time.sleep(0.5)

# Тап на поле Password  
run_adb("input tap 540 450")
time.sleep(0.5)
run_adb("input text 'Jack@123'")
time.sleep(0.5)

# Нажимаем кнопку LOGIN (это легитимный клик с deviceId=0, не блокируется)
# но сетевой запрос будет перехвачен агентом
run_adb("input tap 540 560")
time.sleep(3)

print("    [*] Login request triggered — check analyzer.py for Network event")

print("\n[*] Simulation complete.")
print("[*] Check analyzer.py window for blocked events and JSON audit.")