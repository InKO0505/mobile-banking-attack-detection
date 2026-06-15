import subprocess
import sys
import time

ADB = ["adb", "shell"]


def adb(*args):
    subprocess.run(ADB + list(args), check=False)


# ── attack vectors ──────────────────────────────────────────────────────────

def run_ats():
    print("[1/3] ATS simulation — 6x programmatic taps via adb input tap")
    for _ in range(6):
        adb("input", "tap", "400", "600")
        time.sleep(0.5)


def run_overlay_proxy():
    print("[2/3] Overlay-proxy simulation — launching Settings then returning to app")
    adb("am", "start", "-a", "android.settings.SETTINGS")
    time.sleep(2)
    adb("am", "start", "-n", "com.android.insecurebankv2/.LoginActivity")


def run_c2():
    print("[3/3] C2 trigger — creating /data/local/tmp/c2_trigger on device")
    adb("touch", "/data/local/tmp/c2_trigger")


def run_real_overlay():
    print("[+] Vector 2b: Real overlay APK (FLAG_WINDOW_IS_OBSCURED)")
    # Ensure overlay app is fully dead (clear any stale task in back-stack)
    adb("am", "force-stop", "kz.aitu.overlaytest")
    time.sleep(1)
    # Ensure banking app is in foreground
    adb("am", "start", "--activity-clear-task", "-n",
        "com.android.insecurebankv2/.LoginActivity")
    time.sleep(2)
    # Launch overlay app fresh — OverlayService adds a MATCH_PARENT
    # TYPE_APPLICATION_OVERLAY | FLAG_NOT_FOCUSABLE | FLAG_NOT_TOUCHABLE window.
    # MainActivity finishes after 2 s (postDelayed), leaving OverlayService running.
    adb("am", "start", "--activity-clear-task", "-n",
        "kz.aitu.overlaytest/.MainActivity")
    time.sleep(3)   # wait for postDelayed finish (2 s) + service window to attach
    # Bring banking app back to foreground — the overlay service window (TYPE_APPLICATION_OVERLAY)
    # remains on top even though InsecureBankv2 is the focused activity window.
    adb("am", "start", "--activity-clear-task", "-n",
        "com.android.insecurebankv2/.LoginActivity")
    time.sleep(1)   # wait for LoginActivity to receive focus
    # Tap through the overlay onto InsecureBankv2.  InputDispatcher sets
    # FLAG_WINDOW_IS_OBSCURED = 0x1 on the MotionEvent because an untrusted
    # TYPE_APPLICATION_OVERLAY window is visible above the target → Hook #2b fires.
    adb("input", "tap", "540", "800")
    time.sleep(0.5)
    adb("input", "tap", "540", "800")  # second tap for redundancy
    time.sleep(1)
    adb("am", "force-stop", "kz.aitu.overlaytest")
    time.sleep(1)


# ── entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "all"

    if scenario == "all":
        run_ats()
        run_overlay_proxy()
        run_c2()
    elif scenario == "real_overlay":
        run_real_overlay()
    elif scenario == "ats":
        run_ats()
    elif scenario == "overlay":
        run_overlay_proxy()
    elif scenario == "c2":
        run_c2()
    else:
        print(f"[!] Unknown scenario: {scenario}", file=sys.stderr)
        sys.exit(1)

    print("[*] Attack vectors executed.")
