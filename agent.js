Script.nextTick(function() {
    Java.perform(function () {
        send({"type": "info", "message": "RASP Agent injected. Installing hooks..."});

        // Легитимные хосты банковского приложения
        // Всё что не входит в этот список — подозрительно
        var TRUSTED_HOSTS = ["10.0.2.2", "localhost", "127.0.0.1"];

        function isTrusted(url) {
            for (var i = 0; i < TRUSTED_HOSTS.length; i++) {
                if (url.indexOf(TRUSTED_HOSTS[i]) !== -1) return true;
            }
            return false;
        }

        // HOOK 1: ATS Bot Detection
        try {
            var View = Java.use("android.view.View");
            View.dispatchTouchEvent.implementation = function (ev) {
                var deviceId = ev.getDeviceId();
                if (deviceId < 0) {
                    send({
                        "type":    "critical",
                        "threat":  "ATS Bot Activity",
                        "message": "Programmatic click BLOCKED! Source: " + ev.getSource() + ", DeviceID: " + deviceId
                    });
                    return true;
                }
                return this.dispatchTouchEvent(ev);
            };
            send({"type": "info", "message": "Hook #1 (ATS / View.dispatchTouchEvent) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #1 failed: " + e.message});
        }

        // HOOK 2: Overlay Detection
        try {
            var Activity = Java.use("android.app.Activity");
            Activity.onWindowFocusChanged.implementation = function (hasFocus) {
                if (!hasFocus) {
                    var isKeyboard = false;
                    try {
                        isKeyboard = this.getWindow().getDecorView()
                            .getRootWindowInsets()
                            .isVisible(Java.use("android.view.WindowInsets$Type").ime());
                    } catch(e2) {}
                    if (!isKeyboard) {
                        send({
                            "type":    "alert",
                            "threat":  "Overlay Attack",
                            "message": "Window focus lost — possible overlay covering the screen."
                        });
                    }
                }
                this.onWindowFocusChanged(hasFocus);
            };
            send({"type": "info", "message": "Hook #2 (Overlay / onWindowFocusChanged) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #2 failed: " + e.message});
        }

        // HOOK 3a: DefaultHttpClient — перехват всех HTTP-запросов
        // Легитимные запросы к серверу банка логируются как INFO
        // Запросы на посторонние хосты — CRITICAL (C2 exfiltration)
        try {
            var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
            DefaultHttpClient.execute.overload(
                "org.apache.http.client.methods.HttpUriRequest"
            ).implementation = function (request) {
                var url = request.getURI().toString();
                var method = request.getMethod();

                if (isTrusted(url)) {
                    send({
                        "type":    "warning",
                        "threat":  "Network Request",
                        "message": "Legitimate: HTTP " + method + " → " + url
                    });
                } else {
                    send({
                        "type":    "critical",
                        "threat":  "C2 Exfiltration",
                        "message": "SUSPICIOUS: HTTP " + method + " → " + url + " [NOT a bank server!]"
                    });
                }
                return this.execute(request);
            };
            send({"type": "info", "message": "Hook #3a (Network / DefaultHttpClient.execute) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #3a failed: " + e.message});
        }

        // HOOK 3b: URL.$init — ловим создание любого URL изнутри процесса
        try {
            var URL = Java.use("java.net.URL");
            URL.$init.overload("java.lang.String").implementation = function (url) {
                if (!isTrusted(url)) {
                    send({
                        "type":    "critical",
                        "threat":  "C2 Exfiltration",
                        "message": "SUSPICIOUS URL created: " + url + " [NOT a bank server!]"
                    });
                }
                this.$init(url);
            };
            send({"type": "info", "message": "Hook #3b (Network / URL.$init) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #3b failed: " + e.message});
        }

        send({"type": "info", "message": "=== All hooks active. Monitoring started. ==="});
    });
});