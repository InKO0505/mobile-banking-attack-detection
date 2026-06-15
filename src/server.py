import threading
from flask import Flask, request, jsonify

bank_app = Flask("bank")
c2_app   = Flask("c2")


@bank_app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@bank_app.route("/<path:path>", methods=["GET", "POST"])
def bank_handler(path):
    print(f"[BANK:8888] {request.method} /{path}  form={request.form.to_dict()}")
    return jsonify({"message": "ok", "token": "fake_jwt_token"})


@c2_app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@c2_app.route("/<path:path>", methods=["GET", "POST"])
def c2_handler(path):
    print(f"[C2:9999] EXFILTRATION: /{path}  args={request.args.to_dict()}", flush=True)
    return jsonify({"status": "received"})


def run_c2():
    c2_app.run(host="0.0.0.0", port=9999, use_reloader=False, debug=False)


if __name__ == "__main__":
    t = threading.Thread(target=run_c2, daemon=True)
    t.start()
    bank_app.run(host="0.0.0.0", port=8888, use_reloader=False, debug=False)
