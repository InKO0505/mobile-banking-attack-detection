# server.py — сохрани в ~/Diploma_Mobile_Security/
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
@app.route('/exfiltrate', methods=['GET', 'POST'])
def c2():
    print(f"[C2 SERVER] !!! Data exfiltration attempt: {request.args}")
    return "ok"
def catch_all(path):
    print(f"[SERVER] Request: {request.method} /{path}")
    return jsonify({"message": "ok"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)

 