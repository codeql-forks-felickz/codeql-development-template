from flask import Flask, Response, make_response

app = Flask(__name__)


@app.after_request
def add_security_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # $ Alert
    response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"  # $ Alert
    return response


@app.route("/default-src")
def default_src():
    resp = Response("ok")
    resp.headers["content-security-policy"] = "default-src 'self' 'unsafe-inline'; img-src *"  # $ Alert
    resp.headers.set("access-control-allow-origin", "null")  # $ Alert
    return resp


@app.route("/bulk")
def bulk():
    return make_response("ok", 200, {"Access-Control-Allow-Origin": "*"})  # $ Alert


@app.route("/safe")
def safe():
    resp = Response("ok")
    # Explicitly trusted origin: not flagged.
    resp.headers["Access-Control-Allow-Origin"] = "https://trusted.example.com"
    # Nonce-based script-src: 'unsafe-inline' is ignored by CSP2+ browsers, not flagged.
    resp.headers["Content-Security-Policy"] = "script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'"
    # 'unsafe-inline' restricted to styles only: not flagged.
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    # script-src overrides default-src for scripts: not flagged.
    resp.headers["Content-Security-Policy"] = "default-src 'unsafe-inline'; script-src 'self'"
    # Unrelated header: not flagged.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp
