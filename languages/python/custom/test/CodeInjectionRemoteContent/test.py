import http.server
import re
import urllib.parse
import urllib.request

import httpx
import requests
from flask import Flask, request  # $ Source

app = Flask(__name__)

FETCH = lambda url: urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "x"}))


@app.route("/include")
def include_urlopen():
    url = request.args["include"]
    body = urllib.request.urlopen(url).read()
    exec(body)  # $ Alert


@app.route("/include-with")
def include_urlopen_with():
    with urllib.request.urlopen(request.args["include"]) as resp:
        program = resp.read()
    exec(program)  # $ Alert


@app.route("/include-requests")
def include_requests():
    # Already reported by the standard `py/code-injection` query (`requests` is modeled upstream), so not reported here.
    eval(requests.get(request.args["include"]).text)


@app.route("/include-requests-content")
def include_requests_content():
    resp = requests.get("https://" + request.args["host"] + "/plugin.py")
    # Already reported by the standard `py/code-injection` query (`requests` is modeled upstream), so not reported here.
    exec(compile(resp.content, "<remote>", "exec"))


@app.route("/include-httpx")
def include_httpx():
    resp = httpx.get(request.args["include"])
    exec(resp.text)  # $ Alert


@app.route("/direct")
def direct():
    # Already reported by the standard `py/code-injection` query, so not reported here.
    exec(request.args["code"])


@app.route("/static-url")
def static_url():
    # URL is not attacker controlled.
    exec(urllib.request.urlopen("https://example.com/plugin.py").read())


@app.route("/static-file")
def static_file():
    exec(open("static_template.py").read())


@app.route("/allowlisted")
def allowlisted():
    url = request.args["include"]
    if url == "https://example.com/plugin.py":
        exec(urllib.request.urlopen(url).read())


@app.route("/not-executed")
def not_executed():
    body = urllib.request.urlopen(request.args["include"]).read()
    return body


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict((match.group("parameter"), urllib.parse.unquote(match.group("value"))) for match in re.finditer(r"(?P<parameter>\w+)=(?P<value>[^&]+)", query))
        if "include" in params:
            program = (open(params["include"], "rb") if not "://" in params["include"] else FETCH(params["include"])).read()
            exec(program, {})  # $ Alert
