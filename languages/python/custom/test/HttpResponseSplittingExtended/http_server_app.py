import http.server
import re
import urllib.parse

LATIN1, PORT = (lambda value: value.encode("latin-1", "replace").decode("latin-1")), 8080


def parse(query):
    return dict((m.group("k"), urllib.parse.unquote(m.group("v"))) for m in re.finditer(r"(?P<k>\w+)=(?P<v>[^&]+)", query))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        code, params = 200, dict((m.group("k"), urllib.parse.unquote(m.group("v"))) for m in re.finditer(r"(?P<k>\w+)=(?P<v>[^&]+)", query))
        self.send_response(code)

        # BAD: `dict.get` on a dict built from (key, value) pairs.
        self.send_header("Content-Type", "text/html; charset=%s" % params.get("charset", "utf8"))  # $ Alert
        self.send_header("X-Lang", params.get("lang"))  # $ Alert

        # BAD: dict comprehension with non-literal keys. Not detected: `codeql/python-all`
        # models dict comprehensions as a list of (key, value) tuples, not as dictionary content.
        comp = {m.group(1): m.group(2) for m in re.finditer(r"(\w+)=(\w+)", query)}
        self.send_header("X-Comp", comp.get("x", ""))  # $ MISSING: Alert

        # BAD: dict built in a helper function.
        self.send_header("X-Helper", parse(query).get("y", ""))  # $ Alert

        # BAD: already reported by the stock query (subscript read).
        self.send_header("X-Sub", params["z"])  # $ Alert

        # BAD: `query` (bound by tuple unpacking) is read inside the generator expression,
        # i.e. from a nested scope (DSVW pattern).
        dsvw = dict((m.group("k"), urllib.parse.unquote(",".join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % re.escape(m.group("k")), query)))) for m in re.finditer(r"(?P<k>\w+)=", query))
        self.send_header("Location", LATIN1(dsvw["redir"]))  # $ Alert
        self.send_header("Content-Type", LATIN1("text/plain; charset=%s" % dsvw.get("charset", "utf8")))  # $ Alert

        # BAD: tuple-unpacked variable read from an inner function.
        def inner():
            return query

        self.send_header("X-Inner", inner())  # $ Alert

        # GOOD: line breaks removed before writing the header.
        self.send_header("X-Safe", params.get("charset", "utf8").replace("\n", "").replace("\r", ""))

        # GOOD: constant dict, `get` returns only constants.
        fixed = dict([("charset", "utf8")])
        self.send_header("X-Const", fixed.get("charset", "latin-1"))

        # GOOD: allow-list lookup keyed by user input returns constant values.
        allowed = {"utf8": "utf-8", "latin1": "iso-8859-1"}
        self.send_header("X-Allowed", allowed.get(params.get("charset"), "utf-8"))

        # GOOD: tuple-unpacked constants read from a nested scope.
        lang, region = "en", "US"
        self.send_header("X-Locale", dict((k, lang + "-" + region) for k in ["locale"]).get("locale", ""))
        self.end_headers()
