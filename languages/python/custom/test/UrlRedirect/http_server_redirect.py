import http.server
import re
import urllib.parse


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)

        if self.path.startswith("/redir"):
            # BAD: query parameter copied straight into the Location header
            target = params["redir"][0]
            self.send_response(302)
            self.send_header("Location", target)  # $ Alert
            self.end_headers()
        elif self.path.startswith("/redir-lower"):
            # BAD: header names are case-insensitive
            self.send_response(302)
            self.send_header("location", params["next"][0])  # $ Alert
            self.end_headers()
        elif self.path.startswith("/safe-prefix"):
            # GOOD: user input only controls the suffix of the URL
            self.send_response(302)
            self.send_header("Location", "/static/" + params["page"][0])
            self.end_headers()
        elif self.path.startswith("/safe-allowlist"):
            # GOOD: redirect target is checked against an allowlist
            target = params["next"][0]
            if target in ["/home", "/profile"]:
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
        elif self.path.startswith("/safe-constant"):
            # GOOD: constant redirect target
            self.send_response(302)
            self.send_header("Location", "/home")
            self.end_headers()
        else:
            # GOOD: user input in a header that is not a redirect location
            self.send_response(200)
            self.send_header("X-Requested-Page", params["page"][0])
            self.end_headers()


LATIN1 = lambda value: value.encode("latin-1", "replace").decode("latin-1")


class DsvwStyleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        # `query` is defined by tuple unpacking and then read inside a generator expression
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (match.group("parameter"), urllib.parse.unquote(",".join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % re.escape(match.group("parameter")), query))))
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query)
        )
        self.send_response(302 if "redir" in params else 200)
        if "redir" in params:
            # BAD: same pattern as the DSVW "Unvalidated Redirect" case
            self.send_header("Location", LATIN1(params["redir"]))  # $ Alert
        self.send_header("Connection", "close")
        self.end_headers()


class UnpackedConstantHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # GOOD: unpacked values read in a nested scope are constants, not user input
        path, query = "/", "next=/home"
        params = dict(part.split("=", 1) for part in [query])
        self.send_response(302)
        self.send_header("Location", params["next"])
        self.end_headers()
