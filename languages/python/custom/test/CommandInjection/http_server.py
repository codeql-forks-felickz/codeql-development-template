import http.server
import os
import re
import subprocess
import urllib.parse


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        # Query string obtained through tuple unpacking, then captured by a generator expression.
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (match.group("parameter"), urllib.parse.unquote(",".join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % re.escape(match.group("parameter")), query))))
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query)
        )
        if "domain" in params:
            subprocess.run("nslookup " + params["domain"], shell=True)  # $ Alert
            subprocess.check_output("nslookup " + params["domain"], shell=True)  # $ Alert
            # Argument list without a shell is not a command injection.
            subprocess.check_output(["nslookup", params["domain"]])  # OK

    def do_POST(self):  # $ Source
        # Parameters parsed with `urllib.parse.parse_qsl`.
        query = urllib.parse.urlparse(self.path).query
        params = dict(urllib.parse.parse_qsl(query))
        os.system("ping -c 1 " + params["host"])  # $ Alert
        for key, value in urllib.parse.parse_qsl(query):
            if key == "cmd":
                os.system(value)  # $ Alert

    def do_PUT(self):  # $ Source
        # Tuple unpacking captured by a lambda.
        _, query = self.path.split("?", 1)
        run = lambda: os.system("echo " + query)  # $ Alert
        run()

    def do_DELETE(self):
        # Constant values are not user controlled.
        _, query = ("/", "safe")
        params = dict((k, query) for k in ["a"])
        os.system("echo " + params["a"])  # OK
