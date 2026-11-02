import http.server
import os
import re
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        # `query` is defined by iterable unpacking and read inside a generator expression.
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (m.group("name"), urllib.parse.unquote(",".join(re.findall(r"%s=([^&]+)" % re.escape(m.group("name")), query))))
            for m in re.finditer(r"(?P<name>\w+)=[^&]+", query)
        )
        if "tmpl" in params:
            body = params["tmpl"].format(open(__file__), os)  # $ Alert
            self.wfile.write(body.encode())
