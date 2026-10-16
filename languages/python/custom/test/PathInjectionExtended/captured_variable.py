import http.server
import os
import re
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    def dsvw_style(self):  # $ Source
        # Reduced from the DSVW `path` parameter handling.
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        params = dict(
            (m.group("p"), urllib.parse.unquote(",".join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % re.escape(m.group("p")), query))))
            for m in re.finditer(r"(?:\A|[?&])(?P<p>\w+)=[^&]+", query)
        )
        if "path" in params:
            open(os.path.abspath(params["path"]), "rb")  # $ Alert

    def tuple_unpacking_genexp(self):  # $ Source
        _, query = self.path.split('?', 1)
        values = dict((1, query) for _ in range(1))
        open(values[1])  # $ Alert

    def tuple_unpacking_listcomp(self):  # $ Source
        _, query = self.path.split('?', 1)
        values = [query for _ in range(1)]
        open(values[0])  # $ Alert

    def tuple_unpacking_lambda(self):  # $ Source
        _, query = self.path.split('?', 1)
        read = lambda: open(query)  # $ Alert
        read()

    def for_target_captured(self):  # $ Source
        for part in self.path.split('&'):
            values = [part for _ in range(1)]
            open(values[0])  # $ Alert

    def simple_assignment_captured(self):
        # Already reported by the standard `py/path-injection` query, so not
        # reported again here.
        query = self.path.upper()
        values = dict((1, query) for _ in range(1))
        open(values[1])

    def direct_use(self):
        # Already reported by the standard `py/path-injection` query.
        _, query = self.path.split('?', 1)
        open(query)

    def constant_unpacking(self):
        _, name = ("ignored", "static.txt")
        values = dict((1, name) for _ in range(1))
        open(values[1])

    def checked_path(self):
        _, query = self.path.split('?', 1)
        values = dict((1, os.path.normpath(query)) for _ in range(1))
        safe = values[1]
        if safe.startswith("/srv/www/"):
            open(safe)
