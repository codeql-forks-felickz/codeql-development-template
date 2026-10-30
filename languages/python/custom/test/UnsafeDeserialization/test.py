import base64
import http.server
import json
import pickle
import re
import urllib.parse


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        # NON_COMPLIANT: query parameter decoded with `unquote_to_bytes` and unpickled
        pickle.loads(urllib.parse.unquote_to_bytes(re.search(r"(?:\A|[?&])object=([^&]+)", query).group(1)))
        # NON_COMPLIANT: `unquote_to_bytes` with keyword argument
        pickle.loads(urllib.parse.unquote_to_bytes(string=query))
        # COMPLIANT: safe deserializer
        json.loads(urllib.parse.unquote_to_bytes(query))
        # COMPLIANT: constant input
        pickle.loads(urllib.parse.unquote_to_bytes("abc"))


class ParamsHandler(http.server.BaseHTTPRequestHandler):
    def parse_params(self):
        self.params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

    def do_GET(self):
        self.parse_params()
        # NON_COMPLIANT: request parameter base64-decoded and unpickled
        pickle.loads(base64.b64decode(self.params["object"][0]))
        # COMPLIANT: safe deserializer
        json.loads(base64.b64decode(self.params["object"][0]))
