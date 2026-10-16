import http.server
import io
import re
import urllib.parse

import lxml.etree


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        raw = urllib.parse.unquote_to_bytes(re.search(r"xml=([^&]+)", query).group(1))

        if self.path.startswith("/unsafe-dtd"):
            parser = lxml.etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)
            doc = lxml.etree.parse(io.BytesIO(raw), parser)  # $ Alert
        elif self.path.startswith("/unsafe-kw"):
            parser = lxml.etree.XMLParser(no_network=False)
            doc = lxml.etree.fromstring(urllib.parse.unquote_to_bytes(string=query), parser=parser)  # $ Alert
        else:
            # Safe: entity resolution disabled and network access blocked.
            parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)
            doc = lxml.etree.parse(io.BytesIO(raw), parser)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(lxml.etree.tostring(doc))
