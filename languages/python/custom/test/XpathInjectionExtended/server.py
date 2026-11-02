import http.server
import io
import re
import urllib.parse

import lxml.etree

USERS_XML = "<users><user><name>alice</name><password>secret</password></user></users>"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source
        # `query` is defined by iterable unpacking and then read inside a generator expression.
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (m.group("name"), urllib.parse.unquote(",".join(re.findall(r"%s=([^&]+)" % re.escape(m.group("name")), query))))
            for m in re.finditer(r"(?P<name>\w+)=[^&]+", query)
        )
        doc = lxml.etree.parse(io.BytesIO(USERS_XML.encode()))
        if "name" in params:
            doc.xpath(".//user[name/text()='%s']" % params["name"])  # $ Alert
            # Safe: the value is passed as an XPath variable, not interpolated.
            doc.xpath(".//user[name/text()=$name]", name=params["name"])

    def do_POST(self):  # $ Source
        # Read in a nested function.
        _, value = self.path.split("=", 1)

        def lookup():
            doc = lxml.etree.parse(io.BytesIO(USERS_XML.encode()))
            return doc.xpath("//user[name='" + value + "']")  # $ Alert

        return lookup()

    def do_PUT(self):  # $ Source
        # Read in a list comprehension.
        _, value = self.path.split("=", 1)
        doc = lxml.etree.parse(io.BytesIO(USERS_XML.encode()))
        return [doc.xpath("//user[name='%s']" % value) for _ in range(1)]  # $ Alert

    def do_DELETE(self):
        # Safe: the unpacked value is not used in the XPath expression.
        _, value = self.path.split("=", 1)
        doc = lxml.etree.parse(io.BytesIO(USERS_XML.encode()))
        return [doc.xpath("//user[name='admin']") for _ in [value]]

    def do_PATCH(self):  # $ Source
        # Already reported by `py/xpath-injection`: no nested scope involved.
        _, value = self.path.split("=", 1)
        doc = lxml.etree.parse(io.BytesIO(USERS_XML.encode()))
        return doc.xpath("//user[name='%s']" % value)  # $ Alert
