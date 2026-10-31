import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer


class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        content = "<html>"
        code = 200
        try:
            content += open("data.txt").read()
        except Exception:
            content = traceback.format_exc() # $ Source[py/error-message-exposure]
            code = 500
        finally:
            self.send_response(code)
            self.end_headers()
            self.wfile.write(("%s</html>" % content).encode()) # $ Alert[py/error-message-exposure]

    def do_POST(self):
        try:
            length = int(self.headers["Content-Length"])
        except ValueError as ex: # $ Source[py/error-message-exposure]
            self.send_response(400)
            self.end_headers()
            self.wfile.write(str(ex).encode()) # $ Alert[py/error-message-exposure]
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok %d" % length)

    def do_HEAD(self):
        code, content = 200, "<html>"
        try:
            content += open("data.txt").read()
        except Exception as ex:
            output = ex.output if hasattr(ex, "output") else None
            content, code = traceback.format_exc() if output is None else output, 500 # $ Source[py/error-message-exposure]
        finally:
            self.send_response(code)
            self.end_headers()
            self.wfile.write(b"" if self.command == "HEAD" else ("%s%s" % (content, "</html>")).encode()) # $ Alert[py/error-message-exposure]

    def do_PUT(self):
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            # Safe: details are logged server-side and only a generic message is sent.
            sys.stderr.write(traceback.format_exc())
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal server error")


class NotAHandler:
    def __init__(self, wfile):
        self.wfile = wfile

    def report(self):
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            # Safe: not an HTTP request handler, so not exposed to an HTTP client.
            self.wfile.write(traceback.format_exc().encode())


if __name__ == "__main__":
    HTTPServer(("", 8000), ReqHandler).serve_forever()
