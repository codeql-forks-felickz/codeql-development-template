import http.server
import traceback


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, content = self.path, "<html>"
        try:
            content += open("data.txt").read()
        except Exception:
            content = traceback.format_exc() # $ Source[py/error-message-exposure]
        finally:
            self.send_response(200)
            # A conditional expression with a short-circuiting condition, as in DSVW.
            self.send_header("Content-Type", "text/html" if path == "/" and "x" in content else "text/plain")
            self.end_headers()
            self.wfile.write(("%s%s" % (content, "</html>")).encode()) # $ Alert[py/error-message-exposure]
