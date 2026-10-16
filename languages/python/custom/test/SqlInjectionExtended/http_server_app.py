# Request parameters parsed by hand inside a `http.server` handler
# (pattern reduced from a deliberately vulnerable demo application).
import http.server
import re
import sqlite3
import urllib.parse

connection = sqlite3.connect(":memory:")
COLUMNS = [("users", "id")]


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # $ Source[py/sql-injection-extended]
        # `query` is defined through iterable unpacking and then read inside a
        # generator expression (a nested scope).
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (match.group("parameter"), urllib.parse.unquote(",".join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % re.escape(match.group("parameter")), query))))
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query)
        )
        cursor = connection.cursor()
        if path == "/":
            if "id" in params:
                cursor.execute("SELECT id, username FROM users WHERE id=" + params["id"])  # $ Alert[py/sql-injection-extended]
            elif "comment" in params:
                cursor.execute("INSERT INTO comments VALUES(NULL, '%s')" % (params["comment"],))  # $ Alert[py/sql-injection-extended]
            elif "safe" in params:
                # GOOD: parameter binding
                cursor.execute("SELECT id FROM users WHERE id=?", (params["safe"],))
        elif path == "/login":
            cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username", "")) + "' AND password='" + params.get("password", "") + "'")  # $ Alert[py/sql-injection-extended]

    def do_HEAD(self):
        # GOOD: unpacked values that are not user-controlled, captured in a nested scope
        table, column = COLUMNS[0]
        names = list("SELECT %s FROM %s" % (column, table) for _ in range(1))
        connection.cursor().execute(names[0])

    def do_PUT(self):  # $ Source[py/sql-injection]
        # Plain assignments are already handled by `py/sql-injection`; the extended
        # query must not report them again.
        query = self.path
        params = dict((k, query) for k in ["id"])
        connection.cursor().execute("SELECT * FROM users WHERE id=" + params["id"])  # $ Alert[py/sql-injection]

    def do_DELETE(self):  # $ Source[py/sql-injection-extended]
        # For-loop targets are also definitions without a value.
        for part in self.path.split("/"):
            stmts = ["DELETE FROM t WHERE name='" + part + "'" for _ in range(1)]
            connection.cursor().execute(stmts[0])  # $ Alert[py/sql-injection-extended]

    def do_PATCH(self):  # $ Source[py/sql-injection-extended]
        # `d.get("key")` on a dictionary whose elements are stored at unknown keys.
        query = self.path
        params = dict((k, query) for k in ["id"])
        connection.cursor().execute("SELECT * FROM users WHERE id=" + params.get("id", ""))  # $ Alert[py/sql-injection-extended]
        # GOOD: parameter binding
        connection.cursor().execute("SELECT * FROM users WHERE id=?", (params.get("id", ""),))
