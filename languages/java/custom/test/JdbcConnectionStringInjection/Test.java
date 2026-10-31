import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Test extends HttpServlet {
  private static final Set<String> ALLOWED_DBS = Set.of("inventory", "reports");

  // BAD: the request parameter is appended to the path of the JDBC URL, so it can inject
  // driver properties such as `?allowLoadLocalInfile=true&autoDeserialize=true`.
  // (`java/ssrf` treats the `host/` prefix as sanitizing and does not report this.)
  Connection bad1(HttpServletRequest request) throws SQLException {
    String url = "jdbc:mysql://10.12.1.34/" + request.getParameter("selectedDB"); // $ Source
    return DriverManager.getConnection(url, "user", "pass"); // $ Alert
  }

  // BAD: injected into the query-string part of the URL.
  Connection bad2(HttpServletRequest request) throws SQLException {
    String opts = request.getParameter("opts"); // $ Source
    return DriverManager.getConnection("jdbc:postgresql://db.local:5432/app?" + opts); // $ Alert
  }

  // BAD: built with a StringBuilder, single-argument overload with Properties.
  Connection bad3(HttpServletRequest request) throws SQLException {
    StringBuilder sb = new StringBuilder("jdbc:mysql://10.12.1.34/");
    sb.append(request.getParameter("db")); // $ Source
    return DriverManager.getConnection(sb.toString(), new Properties()); // $ Alert
  }

  // BAD: String.format.
  Connection bad4(HttpServletRequest request) throws SQLException {
    String url = String.format("jdbc:mysql://10.12.1.34/%s", request.getParameter("db")); // $ Source
    return DriverManager.getConnection(url); // $ Alert
  }

  // NOT REPORTED HERE: the whole URL (including the host) is controlled; this is already
  // reported by `java/ssrf`, so it is excluded to avoid duplicate alerts.
  Connection ssrfDuplicate(HttpServletRequest request) throws SQLException {
    return DriverManager.getConnection(request.getParameter("url"));
  }

  // GOOD: the database name is checked against an allowlist.
  Connection good1(HttpServletRequest request) throws SQLException {
    String db = request.getParameter("selectedDB");
    if (ALLOWED_DBS.contains(db)) {
      return DriverManager.getConnection("jdbc:mysql://10.12.1.34/" + db, "user", "pass");
    }
    return null;
  }

  // GOOD: the database name is validated with a strict regular expression.
  Connection good2(HttpServletRequest request) throws SQLException {
    String db = request.getParameter("selectedDB");
    if (db.matches("[A-Za-z0-9_]+")) {
      return DriverManager.getConnection("jdbc:mysql://10.12.1.34/" + db, "user", "pass");
    }
    return null;
  }

  // GOOD: the database name is compared against a constant.
  Connection good3(HttpServletRequest request) throws SQLException {
    String db = request.getParameter("selectedDB");
    if ("reports".equals(db)) {
      return DriverManager.getConnection("jdbc:mysql://10.12.1.34/" + db, "user", "pass");
    }
    return null;
  }

  // GOOD: a numeric value cannot carry URL delimiters.
  Connection good4(HttpServletRequest request) throws SQLException {
    int shard = Integer.parseInt(request.getParameter("shard"));
    return DriverManager.getConnection("jdbc:mysql://10.12.1.34/shard" + shard, "user", "pass");
  }

  // GOOD: constant URL.
  Connection good5() throws SQLException {
    return DriverManager.getConnection("jdbc:mysql://10.12.1.34/inventory", "user", "pass");
  }
}
