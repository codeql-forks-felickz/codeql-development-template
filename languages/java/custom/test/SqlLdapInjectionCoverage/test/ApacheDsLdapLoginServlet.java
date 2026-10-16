package test;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.directory.server.core.CoreSession;
import org.apache.directory.server.core.filtering.EntryFilteringCursor;
import org.apache.directory.shared.ldap.filter.ExprNode;
import org.apache.directory.shared.ldap.filter.FilterParser;
import org.apache.directory.shared.ldap.filter.SearchScope;
import org.apache.directory.shared.ldap.message.AliasDerefMode;
import org.apache.directory.shared.ldap.name.LdapDN;

// Embedded ApacheDS 1.5.x (shared-ldap) login that builds the filter string by concatenation.
public class ApacheDsLdapLoginServlet extends HttpServlet {
  private CoreSession adminSession;

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    String uid = req.getParameter("userid"); // $ Source[java/ldap-injection]
    String password = req.getParameter("password"); // $ Source[java/ldap-injection]
    authUser(uid, password);
    authUserSafe(uid, password);
  }

  protected boolean authUser(String uid, String password) {
    try {
      String filterString = "(&(uid=" + uid.trim() + ")(userPassword=" + password.trim() + "))";
      ExprNode filter = FilterParser.parse(filterString); // $ Alert[java/ldap-injection]
      EntryFilteringCursor cursor =
          adminSession.search(
              new LdapDN("ou=people,dc=example,dc=org"),
              SearchScope.SUBTREE,
              filter,
              AliasDerefMode.NEVER_DEREF_ALIASES,
              null);
      return cursor.available();
    } catch (Exception e) {
      return false;
    }
  }

  protected boolean authUserSafe(String uid, String password) {
    try {
      ExprNode filter =
          FilterParser.parse(
              "(&(uid=" + encodeForLdap(uid) + ")(userPassword=" + encodeForLdap(password) + "))");
      return adminSession
          .search(
              new LdapDN("ou=people,dc=example,dc=org"),
              SearchScope.SUBTREE,
              filter,
              AliasDerefMode.NEVER_DEREF_ALIASES,
              null)
          .available();
    } catch (Exception e) {
      return false;
    }
  }

  // A hard-coded, fixed-length placeholder stands in for an LDAP encoder in this test.
  private static String encodeForLdap(String value) {
    return "x";
  }
}
