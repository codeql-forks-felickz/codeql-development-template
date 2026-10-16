package test;

import javax.servlet.http.HttpServletRequest;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.schema.SchemaManager;

// Apache Directory LDAP API (2.x) filter parsing with request data.
public class ApacheApiLdapFilter {
  public void parse(HttpServletRequest req, SchemaManager schemaManager) throws Exception {
    String user = req.getParameter("user"); // $ Source[java/ldap-injection]
    ExprNode a = FilterParser.parse("(uid=" + user + ")"); // $ Alert[java/ldap-injection]
    ExprNode b = FilterParser.parse("(uid=" + user + ")", true); // $ Alert[java/ldap-injection]
    ExprNode c = FilterParser.parse(schemaManager, "(uid=" + user + ")"); // $ Alert[java/ldap-injection]
    ExprNode d = FilterParser.parse(schemaManager, "(uid=" + user + ")", false); // $ Alert[java/ldap-injection]
    ExprNode safe = FilterParser.parse("(uid=constant)");
  }
}
