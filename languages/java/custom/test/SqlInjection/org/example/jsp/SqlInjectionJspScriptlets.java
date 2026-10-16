package org.example.jsp;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Java equivalents of JSP scriptlets (as a JSP compiler would translate them into a servlet's
 * service method) that concatenate request parameters and session values into JDBC queries.
 */
public class SqlInjectionJspScriptlets extends HttpServlet {
  private Connection con;

  // Admin login: username and MD5-hashed password concatenated into a SELECT.
  public void adminLogin(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    String user = request.getParameter("username"); // $ Source
    String pass = HashMe.hashMe(request.getParameter("password"));
    Statement stmt = con.createStatement();
    String query =
        "select * from users where username='" + user + "' and password='" + pass + "'";
    ResultSet rs = stmt.executeQuery(query); // $ Alert
  }

  // File download: fileid parameter concatenated into a SELECT.
  public void downloadById(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    String fileid = request.getParameter("fileid"); // $ Source
    if (fileid != null && !fileid.equals("")) {
      Statement stmt = con.createStatement();
      ResultSet rs = stmt.executeQuery("select * from FilesList where fileid=" + fileid); // $ Alert
    }
  }

  // Password change: password1 parameter and session username concatenated into an UPDATE.
  public void changePassword(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    HttpSession session = request.getSession();
    String username = (String) session.getAttribute("username");
    String password1 = (String) request.getParameter("password1"); // $ Source
    String password2 = (String) request.getParameter("password2");
    if (password1 != null && password1.length() > 0 && password1.equals(password2)) {
      Statement stmt = con.createStatement();
      String query = "UPDATE Users set password= '" + password1 + "' where name = '" + username + "'";
      stmt.executeQuery(query); // $ Alert
    }
  }

  // Issue example.
  public void issueExample(HttpServletRequest request, Statement stmt) throws Exception {
    String q = "SELECT * FROM users WHERE name = '" + request.getParameter("u") + "'"; // $ Source
    stmt.executeQuery(q); // $ Alert
  }
}
