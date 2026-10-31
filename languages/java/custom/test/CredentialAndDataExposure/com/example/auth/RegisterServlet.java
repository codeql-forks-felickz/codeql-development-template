package com.example.auth;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// CWE-256: registration persists the submitted password in cleartext.
public class RegisterServlet extends HttpServlet {
  private Connection con;
  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String user = request.getParameter("username");
    String pass = request.getParameter("password"); // $ Source
    String email = request.getParameter("email");
    try {
      Statement stmt = con.createStatement();
      // BAD: the password is written to the users table as plaintext.
      String sql =
          "INSERT into users(username, password, email) values ('"
              + user
              + "','"
              + pass
              + "','"
              + email
              + "')";
      stmt.executeUpdate(sql); // $ Alert
    } catch (SQLException ex) {
    }
  }

  protected void registerSafely(HttpServletRequest request) throws SQLException {
    String user = request.getParameter("username");
    String pass = request.getParameter("password");
    // GOOD: only a bcrypt hash of the password is stored.
    String hashed = encoder.encode(pass);
    Statement stmt = con.createStatement();
    stmt.executeUpdate(
        "INSERT into users(username, password) values ('" + user + "','" + hashed + "')");
  }

  protected void updateEmail(HttpServletRequest request) throws SQLException {
    String user = request.getParameter("username");
    String email = request.getParameter("email");
    // GOOD: no password involved.
    Statement stmt = con.createStatement();
    stmt.executeUpdate("UPDATE users SET email='" + email + "' WHERE username='" + user + "'");
  }
}
