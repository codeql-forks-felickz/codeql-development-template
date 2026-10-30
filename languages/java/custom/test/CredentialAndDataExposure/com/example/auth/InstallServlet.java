package com.example.auth;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class InstallServlet extends HttpServlet {
  private Connection con;

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String adminuser = request.getParameter("adminuser");
    // BAD: MD5 is a fast hash (alert reported inside HashMe.hashMe).
    String adminpass = HashMe.hashMe(request.getParameter("adminpass")); // $ Source
    try {
      Statement stmt = con.createStatement();
      // The value stored here is an MD5 hash, so no cleartext storage alert.
      stmt.executeUpdate(
          "INSERT into users(username, password) values ('" + adminuser + "','" + adminpass + "')");
    } catch (SQLException ex) {
    }
  }
}
