package com.example;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginValidator extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String user = request.getParameter("username").trim();
    String pass = request.getParameter("password").trim();
    if (request.getParameter("RememberMe") != null) {
      Cookie username = new Cookie("username", user);
      Cookie password = new Cookie("password", pass);
      response.addCookie(username);
      response.addCookie(password); // $ Alert
    }
  }
}
