package com.example.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

// CWE-256: authentication matches the submitted password against a password column.
@Controller
public class LoginController {
  private JdbcTemplate jdbcTemplate;
  private Connection connection;

  @PostMapping("/login")
  public String login(
      @RequestParam(name = "username") String username,
      @RequestParam(name = "password") String password) { // $ Source
    if (loginSuccess(username, password)) {
      return "redirect:home";
    }
    return "login";
  }

  private boolean loginSuccess(String username, String password) {
    // BAD: the password column holds plaintext passwords.
    String query =
        "SELECT * FROM users WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\"";
    Map<String, Object> result = jdbcTemplate.queryForMap(query); // $ Alert
    return result.containsKey("username");
  }

  @PostMapping("/changePassword")
  public String changePassword(
      @RequestParam(name = "username") String username,
      @RequestParam(name = "newPassword") String newPassword) // $ Source
      throws SQLException {
    PreparedStatement ps =
        connection.prepareStatement("UPDATE users SET password = ? WHERE username = ?");
    ps.setString(1, newPassword); // $ Alert
    ps.setString(2, username);
    ps.executeUpdate();
    return "ok";
  }

  @PostMapping("/signup")
  public String signup(
      @RequestParam(name = "username") String username,
      @RequestParam(name = "password") String password) { // $ Source
    // BAD: plaintext password passed as a bind parameter of a password column.
    jdbcTemplate.update("INSERT INTO users(username, pwd) VALUES (?, ?)", username, password); // $ Alert
    return "ok";
  }

  @PostMapping("/rename")
  public String rename(
      @RequestParam(name = "username") String username,
      @RequestParam(name = "newname") String newName) {
    // GOOD: no password is involved.
    jdbcTemplate.update("UPDATE users SET name = ? WHERE username = ?", newName, username);
    return "ok";
  }
}
