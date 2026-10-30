package org.example.spring;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

public class SqlInjectionSpringControllers {
  // Employee search: @RestController + @PostMapping, name and auth_tan concatenated into a SELECT
  // that runs through an updatable Statement.
  @RestController
  public static class EmployeeSearch {
    private Connection connection;

    @PostMapping("/attack8")
    public String completed(
        @RequestParam String name, // $ Source
        @RequestParam String auth_tan) // $ Source
        throws Exception {
      return search(name, auth_tan);
    }

    protected String search(String name, String auth_tan) throws Exception {
      String query =
          "SELECT * FROM employees WHERE last_name = '" + name + "' AND auth_tan = '" + auth_tan + "'";
      Statement statement =
          connection.createStatement(
              ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
      ResultSet results = statement.executeQuery(query); // $ Alert
      return results.toString();
    }
  }

  // Blabber listing: @Controller + @RequestMapping, sort parameter appended to ORDER BY and passed
  // to prepareStatement (bind parameters do not protect the concatenated part).
  @Controller
  public static class BlabberList {
    private Connection connect;

    @RequestMapping(value = "/blabbers", method = RequestMethod.GET)
    public String showBlabbers(
        @RequestParam(value = "sort", required = false) String sort) // $ Source
        throws Exception {
      if (sort == null || sort.isEmpty()) {
        sort = "blab_name ASC";
      }
      String blabbersSql =
          "SELECT users.username FROM users WHERE users.username NOT IN (\"admin\",?)"
              + " ORDER BY "
              + sort
              + ";";
      PreparedStatement blabberQuery = connect.prepareStatement(blabbersSql); // $ Alert
      blabberQuery.setString(1, "user");
      ResultSet blabbersResults = blabberQuery.executeQuery();
      return "blabbers";
    }
  }
}
