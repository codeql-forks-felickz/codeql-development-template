package org.example.spring.bio;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseManager {
  private Connection connection;

  // Not SQL injection: `userId` is an `int`, so `Integer.parseInt` in the controller rejects any
  // non-numeric input before this query is built.
  public Bio getBio(int userId) {
    try {
      String selectStatement = "SELECT * FROM bio WHERE user_id = " + userId + ";";
      Statement statement = connection.createStatement();
      ResultSet rs = statement.executeQuery(selectStatement);
      if (rs.next()) {
        return new Bio(rs.getInt("id"), rs.getInt("user_id"), rs.getString("bio_text"));
      }
    } catch (SQLException e) {
    }
    return null;
  }

  public boolean insertBio(Bio bio) {
    try {
      String insertStatement =
          "INSERT INTO bio (user_id, bio_text) VALUES ("
              + bio.getUserId()
              + ", '"
              + bio.getBioText()
              + "');";
      return connection.createStatement().executeUpdate(insertStatement) > 0; // $ Alert
    } catch (SQLException e) {
      return false;
    }
  }

  public boolean updateBio(Bio bio) {
    try {
      String updateStatement =
          "UPDATE bio SET bio_text = '" + bio.getBioText() + "' WHERE user_id = " + bio.getUserId();
      return connection.createStatement().executeUpdate(updateStatement) > 0; // $ Alert
    } catch (SQLException e) {
      return false;
    }
  }
}
