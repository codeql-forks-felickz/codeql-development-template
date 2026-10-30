package org.example.jaxrs;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

// Transaction search: JAX-RS request body parsed with Apache Wink JSON4J, start and end dates
// concatenated into a SQL predicate inside a static DB helper.
@Path("/account")
public class AccountApi {
  @POST
  @Path("/{accountNo}/transactions")
  public String getTransactions(
      @PathParam("accountNo") String accountNo, String bodyJSON) // $ Source
      throws Exception {
    JSONObject myJson = new JSONObject(bodyJSON);
    String startString = (String) myJson.get("startDate");
    String endString = myJson.getString("endDate");
    return DbUtil.getTransactions(startString, endString);
  }

  static class DbUtil {
    static Connection connection;

    static String getTransactions(String startDate, String endDate) throws Exception {
      Statement statement = connection.createStatement();
      String dateString = "";
      if (startDate != null && startDate.length() > 0 && endDate != null && endDate.length() > 0) {
        dateString = "DATE BETWEEN '" + startDate + " 00:00:00' AND '" + endDate + " 23:59:59'";
      }
      String query = "SELECT * FROM TRANSACTIONS WHERE " + dateString;
      ResultSet resultSet = statement.executeQuery(query); // $ Alert
      return resultSet.toString();
    }
  }
}
