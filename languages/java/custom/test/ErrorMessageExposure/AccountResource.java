package app;

import java.sql.SQLException;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("/account")
public class AccountResource {

  private static String lookup(String id) throws SQLException {
    throw new SQLException("syntax error near '" + id + "' in table ACCOUNTS");
  }

  @GET
  @Path("/a")
  public Response sqlMessage(String id) {
    try {
      return Response.ok().entity(lookup(id)).build();
    } catch (SQLException e) {
      return Response.serverError().entity("Error: " + e.getLocalizedMessage()).build(); // $ Alert
    }
  }

  @GET
  @Path("/b")
  public Response genericMessage(String id) {
    try {
      return Response.ok().entity(lookup(id)).build();
    } catch (Exception e) {
      return Response.serverError().entity("{Error : " + e.getMessage() + "}").build(); // $ Alert
    }
  }

  @GET
  @Path("/c")
  public Response helperMessage(String id) {
    String result = lookupOrError(id);
    return Response.ok().entity(result).build(); // $ Alert
  }

  private String lookupOrError(String id) {
    try {
      return lookup(id);
    } catch (Exception e) {
      return "Error: " + e.toString();
    }
  }

  @GET
  @Path("/d")
  public Response safeGenericMessage(String id) {
    try {
      return Response.ok().entity(lookup(id)).build();
    } catch (SQLException e) {
      System.err.println(e.getMessage());
      return Response.serverError().entity("An internal error occurred").build();
    }
  }
}
