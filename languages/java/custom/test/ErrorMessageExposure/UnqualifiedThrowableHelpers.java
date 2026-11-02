package app;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("/exception")
public class UnqualifiedThrowableHelpers extends Exception {

  @GET
  @Path("/error")
  public Response errorResponse() {
    return Response.ok()
        .entity(message() + localizedMessage() + description())
        .build(); // $ Alert
  }

  @GET
  @Path("/safe")
  public Response safeResponse() {
    return Response.ok().entity(new NonThrowableValue().render()).build();
  }

  private String message() {
    return getMessage();
  }

  private String localizedMessage() {
    return getLocalizedMessage();
  }

  private String description() {
    return toString();
  }

  private static class NonThrowableValue {
    private String render() {
      return getMessage() + getLocalizedMessage() + toString();
    }

    private String getMessage() {
      return "message";
    }

    private String getLocalizedMessage() {
      return "localized message";
    }

    @Override
    public String toString() {
      return "description";
    }
  }
}
