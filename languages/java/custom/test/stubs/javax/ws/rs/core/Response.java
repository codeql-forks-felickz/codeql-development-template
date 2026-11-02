package javax.ws.rs.core;

public abstract class Response {
  public static ResponseBuilder ok() { return null; }

  public static ResponseBuilder serverError() { return null; }

  public abstract static class ResponseBuilder {
    public abstract Response build();

    public abstract ResponseBuilder entity(Object entity);
  }
}
