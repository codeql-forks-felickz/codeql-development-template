package javax.mail;

public abstract class Message {
  public abstract void setSubject(String subject);
  public abstract void setHeader(String name, String value);
  public abstract void addHeader(String name, String value);
}
