package javax.mail;

public class MimeMessage extends Message {
  public MimeMessage() {}

  @Override
  public void setSubject(String subject) {}

  public void setSubject(String subject, String charset) {}

  @Override
  public void setHeader(String name, String value) {}

  @Override
  public void addHeader(String name, String value) {}
}
