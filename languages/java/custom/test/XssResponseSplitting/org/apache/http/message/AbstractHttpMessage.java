package org.apache.http.message;

import org.apache.http.Header;
import org.apache.http.HttpMessage;

public abstract class AbstractHttpMessage implements HttpMessage {
  public void addHeader(Header header) {}

  public void addHeader(String name, String value) {}

  public void setHeader(Header header) {}

  public void setHeader(String name, String value) {}
}
