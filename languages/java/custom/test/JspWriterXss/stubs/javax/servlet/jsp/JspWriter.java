package javax.servlet.jsp;

public abstract class JspWriter extends java.io.Writer {
  public abstract void print(String s) throws java.io.IOException;

  public abstract void print(int i) throws java.io.IOException;

  public abstract void print(Object o) throws java.io.IOException;

  public abstract void println(String s) throws java.io.IOException;
}
