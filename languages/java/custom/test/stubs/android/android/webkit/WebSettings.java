package android.webkit;

public abstract class WebSettings {
  public abstract boolean getJavaScriptEnabled();

  public abstract void setJavaScriptEnabled(boolean flag);

  public abstract boolean getAllowFileAccess();

  public abstract void setAllowFileAccess(boolean allow);

  public abstract boolean getAllowContentAccess();

  public abstract void setAllowContentAccess(boolean allow);

  public abstract boolean getAllowFileAccessFromFileURLs();

  public abstract void setAllowFileAccessFromFileURLs(boolean flag);

  public abstract boolean getAllowUniversalAccessFromFileURLs();

  public abstract void setAllowUniversalAccessFromFileURLs(boolean flag);
}
