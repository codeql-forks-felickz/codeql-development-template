package android.webkit;

public abstract class WebSettings {
    public abstract void setJavaScriptEnabled(boolean flag);
    public abstract void setAllowFileAccess(boolean allow);
    public abstract void setAllowFileAccessFromFileURLs(boolean flag);
    public abstract void setAllowUniversalAccessFromFileURLs(boolean flag);
    public abstract boolean getJavaScriptEnabled();
    public abstract boolean getAllowUniversalAccessFromFileURLs();
}
