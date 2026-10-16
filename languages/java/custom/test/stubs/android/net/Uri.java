package android.net;

public abstract class Uri {
    public abstract String getQueryParameter(String key);
    public abstract String getHost();
    public abstract String getScheme();
    public abstract String getPath();
    public static Uri parse(String uriString) { return null; }
}
