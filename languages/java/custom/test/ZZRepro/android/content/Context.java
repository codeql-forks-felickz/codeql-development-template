package android.content;

import android.content.pm.PackageManager;

public abstract class Context {
    public static final int CONTEXT_INCLUDE_CODE = 1;
    public static final int CONTEXT_IGNORE_SECURITY = 2;
    public static final int CONTEXT_RESTRICTED = 4;
    public abstract ClassLoader getClassLoader();
    public abstract PackageManager getPackageManager();
    public abstract Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException;
    public abstract void startActivity(Intent intent);
}
