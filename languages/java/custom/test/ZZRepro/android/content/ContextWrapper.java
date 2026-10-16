package android.content;

import android.content.pm.PackageManager;

public class ContextWrapper extends Context {
    public ClassLoader getClassLoader() { return null; }
    public PackageManager getPackageManager() { return null; }
    public Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException { return null; }
    public void startActivity(Intent intent) { }
}
