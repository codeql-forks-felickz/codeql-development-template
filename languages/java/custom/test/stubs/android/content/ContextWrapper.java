package android.content;

import android.content.pm.PackageManager;
import android.os.Handler;

public class ContextWrapper extends Context {
    public ClassLoader getClassLoader() { return null; }
    public PackageManager getPackageManager() { return null; }
    public Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException { return null; }
    public void startActivity(Intent intent) { }
    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, int flags) { return null; }
    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler) { return null; }
    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler, int flags) { return null; }
    public void unregisterReceiver(BroadcastReceiver receiver) { }
}
