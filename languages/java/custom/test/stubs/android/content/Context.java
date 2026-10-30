package android.content;

import android.content.pm.PackageManager;
import android.os.Handler;

public abstract class Context {
    public static final int CONTEXT_INCLUDE_CODE = 1;
    public static final int CONTEXT_IGNORE_SECURITY = 2;
    public static final int CONTEXT_RESTRICTED = 4;
    public static final int RECEIVER_EXPORTED = 2;
    public static final int RECEIVER_NOT_EXPORTED = 4;
    public abstract ClassLoader getClassLoader();
    public abstract PackageManager getPackageManager();
    public abstract Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException;
    public abstract void startActivity(Intent intent);
    public abstract Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter);
    public abstract Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, int flags);
    public abstract Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler);
    public abstract Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler, int flags);
    public abstract void unregisterReceiver(BroadcastReceiver receiver);
}
