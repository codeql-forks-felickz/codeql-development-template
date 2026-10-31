package android.content;

import java.io.File;

public abstract class Context {
  public abstract ContentResolver getContentResolver();

  public abstract void sendBroadcast(Intent intent);

  public abstract void sendBroadcast(Intent intent, String receiverPermission);

  public SharedPreferences getSharedPreferences(String name, int mode) { return null; }

  public File getExternalFilesDir(String type) { return null; }
}
