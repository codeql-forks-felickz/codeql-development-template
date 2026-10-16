package android.content;

public abstract class Context {
  public abstract ContentResolver getContentResolver();

  public abstract void sendBroadcast(Intent intent);

  public abstract void sendBroadcast(Intent intent, String receiverPermission);
}
