package android.content;

import android.os.Handler;

public abstract class Context {
  public static final int RECEIVER_EXPORTED = 0x2;
  public static final int RECEIVER_NOT_EXPORTED = 0x4;

  public abstract Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter);

  public abstract Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, int flags);

  public abstract Intent registerReceiver(
      BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler);

  public abstract Intent registerReceiver(
      BroadcastReceiver receiver,
      IntentFilter filter,
      String broadcastPermission,
      Handler scheduler,
      int flags);
}
