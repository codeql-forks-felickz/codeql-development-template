package android.content;

import android.os.Handler;

public class ContextWrapper extends Context {
  @Override
  public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) {
    return null;
  }

  @Override
  public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, int flags) {
    return null;
  }

  @Override
  public Intent registerReceiver(
      BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler) {
    return null;
  }

  @Override
  public Intent registerReceiver(
      BroadcastReceiver receiver,
      IntentFilter filter,
      String broadcastPermission,
      Handler scheduler,
      int flags) {
    return null;
  }
}
