package androidx.core.content;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

public class ContextCompat {
  public static final int RECEIVER_EXPORTED = 0x2;
  public static final int RECEIVER_NOT_EXPORTED = 0x4;

  public static Intent registerReceiver(
      Context context, BroadcastReceiver receiver, IntentFilter filter, int flags) {
    return null;
  }
}
