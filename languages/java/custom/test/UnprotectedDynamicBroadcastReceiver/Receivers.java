import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import androidx.core.content.ContextCompat;

class ProductDetailReceiver extends BroadcastReceiver {
  @Override
  public void onReceive(Context context, Intent intent) {}
}

class ReceiverActivity extends Activity {
  ProductDetailReceiver receiver = new ProductDetailReceiver();

  void unprotected() {
    IntentFilter filter = new IntentFilter("com.example.action.PRODUCT_DETAIL");
    registerReceiver(receiver, filter); // $ Alert
  }

  void unprotectedAddAction() {
    IntentFilter filter = new IntentFilter();
    filter.addAction("com.example.action.REFRESH");
    filter.addAction(Intent.ACTION_BATTERY_CHANGED);
    registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED); // $ Alert
  }

  void unprotectedNullPermission() {
    registerReceiver(receiver, new IntentFilter("com.example.action.SYNC"), null, null); // $ Alert
  }

  void unprotectedCompat(Context ctx) {
    ContextCompat.registerReceiver(ctx, receiver, new IntentFilter("com.example.action.SYNC"), ContextCompat.RECEIVER_EXPORTED); // $ Alert
  }

  // Safe cases below.

  void withPermission() {
    registerReceiver(receiver, new IntentFilter("com.example.action.SYNC"), "com.example.permission.SYNC", null);
  }

  void notExported() {
    registerReceiver(receiver, new IntentFilter("com.example.action.SYNC"), Context.RECEIVER_NOT_EXPORTED);
    registerReceiver(receiver, new IntentFilter("com.example.action.SYNC"), null, null, RECEIVER_NOT_EXPORTED);
  }

  void notExportedCompat(Context ctx) {
    ContextCompat.registerReceiver(ctx, receiver, new IntentFilter("com.example.action.SYNC"), ContextCompat.RECEIVER_NOT_EXPORTED);
  }

  void systemActionOnly() {
    registerReceiver(receiver, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
  }
}
