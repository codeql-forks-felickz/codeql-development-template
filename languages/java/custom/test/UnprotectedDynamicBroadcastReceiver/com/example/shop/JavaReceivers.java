package com.example.shop;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import androidx.core.content.ContextCompat;

public class JavaReceivers extends Activity {
    static class Receiver extends BroadcastReceiver {
        public void onReceive(Context context, Intent intent) { }
    }

    private final Receiver receiver = new Receiver();

    void unsafe(IntentFilter external, int dynamicFlags) {
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.intent.action.SCREEN_OFF");
        filter.addAction("com.example.shop.SYNC");
        registerReceiver(receiver, filter); // $ Alert
        registerReceiver(receiver, new IntentFilter("com.example.shop.SYNC"), null, null); // $ Alert
        registerReceiver(receiver, new IntentFilter("com.example.shop.SYNC"), null, null, 0); // $ Alert
        ContextCompat.registerReceiver(this, receiver, new IntentFilter("com.example.shop.SYNC"), ContextCompat.RECEIVER_EXPORTED); // $ Alert
    }

    void safe(IntentFilter external, int dynamicFlags) {
        // Safe: senders must hold a permission.
        registerReceiver(receiver, new IntentFilter("com.example.shop.SYNC"), "com.example.shop.permission.SYNC", null);
        // Safe: not exported.
        registerReceiver(receiver, new IntentFilter("com.example.shop.SYNC"), Context.RECEIVER_NOT_EXPORTED);
        ContextCompat.registerReceiver(this, receiver, new IntentFilter("com.example.shop.SYNC"), ContextCompat.RECEIVER_NOT_EXPORTED);
        // Safe: only protected system broadcasts.
        registerReceiver(receiver, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
        // Safe: sticky broadcast query without a receiver.
        registerReceiver(null, new IntentFilter("com.example.shop.SYNC"));
        // Not reported: actions or flags are unknown.
        registerReceiver(receiver, external);
        registerReceiver(receiver, new IntentFilter("com.example.shop.SYNC"), dynamicFlags);
    }
}
