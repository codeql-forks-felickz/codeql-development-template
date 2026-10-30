package com.example.shop

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle

class CustomReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        val url = intent?.extras?.getString("web_url")
        if (!url.isNullOrBlank()) {
            val next = Intent("com.example.shop.WEBVIEW")
            context?.startActivity(next)
        }
    }
}

class AboutUsActivity : Activity() {
    lateinit var receiver: CustomReceiver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        receiver = CustomReceiver()
        registerReceiver(receiver, IntentFilter("com.example.shop.CUSTOM_INTENT")) // $ Alert
    }

    fun registerExported() {
        registerReceiver(receiver, IntentFilter("com.example.shop.CUSTOM_INTENT"), Context.RECEIVER_EXPORTED) // $ Alert
    }

    fun registerNotExported() {
        // Safe: only this application can send it intents.
        registerReceiver(receiver, IntentFilter("com.example.shop.CUSTOM_INTENT"), Context.RECEIVER_NOT_EXPORTED)
    }

    fun stop() {
        unregisterReceiver(receiver)
    }
}
