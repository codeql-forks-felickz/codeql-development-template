package com.example

import android.app.Activity
import android.content.Intent

object Prefs {
    var username: String? = null
    var password: String? = null // $ Source
}

class AboutUsActivity : Activity() {

    fun onSendData() {
        val userName = Prefs.username!!
        val password = Prefs.password!!

        val intent = Intent("com.example.action.BROADCAST")
        intent.putExtra("username", userName)
        intent.putExtra("password", password) // $ Source
        sendBroadcast(intent) // $ Alert
    }

    fun onSendDataWithPermission() {
        val password = Prefs.password!!
        val intent = Intent("com.example.action.BROADCAST")
        intent.putExtra("password", password)
        sendBroadcast(intent, "com.example.permission.RECEIVE")
    }

    fun onSendDataExplicit() {
        val password = Prefs.password!!
        val intent = Intent("com.example.action.BROADCAST")
        intent.setPackage("com.example.receiver")
        intent.putExtra("password", password)
        sendBroadcast(intent)
    }
}
