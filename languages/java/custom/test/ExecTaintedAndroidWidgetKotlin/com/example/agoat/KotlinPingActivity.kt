package com.example.agoat

import android.app.Activity
import android.widget.Button
import android.widget.EditText

class KotlinPingActivity : Activity() {

    // BAD: same pattern in Kotlin (`ip.text` is `EditText.getText()`).
    fun bind() {
        val run = findViewById<Button>(1)
        val ip = findViewById<EditText>(2)
        run.setOnClickListener {
            val cmd = "ping " + ip.text.toString() // $ Source
            Runtime.getRuntime().exec(cmd) // $ Alert
        }
    }
}

class KotlinSafePingActivity : Activity() {

    // GOOD: fixed argument vector; the host is only used when it equals a constant.
    fun bind() {
        val ip = findViewById<EditText>(2)
        val host = ip.text.toString()
        if (host == "127.0.0.1") {
            Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", host))
        }
    }
}
