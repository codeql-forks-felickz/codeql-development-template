package com.example.logging

import android.app.Activity
import android.database.Cursor
import android.util.Log
import android.widget.EditText

class LoggingActivity : Activity() {
    fun logCredentials(username: String, password: String) {
        Log.d("login", "user=$username pass=$password") // $ Alert
    }

    fun logSql(password: String) {
        val query = "SELECT * FROM users WHERE password='$password'" // $ Source
        Log.d("database", query) // $ Alert
    }

    fun logCursorValue(cursor: Cursor) {
        val password = cursor.getString(cursor.getColumnIndex("password"))
        Log.d("database", password) // $ Alert
    }

    fun logUnlabelledCursorValue(cursor: Cursor) {
        val result = cursor.getString(cursor.getColumnIndex("password"))
        Log.d("database", result)
    }

    fun logInput(editText: EditText) {
        val password = editText.text.toString()
        Log.d("login", password) // $ Alert
    }

    fun logNonSensitive(username: String) {
        Log.d("debug", username)
    }
}
