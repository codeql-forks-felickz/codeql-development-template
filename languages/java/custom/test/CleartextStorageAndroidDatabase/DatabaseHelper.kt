package com.example.goatlin

import android.content.ContentValues
import android.content.Context
import android.database.SQLException
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class DatabaseHelper(context: Context) : SQLiteOpenHelper(context, "app.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {}

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}

    // Reusable account password stored in the local SQLite database without hashing.
    fun createAccount(username: String, password: String): Boolean {
        val db: SQLiteDatabase = this.writableDatabase
        val record = ContentValues()
        var status = true

        record.put("username", username)
        record.put("password", password)

        try {
            db.insertOrThrow("Accounts", null, record) // $ Alert
        } catch (e: SQLException) {
            status = false
        }
        return status
    }

    fun addNote(title: String, content: String): Boolean {
        val db: SQLiteDatabase = this.writableDatabase
        val record = ContentValues()
        record.put("title", title)
        record.put("content", content)
        db.insertOrThrow("Notes", null, record)
        return true
    }
}
