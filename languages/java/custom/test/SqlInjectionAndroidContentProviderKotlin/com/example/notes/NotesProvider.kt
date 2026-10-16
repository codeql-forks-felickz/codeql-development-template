package com.example.notes

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteQueryBuilder
import android.net.Uri

// Exported provider (see AndroidManifest.xml): every `query` parameter is attacker controlled.
class NotesProvider : ContentProvider() {
    private lateinit var db: SQLiteDatabase
    private val NOTES = 1
    private val NOTES_ID = 2
    private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH)

    init {
        uriMatcher.addURI("com.example.notes.notes", "notes", NOTES)
        uriMatcher.addURI("com.example.notes.notes", "notes/#", NOTES_ID)
    }

    override fun onCreate(): Boolean = true

    override fun query(uri: Uri, projection: Array<String>?, selection: String?, // $ Source[java/sql-injection]
                       selectionArgs: Array<String>?, sortOrder: String?): Cursor? { // $ Source[java/sql-injection]
        val queryBuilder = SQLiteQueryBuilder()
        queryBuilder.setTables("notes")
        when (uriMatcher.match(uri)) {
            NOTES_ID -> queryBuilder.appendWhere(NOTES_ID.toString() + "=" + uri.lastPathSegment)
            NOTES -> {}
            else -> throw IllegalArgumentException("Unknown URI")
        }
        return queryBuilder.query(db, projection, selection, selectionArgs, null, null, sortOrder) // $ Alert[java/sql-injection]
    }

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues, selection: String?, selectionArgs: Array<String>?): Int = 0
}
