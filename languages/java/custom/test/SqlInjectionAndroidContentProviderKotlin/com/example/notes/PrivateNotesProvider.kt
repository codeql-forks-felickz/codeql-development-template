package com.example.notes

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteQueryBuilder
import android.net.Uri

// Not exported (see AndroidManifest.xml): other apps cannot reach `query`, so no alert.
class PrivateNotesProvider : ContentProvider() {
    private lateinit var db: SQLiteDatabase

    override fun onCreate(): Boolean = true

    override fun query(uri: Uri, projection: Array<String>?, selection: String?,
                       selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val queryBuilder = SQLiteQueryBuilder()
        queryBuilder.setTables("notes")
        queryBuilder.appendWhere("_id=" + uri.lastPathSegment)
        return queryBuilder.query(db, projection, selection, selectionArgs, null, null, sortOrder)
    }

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues, selection: String?, selectionArgs: Array<String>?): Int = 0
}
