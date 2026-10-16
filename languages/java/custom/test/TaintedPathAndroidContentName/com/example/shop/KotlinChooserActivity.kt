package com.example.shop

import android.app.Activity
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.os.Parcelable
import android.provider.OpenableColumns
import java.io.File

// Kotlin version of ChooserActivity, mirroring the original vulnerable sample.
class KotlinChooserActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.extras != null) {
            var uri = intent.getParcelableExtra<Parcelable>("android.intent.extra.STREAM") as Uri // $ Source
            makeTempCopy(uri, getFilename(uri))
            uri = Uri.fromFile(File(uri.toString()))
            makeTempCopy(uri, getFilename(uri))
        }
    }

    private fun makeTempCopy(fileUri: Uri, originalFilename: String?): Uri? {
        val path: String = Environment.getExternalStorageDirectory().absolutePath + File.separator + "shop"
        val fileTemp = File(path, originalFilename)
        fileTemp.createNewFile() // $ Alert
        return Uri.fromFile(fileTemp)
    }

    fun getFilename(uri: Uri): String? {
        var fileName: String? = null
        val scheme = uri.scheme
        if (scheme == "file") {
            fileName = uri.lastPathSegment
        } else if (scheme == "content") {
            val cursor: Cursor? = applicationContext.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            if (cursor != null && cursor.getCount() != 0) {
                val columnIndex: Int = cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)
                cursor.moveToFirst()
                fileName = cursor.getString(columnIndex)
            }
        }
        return fileName
    }
}
