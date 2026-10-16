package com.example

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Parcelable
import java.io.File

class ChooserActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.extras != null) {
            var uri = intent.getParcelableExtra<Parcelable>(Intent.EXTRA_STREAM) as Uri // $ Source
            uri = Uri.fromFile(File(uri.toString()))
            makeTempCopy(uri)
        }
    }

    fun direct() {
        val uri = intent.getParcelableExtra<Parcelable>(Intent.EXTRA_STREAM) as Uri
        // Already reported by `java/android/unsafe-content-uri-resolution`.
        contentResolver.openInputStream(uri)
    }

    fun safe() {
        val uri = intent.getParcelableExtra<Parcelable>(Intent.EXTRA_STREAM) as Uri
        val name = File(uri.toString()).name
        contentResolver.openInputStream(Uri.fromFile(File("/data/local/" + name)))
    }

    private fun makeTempCopy(fileUri: Uri) {
        val out = Uri.fromFile(File("/sdcard/insecureshop/copy"))
        val inputStream = contentResolver.openInputStream(fileUri) // $ Alert
        val outputStream = contentResolver.openOutputStream(out)
        inputStream?.copyTo(outputStream!!)
    }
}
