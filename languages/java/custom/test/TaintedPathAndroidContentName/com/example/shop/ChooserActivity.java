package com.example.shop;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.IOException;

// Exported activity that copies a caller-supplied stream to external storage, using a
// destination file name taken from the (attacker-controlled) source URI.
public class ChooserActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri uri = getIntent().getParcelableExtra("android.intent.extra.STREAM"); // $ Source
        makeTempCopy(uri, getFilenameFromContent(uri));
        Uri fileUri = Uri.fromFile(new File(uri.toString()));
        makeTempCopy(fileUri, fileUri.getLastPathSegment());
    }

    private String getFilenameFromContent(Uri uri) {
        String fileName = null;
        Cursor cursor = getApplicationContext().getContentResolver().query(uri,
                new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null);
        if (cursor != null && cursor.getCount() != 0) {
            int columnIndex = cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME);
            cursor.moveToFirst();
            fileName = cursor.getString(columnIndex);
        }
        return fileName;
    }

    private void makeTempCopy(Uri fileUri, String originalFilename) {
        try {
            String path = Environment.getExternalStorageDirectory().getAbsolutePath()
                    + File.separator + "shop";
            File fileTemp = new File(path, originalFilename);
            fileTemp.createNewFile(); // $ Alert
        } catch (IOException e) {
        }
    }
}
