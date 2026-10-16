package com.example.shop;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.IOException;

// Same pattern as ChooserActivity, but the untrusted name is validated before use.
public class SafeChooserActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri uri = getIntent().getParcelableExtra("android.intent.extra.STREAM");
        makeTempCopy(getFilenameFromContent(uri));
    }

    private String getFilenameFromContent(Uri uri) {
        Cursor cursor = getContentResolver().query(uri,
                new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null);
        cursor.moveToFirst();
        return cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME));
    }

    private void makeTempCopy(String originalFilename) {
        if (originalFilename.contains("..") || originalFilename.contains("/")) {
            return;
        }
        try {
            File fileTemp = new File(Environment.getExternalStorageDirectory(), originalFilename);
            fileTemp.createNewFile();
        } catch (IOException e) {
        }
    }
}
