package com.example.shop;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.IOException;

// Same vulnerable pattern, but the activity is explicitly not exported, so the Intent is not
// attacker-controlled.
public class PrivateChooserActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri uri = getIntent().getParcelableExtra("android.intent.extra.STREAM");
        Cursor cursor = getContentResolver().query(uri,
                new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null);
        cursor.moveToFirst();
        String name = cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME));
        try {
            new File(Environment.getExternalStorageDirectory(), name).createNewFile();
        } catch (IOException e) {
        }
    }
}
