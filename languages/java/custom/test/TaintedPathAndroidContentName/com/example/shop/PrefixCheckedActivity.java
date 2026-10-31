package com.example.shop;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import java.io.File;

public class PrefixCheckedActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String path = getIntent().getStringExtra("path"); // $ Source
        if (path.startsWith(Environment.getExternalStorageDirectory().getAbsolutePath())) {
            new File(path).delete(); // $ Alert
        }
    }

    private void safeDelete() {
        String name = getIntent().getStringExtra("name");
        if (name.contains("..") || name.contains("/") || name.contains("\\")) {
            return;
        }
        new File(Environment.getExternalStorageDirectory(), name).delete();
    }
}
