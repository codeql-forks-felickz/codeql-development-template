package android.app;

import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

public class Activity extends Context {
    public Intent getIntent() {
        return null;
    }

    protected void onCreate(Bundle savedInstanceState) {}

    @Override
    public ContentResolver getContentResolver() {
        return null;
    }

    @Override
    public Context getApplicationContext() {
        return null;
    }
}
