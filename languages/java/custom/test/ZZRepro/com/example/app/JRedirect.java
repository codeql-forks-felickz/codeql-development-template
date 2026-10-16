package com.example.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class JRedirect extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        Intent extra = getIntent().getParcelableExtra("extra_intent");
        if (extra != null) {
            startActivity(extra);
        }
    }
}
