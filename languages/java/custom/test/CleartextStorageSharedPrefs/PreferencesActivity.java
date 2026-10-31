package com.example.storage;

import android.app.Activity;
import android.content.SharedPreferences;

public class PreferencesActivity extends Activity {
    public void storeCredentials(String password, String theme) {
        SharedPreferences.Editor editor = getSharedPreferences("account", 0).edit();
        editor.putString("password", password);
        editor.apply(); // $ Alert

        SharedPreferences.Editor settings = getSharedPreferences("settings", 0).edit();
        settings.putString("theme", theme);
        settings.apply();
    }
}
