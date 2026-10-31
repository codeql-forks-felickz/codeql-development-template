package com.example.storage;

import android.app.Activity;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class StorageActivity extends Activity {
    public void storeCredentials(String password, String note) throws IOException {
        File passwordFile = new File(getExternalFilesDir(null), "credentials.txt");
        FileOutputStream passwordOutput = new FileOutputStream(passwordFile);
        passwordOutput.write(password.getBytes());
        passwordOutput.close(); // $ Alert

        File noteFile = new File(getExternalFilesDir(null), "note.txt");
        FileOutputStream noteOutput = new FileOutputStream(noteFile);
        noteOutput.write(note.getBytes());
        noteOutput.close();
    }
}
