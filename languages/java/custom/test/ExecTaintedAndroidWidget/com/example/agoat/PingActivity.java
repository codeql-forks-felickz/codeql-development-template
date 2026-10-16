package com.example.agoat;

import android.app.Activity;
import android.widget.Button;
import android.widget.EditText;

public class PingActivity extends Activity {

  // BAD: EditText content concatenated into a single-string command line.
  public void bind() {
    Button run = findViewById(1);
    EditText ip = findViewById(2);
    run.setOnClickListener(
        v -> {
          String cmd = "ping " + ip.getText().toString(); // $ Source
          try {
            Runtime.getRuntime().exec(cmd); // $ Alert
          } catch (Exception e) {
            e.printStackTrace();
          }
        });
  }

  // GOOD: fixed command, user value only reaches an allowlisted host.
  public void safe() throws Exception {
    EditText ip = findViewById(2);
    String host = ip.getText().toString();
    if (host.equals("127.0.0.1")) {
      Runtime.getRuntime().exec(new String[] {"ping", "-c", "1", host});
    }
  }
}
