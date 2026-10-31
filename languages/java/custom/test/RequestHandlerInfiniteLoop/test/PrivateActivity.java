package test;

import android.app.Activity;
import android.os.Bundle;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PrivateActivity extends Activity {
  @Override
  protected void onCreate(Bundle state) {
    try {
      InputStream input = new ByteArrayInputStream(new byte[0]);
      while (true) {
        int length = input.read();
        if (length == -1) {
          break;
        }
      }
    } catch (IOException e) {
    }
  }
}
