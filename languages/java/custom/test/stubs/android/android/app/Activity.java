package android.app;

import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;

public class Activity extends Context {
  protected void onCreate(Bundle savedInstanceState) {}

  public Intent getIntent() { return null; }

  public void setContentView(int layoutResID) {}

  public <T extends View> T findViewById(int id) { return null; }

  public ContentResolver getContentResolver() { return null; }

  public void sendBroadcast(Intent intent) {}

  public void sendBroadcast(Intent intent, String receiverPermission) {}
}
