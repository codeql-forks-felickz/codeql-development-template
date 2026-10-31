package android.content;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;

public class Intent {
  public static final String EXTRA_STREAM = "android.intent.extra.STREAM";

  public Intent() {}

  public Intent(String action) {}

  public Intent(Context packageContext, Class<?> cls) {}

  public Intent setPackage(String packageName) { return this; }

  public Intent setClassName(String packageName, String className) { return this; }

  public Intent putExtra(String name, String value) { return this; }

  public String getStringExtra(String name) { return null; }

  public <T extends Parcelable> T getParcelableExtra(String name) { return null; }

  public Bundle getExtras() { return null; }

  public Uri getData() { return null; }
}
