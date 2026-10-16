package android.net;

import android.os.Parcelable;
import java.io.File;

public abstract class Uri implements Parcelable {
  public static Uri parse(String uriString) { return null; }

  public static Uri fromFile(File file) { return null; }

  public abstract String getPath();

  public abstract String getScheme();

  public abstract String getLastPathSegment();
}
