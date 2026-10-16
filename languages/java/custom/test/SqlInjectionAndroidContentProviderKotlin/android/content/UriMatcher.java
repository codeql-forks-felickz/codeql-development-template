package android.content;

import android.net.Uri;

public class UriMatcher {
  public static final int NO_MATCH = -1;

  public UriMatcher(int code) {}

  public void addURI(String authority, String path, int code) {}

  public int match(Uri uri) {
    return 0;
  }
}
