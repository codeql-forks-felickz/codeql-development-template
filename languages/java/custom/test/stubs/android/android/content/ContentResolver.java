package android.content;

import android.net.Uri;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class ContentResolver {
  public final InputStream openInputStream(Uri uri) { return null; }

  public final OutputStream openOutputStream(Uri uri) { return null; }
}
