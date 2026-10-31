package android.content;

import android.database.Cursor;
import android.net.Uri;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class ContentResolver {
    public final Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        return null;
    }

    public final InputStream openInputStream(Uri uri) {
        return null;
    }

    public final OutputStream openOutputStream(Uri uri) {
        return null;
    }
}
