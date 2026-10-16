package android.net;

import android.os.Parcelable;
import java.io.File;

public abstract class Uri implements Parcelable {
    public static Uri fromFile(File file) {
        return null;
    }

    public abstract String getScheme();

    public abstract String getLastPathSegment();

    @Override
    public abstract String toString();
}
