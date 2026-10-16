package android.content;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;

public class Intent {
    public static final String EXTRA_STREAM = "android.intent.extra.STREAM";

    public Bundle getExtras() {
        return null;
    }

    public <T extends Parcelable> T getParcelableExtra(String name) {
        return null;
    }

    public Uri getData() {
        return null;
    }
}
