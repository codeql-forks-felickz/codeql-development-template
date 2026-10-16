package android.content;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;

public class Intent implements Parcelable {
    public Intent() { }
    public Intent(String action) { }
    public Uri getData() { return null; }
    public String getDataString() { return null; }
    public Bundle getExtras() { return null; }
    public String getStringExtra(String name) { return null; }
    public <T extends Parcelable> T getParcelableExtra(String name) { return null; }
    public int getFlags() { return 0; }
    public Intent setData(Uri data) { return this; }
    public Intent addFlags(int flags) { return this; }
}
