package android.app;

import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;

public class Activity extends ContextWrapper {
    public static final int RESULT_OK = -1;
    public static final int RESULT_CANCELED = 0;
    protected void onCreate(Bundle savedInstanceState) { }
    public Intent getIntent() { return null; }
    public final void setResult(int resultCode, Intent data) { }
    public void finish() { }
}
