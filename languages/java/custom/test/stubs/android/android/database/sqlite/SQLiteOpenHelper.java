package android.database.sqlite;

import android.content.Context;

public abstract class SQLiteOpenHelper {
    public SQLiteOpenHelper(Context context, String name, SQLiteDatabase.CursorFactory factory, int version) {}

    public SQLiteDatabase getWritableDatabase() { return null; }

    public SQLiteDatabase getReadableDatabase() { return null; }

    public abstract void onCreate(SQLiteDatabase db);

    public abstract void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion);
}
