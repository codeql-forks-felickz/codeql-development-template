package android.database.sqlite;

import android.content.ContentValues;

public final class SQLiteDatabase {
    public interface CursorFactory {}

    public long insert(String table, String nullColumnHack, ContentValues values) { return 0; }

    public long insertOrThrow(String table, String nullColumnHack, ContentValues values) { return 0; }

    public void execSQL(String sql) {}
}
