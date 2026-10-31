package android.database;

public interface Cursor {
    int getCount();

    int getColumnIndexOrThrow(String columnName);

    boolean moveToFirst();

    String getString(int columnIndex);
}
