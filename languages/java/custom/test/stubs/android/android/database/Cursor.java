package android.database;

public interface Cursor {
  int getColumnIndex(String columnName);

  String getString(int columnIndex);
}
