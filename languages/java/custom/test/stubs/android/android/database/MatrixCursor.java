package android.database;

public class MatrixCursor implements Cursor {
  public MatrixCursor(String[] columnNames) {}

  public void addRow(Object[] columnValues) {}

  public RowBuilder newRow() { return null; }

  public class RowBuilder {
    public RowBuilder add(Object columnValue) { return this; }

    public RowBuilder add(String columnName, Object value) { return this; }
  }
}
