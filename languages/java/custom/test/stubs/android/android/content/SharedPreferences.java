package android.content;

public interface SharedPreferences {
  Editor edit();

  interface Editor {
    Editor putString(String key, String value);

    void apply();

    boolean commit();
  }
}
