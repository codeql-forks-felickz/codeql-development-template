import android.widget.EditText;

public class EditableJava {
  // Already reported by java/command-line-injection, so not repeated.
  void run(EditText ip) throws Exception {
    Runtime.getRuntime().exec("ping " + ip.getText().toString());
  }
}
