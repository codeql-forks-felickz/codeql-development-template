import android.view.View
import android.widget.EditText

class OsCommandInjectionActivity {
    fun onCreate(runButton: View, ip: EditText) {
        runButton.setOnClickListener {
            val ip1 = "ping " + ip.text.toString() // $ Source
            Runtime.getRuntime().exec(ip1) // $ Alert
        }
    }

    fun direct(ip: EditText) {
        Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", "ping " + ip.text.toString())) // $ Alert
    }

    fun notEditable(ip: EditText, other: Any) {
        // toString() of a value that is not Editable text.
        Runtime.getRuntime().exec("ping " + other.toString())
        // Only the length of the text is used.
        Runtime.getRuntime().exec("ping " + ip.text.length.toString())
    }
}
