# Dynamically registered broadcast receiver without protection

`Context.registerReceiver` registers a broadcast receiver at runtime. Unless the call passes a
`broadcastPermission` or the `RECEIVER_NOT_EXPORTED` flag, the receiver is exported: any
application on the device can send it an intent that matches its filter. A receiver registered for
an application-defined action (one that does not start with `android.`) is not protected by the
system, so a malicious application can deliver attacker-controlled extras to it. This often leads
to opening attacker-supplied URLs, starting internal components or changing application state.

This query reports `Context.registerReceiver` and `ContextCompat.registerReceiver` calls whose
`IntentFilter` is created locally with at least one custom action, that pass no broadcast
permission, and whose flags (if any) are constants without `RECEIVER_NOT_EXPORTED`.

## Recommendation

Pass `Context.RECEIVER_NOT_EXPORTED` (or `ContextCompat.RECEIVER_NOT_EXPORTED`) when the
receiver only needs broadcasts from the same application. If other applications must send the
broadcast, require a permission with `signature` protection level as the `broadcastPermission`
argument. Treat every extra received by the receiver as untrusted.

## Example

The following activity registers an exported receiver for a custom action:

```kotlin
class AboutUsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        registerReceiver(CustomReceiver(), IntentFilter("com.example.CUSTOM_INTENT"))
    }
}
```

The following registration only accepts broadcasts from the same application:

```kotlin
ContextCompat.registerReceiver(
    this, CustomReceiver(), IntentFilter("com.example.CUSTOM_INTENT"),
    ContextCompat.RECEIVER_NOT_EXPORTED
)
```

## References

- Android Developers: [Context-registered receivers](https://developer.android.com/develop/background-work/background-tasks/broadcasts#context-registered-receivers).
- Android Developers: [Context.registerReceiver](https://developer.android.com/reference/android/content/Context#registerReceiver(android.content.BroadcastReceiver,%20android.content.IntentFilter,%20int)).
- Common Weakness Enumeration: [CWE-925](https://cwe.mitre.org/data/definitions/925.html).
- Common Weakness Enumeration: [CWE-926](https://cwe.mitre.org/data/definitions/926.html).
