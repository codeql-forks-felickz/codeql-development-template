# Unprotected dynamically registered broadcast receiver

A broadcast receiver registered at runtime with `Context.registerReceiver` is exported by default on Android versions before 14 unless a broadcast permission or the `RECEIVER_NOT_EXPORTED` flag is supplied. When the receiver listens for an application-defined action, any installed application can send it an intent with arbitrary extras and trigger its behavior.

System broadcast actions (those starting with `android.`) can only be sent by the system, so receivers that only listen for them are not reported.

## Recommendation

If the receiver only needs broadcasts from the same application, register it with `Context.RECEIVER_NOT_EXPORTED` (or `ContextCompat.RECEIVER_NOT_EXPORTED`). If other applications must be able to send the broadcast, require a signature-level permission through the `broadcastPermission` argument.

## Example

```kotlin
val filter = IntentFilter("com.example.action.PRODUCT_DETAIL")
registerReceiver(receiver, filter)                              // BAD
registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)       // GOOD
```

## References

- [CWE-925: Improper Verification of Intent by Broadcast Receiver](https://cwe.mitre.org/data/definitions/925.html)
- [CWE-926: Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
- [Android: Context-registered receivers](https://developer.android.com/develop/background-work/background-tasks/broadcasts#context-registered-receivers)
