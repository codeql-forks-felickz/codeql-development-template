# Loading code from another package while ignoring security

`Context.createPackageContext(packageName, flags)` returns a `Context` for another installed
application. When `flags` contains `CONTEXT_INCLUDE_CODE`, the returned context's class loader can
load and run that application's code inside the calling process. Adding `CONTEXT_IGNORE_SECURITY`
disables the platform check that would otherwise refuse to load code that is not safe to load.

Package names are not a trust boundary: any application can be published with a package name that
matches the prefix or name the caller searches for. Code loaded this way runs with all the
permissions and data of the calling application, leading to arbitrary code execution.

## Recommendation

Do not load code from other packages with `CONTEXT_IGNORE_SECURITY`. If a plugin model is required,
verify the signing certificate of the target package (for example with
`PackageManager.checkSignatures` or `PackageManager.hasSigningCertificate`) before loading any code,
and prefer bound services or other IPC mechanisms over loading foreign code.

## Example

The following code loads a class from any installed package whose name starts with a fixed prefix:

```kotlin
for (info in packageManager.getInstalledPackages(0)) {
    if (info.packageName.startsWith("com.example.plugin")) {
        val ctx = createPackageContext(
            info.packageName,
            Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY
        )
        ctx.classLoader.loadClass("com.example.plugin.MainInterface")
            .getMethod("getInstance", Context::class.java)
            .invoke(null, this)
    }
}
```

Creating a package context only to read resources, without `CONTEXT_IGNORE_SECURITY`, is not
reported:

```kotlin
val ctx = createPackageContext(packageName, Context.CONTEXT_RESTRICTED)
```

## References

- Android Developers: [Context.createPackageContext](https://developer.android.com/reference/android/content/Context#createPackageContext(java.lang.String,%20int)).
- Android Developers: [Context.CONTEXT_IGNORE_SECURITY](https://developer.android.com/reference/android/content/Context#CONTEXT_IGNORE_SECURITY).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-749](https://cwe.mitre.org/data/definitions/749.html).
- Common Weakness Enumeration: [CWE-829](https://cwe.mitre.org/data/definitions/829.html).
