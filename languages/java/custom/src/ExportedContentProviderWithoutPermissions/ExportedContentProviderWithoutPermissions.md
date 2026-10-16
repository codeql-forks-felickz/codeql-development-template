# Exported content provider without permissions

An Android `<provider>` declared with `android:exported="true"` can be accessed by every other
application installed on the device. If the provider does not declare `android:permission`,
`android:readPermission`, `android:writePermission` or any `<path-permission>` element, any
application can query, insert, update and delete the data it manages, which commonly includes
credentials, notes, tokens or other private records.

A permission does not protect a provider if any application can obtain it. A custom
`<permission>` declared without `android:protectionLevel`, or with `android:protectionLevel="normal"`,
is granted automatically to any application that requests it in its manifest. This query also
reports exported providers whose read or write access is guarded only by such a permission declared
in the same manifest. Permissions declared elsewhere are not reported because their protection level
is unknown.

Providers protected by only one of `android:readPermission` or `android:writePermission` with a
stronger permission are reported by the standard `java/android/incomplete-provider-permissions`
query and are not reported by this query.

## Recommendation

Set `android:exported="false"` unless the provider must be shared with other applications. If it
must be exported, protect it with `android:permission` (or both `android:readPermission` and
`android:writePermission`) using a permission with `signature` protection level.

## Example

The following provider is exported and requires no permission:

```xml
<provider
    android:name=".NotesProvider"
    android:authorities="com.example.notes"
    android:exported="true" />
```

The following provider is protected only by a `normal` permission, so any application can read it:

```xml
<permission android:name="com.example.permission.READ" />

<provider
    android:name=".NotesProvider"
    android:authorities="com.example.notes"
    android:exported="true"
    android:readPermission="com.example.permission.READ" />
```

The following providers are safe:

```xml
<provider
    android:name=".NotesProvider"
    android:authorities="com.example.notes"
    android:exported="false" />

<provider
    android:name=".SharedProvider"
    android:authorities="com.example.shared"
    android:exported="true"
    android:permission="com.example.permission.ACCESS_SHARED" />

<permission
    android:name="com.example.permission.ACCESS_SHARED"
    android:protectionLevel="signature" />
```

## References

- Android Developers: [`<provider>` element](https://developer.android.com/guide/topics/manifest/provider-element).
- Android Developers: [`<permission>` element](https://developer.android.com/guide/topics/manifest/permission-element).
- Android Developers: [Content provider security](https://developer.android.com/privacy-and-security/risks/content-resolver).
- Common Weakness Enumeration: [CWE-926](https://cwe.mitre.org/data/definitions/926.html).
