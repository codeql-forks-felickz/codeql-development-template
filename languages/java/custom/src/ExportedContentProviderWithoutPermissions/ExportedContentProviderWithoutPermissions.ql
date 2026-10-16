/**
 * @name Exported content provider without permissions
 * @description An Android content provider that is explicitly exported without any
 *              `permission`, `readPermission`, `writePermission` or `<path-permission>`
 *              protection, or only protected by permissions that the app declares with the
 *              `normal` protection level, can be queried and modified by any application
 *              on the device.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.2
 * @precision high
 * @id java/android/exported-provider-without-permissions
 * @tags security
 *       external/cwe/cwe-926
 */

import java
import semmle.code.xml.AndroidManifest

/**
 * Holds if the manifest that contains `provider` declares the permission `name` with the
 * `normal` protection level, either explicitly or by omitting `android:protectionLevel`.
 * Any application can obtain such a permission by requesting it.
 */
predicate isNormalAppPermission(AndroidProviderXmlElement provider, string name) {
  exists(XmlElement permission |
    permission.getParent() = provider.getFile().(AndroidManifestXmlFile).getManifestElement() and
    permission.getName() = "permission" and
    permission.getAttribute("name").getNamespace().getPrefix() = "android" and
    permission.getAttribute("name").getValue() = name
  |
    not exists(permission.getAttribute("protectionLevel"))
    or
    permission.getAttribute("protectionLevel").getValue().toLowerCase() = "normal"
  )
}

/**
 * Gets the permission that guards `access` (`read` or `write`) to `provider`. A specific
 * `readPermission` or `writePermission` takes precedence over `permission`.
 */
string getEffectivePermission(AndroidProviderXmlElement provider, string access) {
  exists(AndroidPermissionXmlAttribute attr | attr = provider.getAnAttribute() |
    access = "read" and
    (
      attr.isRead()
      or
      attr.isFull() and
      not exists(AndroidPermissionXmlAttribute r | r = provider.getAnAttribute() and r.isRead())
    ) and
    result = attr.getValue()
    or
    access = "write" and
    (
      attr.isWrite()
      or
      attr.isFull() and
      not exists(AndroidPermissionXmlAttribute w | w = provider.getAnAttribute() and w.isWrite())
    ) and
    result = attr.getValue()
  )
}

from AndroidProviderXmlElement provider, string message
where
  not provider.getFile().(AndroidManifestXmlFile).isInBuildDirectory() and
  provider.isExported() and
  not exists(AndroidPathPermissionXmlElement pathPermission | pathPermission.getParent() = provider) and
  (
    // Providers protected by a single read or write permission are reported by
    // `java/android/incomplete-provider-permissions`.
    not provider.getAnAttribute() instanceof AndroidPermissionXmlAttribute and
    message = "' does not require any permission to read or write its data."
    or
    message =
      "' only requires a permission with the 'normal' protection level, which any application can obtain, for "
        +
        strictconcat(string access |
          isNormalAppPermission(provider, getEffectivePermission(provider, access))
        |
          access, " and "
        ) + " access."
  )
select provider, "Exported provider '" + provider.getResolvedComponentName() + message
