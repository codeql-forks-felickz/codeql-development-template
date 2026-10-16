/**
 * @name Exported content provider without permissions
 * @description An Android content provider that is explicitly exported without any
 *              `permission`, `readPermission`, `writePermission` or `<path-permission>`
 *              protection can be queried and modified by any application on the device.
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

from AndroidProviderXmlElement provider
where
  not provider.getFile().(AndroidManifestXmlFile).isInBuildDirectory() and
  provider.isExported() and
  // Providers protected by a single read or write permission are reported by
  // `java/android/incomplete-provider-permissions`.
  not provider.getAnAttribute() instanceof AndroidPermissionXmlAttribute and
  not exists(AndroidPathPermissionXmlElement pathPermission | pathPermission.getParent() = provider)
select provider,
  "Exported provider '" + provider.getResolvedComponentName() +
    "' does not require any permission to read or write its data."
