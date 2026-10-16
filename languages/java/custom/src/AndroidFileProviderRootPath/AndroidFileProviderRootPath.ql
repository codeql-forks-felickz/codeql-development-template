/**
 * @name Android FileProvider shares the device root directory
 * @description A FileProvider paths configuration containing a `<root-path>` entry that points at
 *              the file system root allows content URIs to be generated for, and access to be
 *              granted to, any file the application can read.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/android/file-provider-root-path
 * @tags security
 *       external/cwe/cwe-668
 *       external/cwe/cwe-200
 */

import java

/**
 * The root `<paths>` element of an `androidx.core.content.FileProvider` (or support library
 * `FileProvider`) paths configuration file, typically stored in `res/xml/`.
 */
class FileProviderPathsXmlElement extends XmlElement {
  FileProviderPathsXmlElement() {
    this.getName() = "paths" and
    this.getParent() instanceof XmlFile
  }
}

/** A `<root-path>` entry of a FileProvider paths configuration. */
class FileProviderRootPathXmlElement extends XmlElement {
  FileProviderRootPathXmlElement() {
    this.getName() = "root-path" and
    this.getParent() instanceof FileProviderPathsXmlElement
  }

  /** Gets the value of the `path` attribute, or the empty string if it is absent. */
  string getPathValue() {
    if exists(this.getAttribute("path"))
    then result = this.getAttribute("path").getValue().trim()
    else result = ""
  }

  /** Holds if this entry shares the whole file system, starting from `/`. */
  predicate sharesFileSystemRoot() { this.getPathValue() = ["", "/", ".", "./", "/."] }
}

from FileProviderRootPathXmlElement rootPath
where rootPath.sharesFileSystemRoot()
select rootPath,
  "This FileProvider entry shares the device root directory, exposing every file readable by the application."
