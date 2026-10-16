/**
 * Provides additional sources and sinks for the Zip Slip (`js/zipslip`)
 * data flow configuration that are not modeled by the standard library.
 */

import javascript
private import semmle.javascript.security.dataflow.ZipSlipCustomizations
private import semmle.javascript.dependencies.SemVer

/**
 * Provides extended models for unsafe archive extraction.
 */
module ZipSlipExtensions {
  /**
   * Gets an `unzipper` central-directory object, as returned (via a promise)
   * by `unzipper.Open.buffer(...)`, `unzipper.Open.file(...)` and friends.
   */
  private API::Node unzipperDirectory() {
    result =
      API::moduleImport("unzipper")
          .getMember("Open")
          .getMember(["buffer", "file", "url", "s3", "s3_v3", "custom"])
          .getReturn()
          .getPromised()
  }

  /**
   * An archive entry path read from an entry of an `unzipper` central directory.
   *
   * For example, `entry.path` in:
   * ```javascript
   * const directory = await unzipper.Open.buffer(buffer);
   * for (const entry of directory.files) {
   *   fs.createWriteStream(dest + entry.path);
   * }
   * ```
   */
  class UnzipperOpenEntrySource extends ZipSlip::Source {
    UnzipperOpenEntrySource() {
      this = unzipperDirectory().getMember("files").getArrayElement().getMember("path").asSource()
    }
  }

  /**
   * Holds if the `package.json` governing `f` pins a version of `adm-zip` that
   * does not sanitize entry names during extraction (CVE-2018-1002204, fixed
   * in 0.4.11).
   *
   * Only exact versions (optionally prefixed with `=`, `<=` or `v`) are
   * considered, since ranges such as `^0.4.7` may resolve to a fixed release.
   */
  private predicate usesVulnerableAdmZip(File f) {
    exists(NpmPackage pkg, ExternalNpmDependency dep, DependencySemVer v |
      f = pkg.getAFile() and
      dep = pkg.getPackageJson().getADependenciesObject(_).getPropValue("adm-zip") and
      dep.(JsonString).getValue().regexpMatch("\\s*(=|<=)?\\s*v?\\d+\\.\\d+\\.\\d+\\s*") and
      v.getDependency() = dep and
      v = dep.getVersion() and
      v.maybeBefore("0.4.11")
    )
  }

  /** Gets an `adm-zip` archive, created with or without `new`. */
  private DataFlow::InvokeNode admZipArchive() {
    result = DataFlow::moduleImport("adm-zip").getAnInvocation()
  }

  /**
   * An `adm-zip` archive, as a source of untrusted entry names that are
   * implicitly used by a high-level extraction method.
   */
  class VulnerableAdmZipArchiveSource extends ZipSlip::Source {
    VulnerableAdmZipArchiveSource() {
      this = admZipArchive() and
      usesVulnerableAdmZip(this.getFile()) and
      this = any(VulnerableAdmZipExtractionSink s).getArchive()
    }
  }

  /**
   * The receiver of a call to `extractAllTo`, `extractAllToAsync` or
   * `extractEntryTo` on an `adm-zip` archive whose version does not sanitize
   * entry names, as a sink for unsafe archive extraction.
   */
  class VulnerableAdmZipExtractionSink extends ZipSlip::Sink {
    DataFlow::InvokeNode archive;

    VulnerableAdmZipExtractionSink() {
      archive = admZipArchive() and
      usesVulnerableAdmZip(archive.getFile()) and
      this =
        archive
            .getAMethodCall(["extractAllTo", "extractAllToAsync", "extractEntryTo"])
            .getReceiver()
    }

    /** Gets the archive whose entries are extracted. */
    DataFlow::InvokeNode getArchive() { result = archive }
  }
}
