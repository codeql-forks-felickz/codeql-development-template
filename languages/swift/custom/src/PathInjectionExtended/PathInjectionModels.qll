/**
 * Provides additional models used by `swift/path-injection-extended` to track
 * custom URL scheme (deep link) data into file system paths.
 *
 * Swift does not support data extension (`.model.yml`) files, so these models
 * are written in QL using the `SummaryModelCsv` and `TaintInheritingContent`
 * extension points of `codeql/swift-all`. They only take effect in queries that
 * import this module.
 */

import swift
private import codeql.swift.dataflow.DataFlow
private import codeql.swift.dataflow.ExternalFlow
private import codeql.swift.dataflow.FlowSteps
private import codeql.swift.security.PathInjectionExtensions

/**
 * A model for `URLComponents` / `NSURLComponents` and `Sequence` members that
 * permit taint flow when parsing query parameters out of a URL.
 */
private class UrlComponentsSummaries extends SummaryModelCsv {
  override predicate row(string row) {
    row =
      [
        ";URLComponents;true;init(url:resolvingAgainstBaseURL:);;;Argument[0];ReturnValue.OptionalSome;taint",
        ";URLComponents;true;init(string:);;;Argument[0];ReturnValue.OptionalSome;taint",
        ";NSURLComponents;true;init(url:resolvingAgainstBaseURL:);;;Argument[0];ReturnValue.OptionalSome;taint",
        ";NSURLComponents;true;init(string:);;;Argument[0];ReturnValue.OptionalSome;taint",
        ";Sequence;true;first(where:);;;Argument[-1];ReturnValue;taint"
      ]
  }
}

/**
 * A content implying that, if a `URLComponents`, `NSURLComponents`,
 * `URLQueryItem` or `NSURLQueryItem` is tainted, then all its fields (for
 * example `queryItems`, `path`, `name` and `value`) are tainted.
 */
private class UrlComponentsFieldsInheritTaint extends TaintInheritingContent,
  DataFlow::Content::FieldContent
{
  UrlComponentsFieldsInheritTaint() {
    this.getField().getEnclosingDecl().asNominalTypeDecl().getFullName() =
      ["URLComponents", "NSURLComponents", "URLQueryItem", "NSURLQueryItem"]
  }
}

/** Holds if `f` is a stored property of a `UIViewController` subclass. */
private predicate isViewControllerProperty(FieldDecl f) {
  f.getEnclosingDecl().asNominalTypeDecl().getABaseTypeDecl*().getFullName() = "UIViewController"
}

/**
 * A flow step from a value assigned to a stored property of a
 * `UIViewController` subclass to reads of that property through `self`.
 *
 * View controllers commonly store a deep link in a property and handle it later
 * in a lifecycle method such as `viewDidAppear(_:)`, which is invoked by UIKit
 * rather than by application code, so standard data flow does not connect the
 * write to the read.
 */
private class ViewControllerStoredPropertyStep extends PathInjectionAdditionalFlowStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    exists(FieldDecl f, AssignExpr assign, MemberRefExpr read |
      isViewControllerProperty(f) and
      assign.getDest().(MemberRefExpr).getMember() = f and
      node1.asExpr() = assign.getSource() and
      read.getMember() = f and
      not read = any(AssignExpr a).getDest() and
      read.getBase().(DeclRefExpr).getDecl() = any(Callable c).getSelfParam() and
      node2.asExpr() = read
    )
  }
}
