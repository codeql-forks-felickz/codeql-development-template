/**
 * @name Unsafe WebView fetch of local user input
 * @description Loading HTML built from local user input (such as text typed into a
 *              `UITextField`) into a WebView without restricting the base URL may enable
 *              cross-site scripting or give injected script access to local data.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id swift/custom/unsafe-webview-fetch-local-input
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-095
 *       external/cwe/cwe-749
 */

import swift
import UnsafeWebViewFetchLocalInput
import UnsafeWebViewFetchLocalInputFlow::PathGraph

from
  UnsafeWebViewFetchLocalInputFlow::PathNode sourceNode,
  UnsafeWebViewFetchLocalInputFlow::PathNode sinkNode, UnsafeWebViewFetchSink sink, string message
where
  UnsafeWebViewFetchLocalInputFlow::flowPath(sourceNode, sinkNode) and
  sink = sinkNode.getNode() and
  unsafeWebViewFetchLocalInput(sink, message)
select sink, sourceNode, sinkNode, message
