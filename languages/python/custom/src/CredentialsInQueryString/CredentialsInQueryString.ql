/**
 * @name Credentials read from URL query string
 * @description Reading a password from the query string of an HTTP request means the
 *              credential is sent in the URL, where it is retained in browser history,
 *              server and proxy access logs, and `Referer` headers.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id py/credentials-in-query-string
 * @tags security
 *       external/cwe/cwe-598
 */

import python
import semmle.python.dataflow.new.DataFlow
private import codeql.concepts.internal.SensitiveDataHeuristics
import semmle.python.ApiGraphs
import semmle.python.frameworks.Flask

/** Gets a reference to the query string arguments of a Flask request (`flask.request.args`). */
API::Node flaskQueryArgs() { result = Flask::request().getMember("args") }

/**
 * Holds if `read` reads the query string parameter named by `key` from a Flask request,
 * either through `request.args.get(key)`, `request.args.getlist(key)` or `request.args[key]`.
 */
predicate queryStringRead(DataFlow::Node read, DataFlow::Node key) {
  exists(API::CallNode call |
    call = flaskQueryArgs().getMember(["get", "getlist"]).getACall() and
    read = call and
    key = call.getParameter(0, "key").asSink()
  )
  or
  exists(SubscriptNode sub |
    sub.getObject() = flaskQueryArgs().getAValueReachableFromSource().asCfgNode() and
    read.asCfgNode() = sub and
    key.asCfgNode() = sub.getIndex()
  )
}

from DataFlow::Node read, DataFlow::Node key, StringLiteral name
where
  queryStringRead(read, key) and
  DataFlow::exprNode(name).(DataFlow::LocalSourceNode).flowsTo(key) and
  HeuristicNames::nameIndicatesSensitiveData(name.getText(), SensitiveDataClassification::password())
select read, "The credential '" + name.getText() + "' is read from the URL query string."
