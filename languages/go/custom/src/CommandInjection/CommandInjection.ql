/**
 * @name Command built from user-controlled sources
 * @description Building a system command from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

/*
 * Customized variant of the upstream `go/command-injection` query. In addition to the upstream
 * logic (unchanged), it tracks arguments of calls through function-typed struct fields (such as
 * `s.Handler(mode, input)`) into the parameters of the functions stored in that field (such as
 * `Sink{Handler: execHandler}`), which the Go call graph does not resolve.
 */

import go
import semmle.go.security.CommandInjection
import Dispatch.FunctionFieldDispatch

module Flow =
  DataFlow::MergePathGraph<CommandInjection::Flow::PathNode,
    CommandInjection::DoubleDashSanitizingFlow::PathNode, CommandInjection::Flow::PathGraph,
    CommandInjection::DoubleDashSanitizingFlow::PathGraph>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where
  CommandInjection::Flow::flowPath(source.asPathNode1(), sink.asPathNode1()) or
  CommandInjection::DoubleDashSanitizingFlow::flowPath(source.asPathNode2(), sink.asPathNode2())
select sink.getNode(), source, sink, "This command depends on a $@.", source.getNode(),
  "user-provided value"
