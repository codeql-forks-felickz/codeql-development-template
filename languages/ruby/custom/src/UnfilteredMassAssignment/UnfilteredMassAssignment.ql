/**
 * @name Insecure mass assignment from an unfiltered request hash
 * @description Passing a whole user-controlled hash (such as Sinatra `params` or a decoded
 *              JSON request body) to a model constructor or update method allows a client
 *              to set any attribute of the model.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id rb/insecure-mass-assignment-unfiltered-hash
 * @tags security
 *       external/cwe/cwe-915
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.Concepts
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.dataflow.RemoteFlowSources
import codeql.ruby.frameworks.Sinatra
import codeql.ruby.security.MassAssignmentCustomizations

/** Holds if `call` has no explicit receiver (e.g. `post "/x" do ... end`). */
private predicate hasImplicitSelfReceiver(DataFlow::CallNode call) {
  call.asExpr().getExpr().(MethodCall).getReceiver().(SelfVariableAccess).isSynthesized()
}

/**
 * The block of a Sinatra route handler, either in a classic
 * (top-level) Sinatra application or in a `Sinatra::Base` subclass.
 */
class SinatraRouteBlock extends DataFlow::BlockNode {
  SinatraRouteBlock() {
    exists(DataFlow::CallNode route |
      route.getMethodName() = ["get", "post", "put", "patch", "delete", "options", "link", "unlink"] and
      hasImplicitSelfReceiver(route) and
      (
        route.asExpr().getExpr().getEnclosingModule() instanceof Toplevel
        or
        route = any(Sinatra::App app).getAModuleLevelCall(_)
      ) and
      route.getArgument(0).asExpr().getExpr() instanceof StringlikeLiteral and
      this = route.getBlock()
    )
  }
}

/** A receiver-less call to `name` directly inside a Sinatra route handler block. */
private predicate sinatraRouteCall(DataFlow::CallNode call, string name) {
  call.getMethodName() = name and
  hasImplicitSelfReceiver(call) and
  call.asExpr().getExpr().getEnclosingCallable() = any(SinatraRouteBlock b).asCallableAstNode()
}

/** Flow states for raw request data versus an attacker-controlled hash of attributes. */
private newtype TState =
  /** Raw request data that is not (yet) a hash of attributes. */
  TRaw() or
  /** A plain hash whose keys are fully controlled by the client. */
  TUnfilteredHash()

private class State extends TState {
  string toString() {
    this = TRaw() and result = "raw"
    or
    this = TUnfilteredHash() and result = "unfiltered-hash"
  }
}

/** Holds if `call` decodes its first argument into a plain hash (e.g. JSON parsing). */
private predicate decodesToHash(DataFlow::CallNode call) {
  call = API::getTopLevelMember("MultiJson").getAMethodCall(["load", "decode"])
  or
  call = API::getTopLevelMember("JSON").getAMethodCall(["parse", "parse!", "load"])
  or
  call = API::getTopLevelMember("Oj").getAMethodCall(["load", "safe_load"])
}

/** A DataMapper model class, i.e. a class that includes `DataMapper::Resource`. */
private class DataMapperModel extends DataFlow::ModuleNode {
  DataMapperModel() {
    exists(ConstantReadAccess resource |
      resource = this.getAModuleLevelCall("include").getArgument(0).asExpr().getExpr() and
      resource.getName() = "Resource" and
      resource.getScopeExpr().(ConstantReadAccess).getName() = "DataMapper"
    )
  }
}

/** A DataMapper method call that assigns attributes from a hash argument. */
private class DataMapperMassAssignmentSink extends DataFlow::Node {
  DataMapperMassAssignmentSink() {
    exists(DataMapperModel model, DataFlow::CallNode call |
      call =
        model
            .getAnImmediateReference()
            .getAMethodCall([
                "new", "create", "create!", "first_or_create", "first_or_new", "update", "update!"
              ])
      or
      exists(DataFlow::CallNode instance |
        instance =
          model
              .getAnImmediateReference()
              .getAMethodCall([
                  "get", "get!", "first", "last", "new", "create", "first_or_create", "first_or_new"
                ]) and
        instance.flowsTo(call.getReceiver()) and
        call.getMethodName() = ["update", "update!", "attributes="]
      )
    |
      this = call.getArgument(_)
    )
  }
}

private module Config implements DataFlow::StateConfigSig {
  class FlowState = State;

  predicate isSource(DataFlow::Node node, FlowState state) {
    // Any remote input may later be decoded into an attacker-controlled hash.
    state = TRaw() and
    (
      node instanceof RemoteFlowSource
      or
      sinatraRouteCall(node, "request")
    )
    or
    // Sinatra `params` is a plain `Hash`, unlike Rails' `ActionController::Parameters`.
    state = TUnfilteredHash() and
    (
      sinatraRouteCall(node, "params")
      or
      node.(Http::Server::RequestInputAccess).getSourceType() = "Sinatra::Base#params"
    )
  }

  predicate isSink(DataFlow::Node node, FlowState state) {
    state = TUnfilteredHash() and
    (
      node instanceof MassAssignment::Sink
      or
      node instanceof DataMapperMassAssignmentSink
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // Explicitly selecting the allowed keys.
    node.(DataFlow::CallNode).getMethodName() = ["slice", "permit", "values_at"] and
    exists(node.(DataFlow::CallNode).getArgument(0))
  }

  predicate isBarrierIn(DataFlow::Node node, FlowState state) { isSource(node, state) }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    // Reading the request body: `request.body.read`, `request.raw_post`, ...
    exists(DataFlow::CallNode call |
      call.getMethodName() = ["body", "read", "string", "raw_post", "to_s"] and
      node1 = call.getReceiver() and
      node2 = call and
      state1 = TRaw() and
      state2 = TRaw()
    )
    or
    // Decoding raw data into a hash: `JSON.parse(request.body.read)`.
    exists(DataFlow::CallNode call |
      decodesToHash(call) and
      node1 = call.getArgument(0) and
      node2 = call and
      state1 = TRaw() and
      state2 = TUnfilteredHash()
    )
  }
}

module UnfilteredMassAssignmentFlow = TaintTracking::GlobalWithState<Config>;

import UnfilteredMassAssignmentFlow::PathGraph

from UnfilteredMassAssignmentFlow::PathNode source, UnfilteredMassAssignmentFlow::PathNode sink
where UnfilteredMassAssignmentFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This mass assignment operation can assign arbitrary attributes from an unfiltered hash built from $@.",
  source.getNode(), "this user-controlled input"
