/**
 * @name Stored server-side request forgery
 * @description Making a network request with a URL read from a database field, which may
 *              have been set by a user, allows for request forgery attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id rb/stored-request-forgery
 * @tags security
 *       external/cwe/cwe-918
 */

import codeql.ruby.AST
import codeql.ruby.Concepts
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.dataflow.BarrierGuards
import codeql.ruby.security.ServerSideRequestForgeryCustomizations

/**
 * Tracks ORM instances (for example `User.find(id)`) to the receivers of method calls.
 */
private module OrmTrackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof OrmInstantiation and source instanceof DataFlow::CallNode
  }

  predicate isSink(DataFlow::Node sink) { sink = any(DataFlow::CallNode c).getReceiver() }

  predicate isBarrierIn(DataFlow::Node node) { node instanceof DataFlow::SelfParameterNode }

  int accessPathLimit() { result = 1 }
}

private module OrmTracking = DataFlow::Global<OrmTrackingConfig>;

/**
 * A read of a field of an ORM-backed object (for example `user.avatar_url`), whose
 * value may have been stored by a user.
 */
class OrmFieldRead extends DataFlow::CallNode {
  OrmFieldRead() {
    exists(DataFlow::CallNode inst |
      OrmTracking::flow(inst, this.getReceiver()) and
      inst.(OrmInstantiation).methodCallMayAccessField(this.getMethodName()) and
      this.getNumberOfArguments() = 0 and
      not exists(this.getBlock())
    )
  }
}

private module StoredServerSideRequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof OrmFieldRead }

  predicate isSink(DataFlow::Node sink) { sink instanceof ServerSideRequestForgery::Sink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof ServerSideRequestForgery::Sanitizer or
    node instanceof StringConstCompareBarrier or
    node instanceof StringConstArrayInclusionCallBarrier
  }
}

module StoredServerSideRequestForgeryFlow =
  TaintTracking::Global<StoredServerSideRequestForgeryConfig>;

import StoredServerSideRequestForgeryFlow::PathGraph

from
  StoredServerSideRequestForgeryFlow::PathNode source,
  StoredServerSideRequestForgeryFlow::PathNode sink
where StoredServerSideRequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "The URL of this request depends on a $@.", source.getNode(),
  "stored (potentially user-provided) value"
