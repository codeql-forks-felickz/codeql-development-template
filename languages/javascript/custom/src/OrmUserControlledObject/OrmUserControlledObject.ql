/**
 * @name User-controlled object used in ORM model or query
 * @description Passing a user-controlled object (such as a whole request body or the
 *              result of `JSON.parse` on request data) to an ORM model constructor,
 *              create/update method or query condition lets an attacker set arbitrary
 *              model attributes (mass assignment) or change the query conditions.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id js/orm-user-controlled-object
 * @tags security
 *       external/cwe/cwe-915
 *       external/cwe/cwe-943
 */

import javascript
import semmle.javascript.security.TaintedObject

/** Gets a reference to a Mongoose model. */
API::Node mongooseModel() { result = ModelOutput::getATypeNode("mongoose.Model") }

/** Gets a reference to a Mongoose document. */
API::Node mongooseDocument() {
  result = ModelOutput::getATypeNode("mongoose.Document")
  or
  result = mongooseModel().getInstance()
  or
  result =
    mongooseModel()
        .getMember(["findById", "findOne", "findOneAndUpdate", "findByIdAndUpdate"])
        .getReturn()
        .getPromised()
}

/** Gets a reference to a Sequelize model, as modeled by the standard library. */
API::Node sequelizeModel() {
  result = ModelOutput::getATypeNode("sequelize.Model")
  or
  result = API::moduleImport("sequelize").getMember("Model")
}

/** Gets a class that extends a Sequelize model, for example `class User extends Model {}`. */
DataFlow::ClassNode sequelizeModelSubclass() {
  result.getASuperClassNode() = sequelizeModel().getAValueReachableFromSource()
  or
  result = sequelizeModelSubclass().getADirectSubClass()
}

/** Gets a call to the static model method `name` of a Sequelize model. */
DataFlow::CallNode sequelizeModelCall(string name) {
  result = sequelizeModel().getMember(name).getACall()
  or
  result = sequelizeModelSubclass().getAClassReference().getAMethodCall(name)
}

/** Gets an instantiation `new Model(...)` of a Sequelize model. */
DataFlow::InvokeNode sequelizeModelInstantiation() {
  result = sequelizeModel().getAnInstantiation()
  or
  result = sequelizeModelSubclass().getAClassReference().getAnInstantiation()
}

/** Gets a reference to a Sequelize model instance. */
DataFlow::SourceNode sequelizeInstance() {
  result = sequelizeModelInstantiation()
  or
  result = sequelizeModel().getInstance().asSource()
  or
  result = sequelizeModelCall("build")
  or
  exists(DataFlow::CallNode call | call = sequelizeModelCall(["findByPk", "findOne", "create"]) |
    result.asExpr().(AwaitExpr).getOperand().flow().getALocalSource() = call
    or
    result = call.getAMethodCall("then").getCallback(0).getParameter(0)
  )
}

/**
 * A data-flow node that is written as a whole into an ORM model, so that every
 * property of the value becomes a model attribute.
 */
class ModelWriteSink extends DataFlow::Node {
  ModelWriteSink() {
    // Mongoose: `new Model(obj)`, `Model.create(obj)`, `Model.insertMany(obj)`
    this = mongooseModel().getParameter(0).asSink()
    or
    this = mongooseModel().getMember(["create", "insertMany"]).getParameter(0).asSink()
    or
    // Mongoose: `doc.set(obj)`, `doc.overwrite(obj)`
    this = mongooseDocument().getMember(["set", "$set", "overwrite"]).getParameter(0).asSink()
    or
    // Sequelize: `new Model(obj)`, `Model.build(obj)`, `Model.create(obj)`, `Model.update(obj, opts)`
    this = sequelizeModelInstantiation().getArgument(0)
    or
    this =
      sequelizeModelCall(["build", "create", "bulkBuild", "bulkCreate", "upsert", "update"])
          .getArgument(0)
    or
    // Sequelize: `instance.set(obj)`, `instance.update(obj)`
    this = sequelizeInstance().getAMethodCall(["set", "update"]).getArgument(0)
  }
}

/**
 * A data-flow node that is used as a Sequelize `where` condition, or as the value
 * of a property in such a condition. A user-controlled object or array in this
 * position can change the meaning of the generated query.
 */
class QueryConditionSink extends DataFlow::Node {
  QueryConditionSink() {
    exists(DataFlow::Node cond |
      cond =
        sequelizeModelCall([
            "findAll", "findOne", "findAndCountAll", "count", "destroy", "restore", "findOrCreate",
            "findOrBuild", "findCreateFind"
          ]).getOptionArgument(0, "where")
      or
      cond = sequelizeModelCall(["max", "min", "sum", "update"]).getOptionArgument(1, "where")
    |
      this = cond
      or
      this = cond.getALocalSource().getAPropertyWrite().getRhs()
    )
  }
}

module OrmUserControlledObjectConfig implements DataFlow::StateConfigSig {
  import semmle.javascript.security.CommonFlowState

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof RemoteFlowSource and state.isTaint()
    or
    source instanceof TaintedObject::Source and state.isTaintedObject()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    (sink instanceof ModelWriteSink or sink instanceof QueryConditionSink) and
    state.isTaintedObject() and
    // Already reported by `js/sql-injection` (NoSQL injection).
    not sink instanceof NoSql::Query
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    TaintTracking::defaultSanitizer(node) and state.isTaint()
    or
    node = TaintedObject::SanitizerGuard::getABarrierNode(state)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    TaintedObject::isAdditionalFlowStep(node1, state1, node2, state2) and
    // Projecting an allow-list of properties (for example `_.pick(obj, [...])`) is the
    // recommended mitigation for mass assignment.
    not node2 instanceof PropertyProjection
    or
    TaintTracking::defaultTaintStep(node1, node2) and
    state1.isTaint() and
    state2 = state1
  }
}

module OrmUserControlledObjectFlow = DataFlow::GlobalWithState<OrmUserControlledObjectConfig>;

import OrmUserControlledObjectFlow::PathGraph

from OrmUserControlledObjectFlow::PathNode source, OrmUserControlledObjectFlow::PathNode sink
where OrmUserControlledObjectFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This user-controlled object from a $@ is used in an ORM model or query, which may allow mass assignment of model attributes or manipulation of the query.",
  source.getNode(), "user-provided value"
