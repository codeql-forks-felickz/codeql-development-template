/**
 * @name Prompt injection (extended)
 * @description Concatenating user-controlled text with instructions into a single
 *              LlamaIndex LLM completion prompt lets the user override those instructions.
 *              This variant of the experimental `py/prompt-injection` query models LlamaIndex
 *              LLM completion APIs and `string.Template` substitution.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id py/prompt-injection-extended
 * @tags security
 *       external/cwe/cwe-1427
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.BarrierGuards

/** Gets a call that constructs a LlamaIndex LLM, such as `llama_index.llms.ollama.Ollama(...)`. */
private DataFlow::CallCfgNode llamaIndexLlmConstruction() {
  result =
    API::moduleImport("llama_index")
        .getMember("llms")
        .getMember(_)
        .getMember(_)
        .getASubclass*()
        .getACall()
  or
  result =
    API::moduleImport("llama_index").getMember("core").getMember("llms").getMember(_).getACall()
}

/**
 * Holds if `nodeFrom` is the right-hand side of an iterable unpacking assignment with a
 * `self.<attr>` target, such as `self.llm, self.embeddings = init_models()`, and `nodeTo`
 * is a read of `self.<attr>` in a method of the same class.
 *
 * The standard library does not track values into attribute targets of iterable unpacking.
 */
private predicate unpackedSelfAttributeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(AssignStmt assign, Attribute target, Class cls, string attr, Attribute read |
    target = assign.getATarget().(Tuple).getAnElt+() and
    target.getName() = attr and
    target.getObject().(Name).getId() = "self" and
    target.getScope().(Function).getScope() = cls and
    nodeFrom.asExpr() = assign.getValue() and
    read.getName() = attr and
    read.getObject().(Name).getId() = "self" and
    read.getScope().(Function).getScope() = cls and
    read.getCtx() instanceof Load and
    nodeTo.asExpr() = read
  )
}

/** Tracks LlamaIndex LLM instances to the receivers of method calls. */
private module LlmInstanceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source = llamaIndexLlmConstruction() }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call | call.calls(sink, _))
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    unpackedSelfAttributeStep(nodeFrom, nodeTo)
  }
}

private module LlmInstanceFlow = TaintTracking::Global<LlmInstanceConfig>;

/**
 * The prompt argument of a LlamaIndex LLM text completion call, such as
 * `llm.complete(prompt)`. The whole prompt is a single string, so instructions and
 * untrusted text share the same channel.
 */
private class LlmCompletionPromptSink extends DataFlow::Node {
  LlmCompletionPromptSink() {
    exists(DataFlow::MethodCallNode call, DataFlow::Node receiver |
      call.calls(receiver, ["complete", "acomplete", "stream_complete", "astream_complete"]) and
      LlmInstanceFlow::flowTo(receiver) and
      this = [call.getArg(0), call.getArgByName("prompt")]
    )
  }
}

/**
 * Holds if `nodeTo` is the result of a `string.Template`-style substitution
 * (`template.substitute(...)` or `template.safe_substitute(...)`) and `nodeFrom` is one of
 * its arguments (a mapping or keyword arguments).
 */
private predicate templateSubstitutionStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(DataFlow::MethodCallNode call |
    call.calls(_, ["substitute", "safe_substitute"]) and
    nodeTo = call and
    nodeFrom = [call.getArg(_), call.getArgByName(_)]
  )
}

private module PromptInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof LlmCompletionPromptSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof ConstCompareBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    templateSubstitutionStep(nodeFrom, nodeTo)
  }
}

module PromptInjectionExtendedFlow = TaintTracking::Global<PromptInjectionExtendedConfig>;

import PromptInjectionExtendedFlow::PathGraph

from PromptInjectionExtendedFlow::PathNode source, PromptInjectionExtendedFlow::PathNode sink
where PromptInjectionExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This LLM prompt depends on a $@.", source.getNode(),
  "user-provided value"
