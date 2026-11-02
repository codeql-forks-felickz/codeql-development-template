/**
 * @name Host header poisoning in email generation
 * @description Setting the ActionMailer default URL options from request data, such as the
 *              HTTP Host header, lets an attacker control the links in generated emails
 *              (for example password reset links), which can leak secret tokens.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id rb/host-header-forgery-in-email-generation
 * @tags security
 *       external/cwe/cwe-640
 *       external/cwe/cwe-644
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.CFG
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.dataflow.RemoteFlowSources
import codeql.ruby.dataflow.BarrierGuards

/** Gets the name of a URL option that controls where generated links point to. */
string urlLocationOption() { result = ["host", "protocol", "port", "domain", "subdomain"] }

/** Holds if `key` is a constant string or symbol naming a URL location option. */
predicate isUrlLocationKey(DataFlow::Node key) {
  key.getConstantValue().isStringlikeValue(urlLocationOption())
}

/**
 * Gets a reference to the ActionMailer configuration object on which
 * `default_url_options` is read or written: `ActionMailer::Base` or a
 * subclass of it, or `config.action_mailer`.
 */
DataFlow::Node actionMailerConfig() {
  result = API::getTopLevelMember("ActionMailer").getMember("Base").getAValueReachableFromSource()
  or
  result.(DataFlow::CallNode).getMethodName() = "action_mailer"
}

/** Gets a call that reads `default_url_options` from the ActionMailer configuration. */
DataFlow::CallNode defaultUrlOptionsRead() {
  result.getMethodName() = "default_url_options" and
  result.getNumberOfArguments() = 0 and
  actionMailerConfig().(DataFlow::LocalSourceNode).flowsTo(result.getReceiver())
}

/** A value that is used to set a single URL location option of the ActionMailer default URL options. */
class ActionMailerDefaultUrlOptionValueSink extends DataFlow::Node {
  ActionMailerDefaultUrlOptionValueSink() {
    // ActionMailer::Base.default_url_options[:host] = value
    // ActionMailer::Base.default_url_options.store(:host, value)
    exists(DataFlow::CallNode write |
      defaultUrlOptionsRead().(DataFlow::LocalSourceNode).flowsTo(write.getReceiver()) and
      write.getMethodName() = ["[]=", "store"] and
      isUrlLocationKey(write.getArgument(0)) and
      this = write.getArgument(1)
    )
    or
    // ActionMailer::Base.default_url_options.merge!(host: value)
    exists(DataFlow::CallNode write |
      defaultUrlOptionsRead().(DataFlow::LocalSourceNode).flowsTo(write.getReceiver()) and
      write.getMethodName() = mergeMethodName() and
      this = write.getKeywordArgument(urlLocationOption())
    )
  }
}

/**
 * An options hash that is used to set the ActionMailer default URL options. Only the
 * URL location options of the hash are relevant.
 */
class ActionMailerDefaultUrlOptionsHashSink extends DataFlow::Node {
  ActionMailerDefaultUrlOptionsHashSink() {
    // ActionMailer::Base.default_url_options.merge!({ host: value })
    exists(DataFlow::CallNode write |
      defaultUrlOptionsRead().(DataFlow::LocalSourceNode).flowsTo(write.getReceiver()) and
      write.getMethodName() = mergeMethodName() and
      this = write.getPositionalArgument(_)
    )
    or
    // ActionMailer::Base.default_url_options = { host: value }
    exists(DataFlow::CallNode write |
      write.getMethodName() = "default_url_options=" and
      actionMailerConfig().(DataFlow::LocalSourceNode).flowsTo(write.getReceiver()) and
      this = write.getArgument(0)
    )
  }
}

/** Gets the name of a method that merges a hash into the receiver hash in place. */
string mergeMethodName() { result = ["merge!", "update", "reverse_merge!", "deep_merge!"] }

module HostHeaderPoisoningConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ActionMailerDefaultUrlOptionValueSink or
    sink instanceof ActionMailerDefaultUrlOptionsHashSink
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    node instanceof ActionMailerDefaultUrlOptionsHashSink and
    exists(DataFlow::Content::KnownElementContent element |
      element.getIndex().isStringlikeValue(urlLocationOption()) and
      c.isKnownOrUnknownElement(element)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof StringConstCompareBarrier or
    node instanceof StringConstArrayInclusionCallBarrier
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module HostHeaderPoisoningFlow = TaintTracking::Global<HostHeaderPoisoningConfig>;

import HostHeaderPoisoningFlow::PathGraph

from HostHeaderPoisoningFlow::PathNode source, HostHeaderPoisoningFlow::PathNode sink
where HostHeaderPoisoningFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Links in emails generated by ActionMailer can be hijacked because the default URL options depend on a $@.",
  source.getNode(), "user-provided value"
