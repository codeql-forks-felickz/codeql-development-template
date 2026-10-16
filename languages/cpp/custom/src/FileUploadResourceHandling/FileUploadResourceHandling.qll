/**
 * Provides predicates for detecting insecure handling of security-sensitive
 * resources in C/C++ code that are not reported by the standard CodeQL queries:
 *
 * - CWE-15: untrusted data used to change a system configuration setting.
 * - CWE-114: untrusted data used as the library path of `LoadLibraryEx*`.
 * - CWE-247: a reverse DNS lookup result used in a security decision.
 * - CWE-428: an unquoted command line with spaces held in a `char[]` buffer
 *   passed to a `CreateProcess*` function with a NULL application name.
 * - CWE-535: sensitive data (such as a password) written to standard error.
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.security.FileWrite
import semmle.code.cpp.security.SensitiveExprs

/*
 * CWE-15: External control of a system or configuration setting.
 */

/**
 * Holds if argument `arg` of `name` sets a system-wide configuration setting.
 */
private predicate isSystemConfigurationSetter(string name, int arg) {
  name = ["SetComputerNameA", "SetComputerNameW", "sethostname", "setdomainname"] and arg = 0
  or
  name = ["SetComputerNameExA", "SetComputerNameExW"] and arg = 1
}

/** Holds if `sink` is the string passed to a system configuration setter `call`. */
private predicate isSystemConfigurationSink(DataFlow::Node sink, FunctionCall call) {
  exists(int arg |
    isSystemConfigurationSetter(call.getTarget().getName(), arg) and
    sink.asIndirectExpr() = call.getArgument(arg)
  )
}

private module ExternalConfigControlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { isSystemConfigurationSink(sink, _) }
}

private module ExternalConfigControlFlow = TaintTracking::Global<ExternalConfigControlConfig>;

/**
 * Holds if untrusted data from `source` is used by `call` to change a system
 * configuration setting.
 */
predicate externalConfigControl(FunctionCall call, FlowSource source) {
  exists(DataFlow::Node sink |
    ExternalConfigControlFlow::flow(source, sink) and
    isSystemConfigurationSink(sink, call)
  )
}

/*
 * CWE-114: Process control through an untrusted library path.
 *
 * `LoadLibrary`, `LoadLibraryA` and `LoadLibraryW` are reported by the
 * standard `cpp/uncontrolled-process-operation` query, so only the
 * `LoadLibraryEx` variants are modeled here.
 */

/** Holds if `sink` is the library path passed to a `LoadLibraryEx*` `call`. */
private predicate isLibraryLoadSink(DataFlow::Node sink, FunctionCall call) {
  call.getTarget().getName() = ["LoadLibraryExA", "LoadLibraryExW"] and
  sink.asIndirectExpr() = call.getArgument(0)
}

private module UntrustedLibraryLoadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { isLibraryLoadSink(sink, _) }
}

private module UntrustedLibraryLoadFlow = TaintTracking::Global<UntrustedLibraryLoadConfig>;

/**
 * Holds if untrusted data from `source` is used by `call` as the path of a
 * library to load.
 */
predicate untrustedLibraryLoad(FunctionCall call, FlowSource source) {
  exists(DataFlow::Node sink |
    UntrustedLibraryLoadFlow::flow(source, sink) and
    isLibraryLoadSink(sink, call)
  )
}

/*
 * CWE-247: Reliance on DNS lookups in a security decision.
 */

/** A call to a function that performs a reverse DNS lookup. */
class ReverseDnsLookupCall extends FunctionCall {
  ReverseDnsLookupCall() {
    this.getTarget().hasGlobalName(["gethostbyaddr", "getnameinfo", "GetNameInfoA", "GetNameInfoW"])
  }

  /** Gets the data flow node that holds the resolved host name. */
  DataFlow::Node getHostNameNode() {
    exists(FieldAccess hostName |
      this.getTarget().hasGlobalName("gethostbyaddr") and
      hostName.getTarget().hasName("h_name") and
      hostName.getTarget().getDeclaringType().hasName("hostent") and
      DataFlow::localExprFlow(this, hostName.getQualifier()) and
      result.asIndirectExpr() = hostName
    )
    or
    this.getTarget().hasGlobalName(["getnameinfo", "GetNameInfoA", "GetNameInfoW"]) and
    result.asDefiningArgument() = this.getArgument(2)
  }
}

/** A call to a function that compares two strings or memory regions. */
private class ComparisonCall extends FunctionCall {
  ComparisonCall() {
    this.getTarget()
        .hasGlobalOrStdName([
            "strcmp", "strncmp", "strcasecmp", "strncasecmp", "stricmp", "strnicmp", "_stricmp",
            "_strnicmp", "strcmpi", "_strcmpi", "wcscmp", "wcsncmp", "wcsicmp", "_wcsicmp",
            "_wcsnicmp", "_mbscmp", "_mbsicmp", "lstrcmpA", "lstrcmpW", "lstrcmpiA", "lstrcmpiW",
            "CompareStringA", "CompareStringW", "memcmp", "strstr", "strcasestr", "wcsstr"
          ])
  }
}

/**
 * Holds if the result of `call` (eventually) controls a branch, that is, it is
 * used to make a decision.
 */
private predicate isUsedInDecision(ComparisonCall call) {
  exists(Expr e |
    DataFlow::localExprFlow(call, e) and
    (
      e = any(ConditionalStmt s).getControllingExpr().getAChild*()
      or
      e = any(ConditionalExpr c).getCondition().getAChild*()
    )
  )
}

/** Holds if `sink` is a string compared by `call` to make a decision. */
private predicate isDnsDecisionSink(DataFlow::Node sink, ComparisonCall call) {
  isUsedInDecision(call) and
  sink.asIndirectExpr() = call.getAnArgument()
}

private module DnsSecurityDecisionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = any(ReverseDnsLookupCall c).getHostNameNode()
  }

  predicate isSink(DataFlow::Node sink) { isDnsDecisionSink(sink, _) }
}

private module DnsSecurityDecisionFlow = TaintTracking::Global<DnsSecurityDecisionConfig>;

/**
 * Holds if the host name resolved by `lookup` is compared by `call` to make a
 * decision.
 */
predicate dnsSecurityDecision(ComparisonCall call, ReverseDnsLookupCall lookup) {
  exists(DataFlow::Node sink |
    DnsSecurityDecisionFlow::flow(lookup.getHostNameNode(), sink) and
    isDnsDecisionSink(sink, call)
  )
}

/*
 * CWE-428: Unquoted search path or element.
 *
 * Command lines that are string literals or `char *` variables pointing to a
 * literal are reported by the standard `cpp/unsafe-create-process-call` query.
 * That query does not report writable `char[]` buffers initialized from a
 * literal, so only that case is modeled here.
 */

/**
 * Holds if `name` is a process-creation function with the application name at
 * argument `appNameArg` and the command line at argument `cmdLineArg`.
 */
private predicate isCreateProcessFunction(string name, int appNameArg, int cmdLineArg) {
  name = ["CreateProcessA", "CreateProcessW"] and appNameArg = 0 and cmdLineArg = 1
  or
  name = ["CreateProcessAsUserA", "CreateProcessAsUserW"] and appNameArg = 1 and cmdLineArg = 2
  or
  name = "CreateProcessWithTokenW" and appNameArg = 2 and cmdLineArg = 3
  or
  name = "CreateProcessWithLogonW" and appNameArg = 4 and cmdLineArg = 5
}

/**
 * Holds if the command line `s` has an executable path that contains
 * whitespace and is not quoted.
 */
bindingset[s]
private predicate isUnquotedPathWithSpaces(string s) {
  not s.regexpMatch("\"([^\"])*\"[\\s\\S]*") and
  s.regexpMatch("[\\s\\S]*\\s[\\s\\S]*")
}

/**
 * Holds if `call` is passed a NULL application name and a local `char[]`
 * command line buffer `buffer`, initialized from the unquoted literal `cmdLine`.
 */
predicate unquotedCommandLineBuffer(FunctionCall call, LocalVariable buffer, string cmdLine) {
  exists(int appNameArg, int cmdLineArg |
    isCreateProcessFunction(call.getTarget().getName(), appNameArg, cmdLineArg) and
    call.getArgument(appNameArg).getValue() = "0" and
    call.getArgument(cmdLineArg).(VariableAccess).getTarget() = buffer and
    buffer.getUnspecifiedType() instanceof ArrayType and
    cmdLine = buffer.getInitializer().getExpr().(StringLiteral).getValue() and
    isUnquotedPathWithSpaces(cmdLine)
  )
}

/*
 * CWE-535: Exposure of information through shell error message.
 *
 * The standard `cpp/cleartext-storage-file` query deliberately excludes the
 * standard streams, so writes of sensitive data to standard error are
 * modeled here.
 */

/** Holds if `e` refers to the standard error stream. */
private predicate isStandardError(Expr e) {
  e.(VariableAccess).getTarget().hasName(["stderr", "cerr", "clog", "wcerr", "wclog"])
  or
  e.findRootCause().(Macro).getName() = "stderr"
}

/** Holds if `sink` is data written by `write` to standard error. */
private predicate isStandardErrorWriteSink(DataFlow::Node sink, Expr write) {
  exists(Expr source | source = [sink.asExpr(), sink.asIndirectExpr()] |
    isStandardError(write.(FileWrite).getDest()) and
    source = write.(FileWrite).getASource()
    or
    write.(FunctionCall).getTarget().hasGlobalOrStdName("perror") and
    source = write.(FunctionCall).getArgument(0)
    or
    isStandardError(write.(ChainedOutputCall).getEndDest()) and
    source = write.(ChainedOutputCall).getSource()
  )
}

private module SensitiveToStderrConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof SensitiveExpr }

  predicate isSink(DataFlow::Node sink) { isStandardErrorWriteSink(sink, _) }

  // Report only the sensitive expression closest to the sink.
  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr().getUnspecifiedType() instanceof IntegralType
  }
}

private module SensitiveToStderrFlow = TaintTracking::Global<SensitiveToStderrConfig>;

/**
 * Holds if sensitive data from `sensitive` is written to standard error by
 * `write`. `sensitive` is the sensitive variable when the data is read from a
 * variable, and otherwise the sensitive expression itself.
 */
predicate sensitiveDataToStderr(Expr write, Element sensitive) {
  exists(SensitiveExpr source, DataFlow::Node sourceNode, DataFlow::Node sink |
    sourceNode.asExpr() = source and
    SensitiveToStderrFlow::flow(sourceNode, sink) and
    isStandardErrorWriteSink(sink, write)
  |
    sensitive = source.(VariableAccess).getTarget()
    or
    not source instanceof VariableAccess and sensitive = source
  )
}
