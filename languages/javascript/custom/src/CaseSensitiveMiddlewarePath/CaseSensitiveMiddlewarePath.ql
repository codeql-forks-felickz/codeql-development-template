/**
 * @name Case-sensitive middleware path
 * @description Middleware with case-sensitive paths do not protect endpoints with case-insensitive paths.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.3
 * @precision high
 * @id js/case-sensitive-middleware-path
 * @tags security
 *       external/cwe/cwe-178
 */

/*
 * Customized variant of the upstream `js/case-sensitive-middleware-path` query. In addition to the
 * upstream logic (unchanged), it reports middleware that is skipped for request paths matching a
 * case-sensitive *exclusion* regular expression, either through an `unless({ path: ... })` option
 * (as in `express-unless`) or through an early `return next()` guarded by a regular expression test
 * of `req.path`. If an endpoint path is protected by the middleware but a differently cased variant
 * of it is excluded, the middleware can be bypassed.
 */

import javascript

/**
 * Converts `s` to upper case, or to lower-case if it was already upper case.
 */
bindingset[s]
string toOtherCase(string s) {
  if s.regexpMatch(".*[a-z].*") then result = s.toUpperCase() else result = s.toLowerCase()
}

private import semmle.javascript.security.regexp.RegExpTreeView::RegExpTreeView as TreeView
import codeql.regex.nfa.NfaUtils::Make<TreeView> as NfaUtils

/** Holds if `s` is a relevant regexp term were we want to compute a string that matches the term (for `getCaseSensitiveBypassExample`). */
predicate isCand(NfaUtils::State s) {
  s.getRepr() instanceof NfaUtils::RegExpRoot and
  exists(DataFlow::RegExpCreationNode creation |
    isCaseSensitiveMiddleware(_, creation, _) and
    s.getRepr().getRootTerm() = creation.getRoot()
  )
}

import NfaUtils::PrefixConstruction<isCand/1> as Prefix

/** Gets a string matched by `term`. */
string getExampleString(RegExpTerm term) {
  result = Prefix::prefix(any(NfaUtils::State s | s.getRepr() = term))
}

string getCaseSensitiveBypassExample(RegExpTerm term) {
  exists(string byPassExample |
    byPassExample = getExampleString(term) and
    result = toOtherCase(byPassExample) and
    result != byPassExample // getting an byPassExample string is approximate; ensure we got a proper case-change byPassExample
  )
}

/**
 * Holds if `setup` has a path-argument `arg` referring to the given case-sensitive `regexp`.
 */
predicate isCaseSensitiveMiddleware(
  Routing::RouteSetup setup, DataFlow::RegExpCreationNode regexp, DataFlow::Node arg
) {
  exists(DataFlow::MethodCallNode call |
    setup = Routing::getRouteSetupNode(call) and
    (
      setup.definitelyResumesDispatch()
      or
      // If applied to all HTTP methods, be a bit more lenient in detecting middleware
      setup.mayResumeDispatch() and
      not exists(setup.getOwnHttpMethod())
    ) and
    arg = call.getArgument(0) and
    regexp.getAReference().flowsTo(arg) and
    exists(string flags |
      flags = regexp.tryGetFlags() and
      not RegExp::maybeIgnoreCase(flags)
    )
  )
}

predicate isGuardedCaseInsensitiveEndpoint(
  Routing::RouteSetup endpoint, Routing::RouteSetup middleware
) {
  isCaseSensitiveMiddleware(middleware, _, _) and
  exists(DataFlow::MethodCallNode call |
    endpoint = Routing::getRouteSetupNode(call) and
    endpoint.isGuardedByNode(middleware) and
    call.getArgument(0).mayHaveStringValue(_)
  )
}

/**
 * Gets an example path that will hit `endpoint`.
 * Query parameters (e.g. the ":param" in "/foo/:param") have been replaced with example values.
 */
string getAnEndpointExample(Routing::RouteSetup endpoint) {
  exists(string raw |
    raw = endpoint.getRelativePath() and
    result = raw.regexpReplaceAll(":\\w+\\b|\\*", ["a", "1"])
  )
}

import codeql.regex.nfa.RegexpMatching::Make<TreeView> as RegexpMatching

NfaUtils::RegExpRoot getARoot(DataFlow::RegExpCreationNode creator) {
  result.getRootTerm() = creator.getRoot()
}

/**
 * Holds if the regexp matcher should test whether `root` matches `str`.
 * The result is used to test whether a case-sensitive bypass exists.
 */
predicate isMatchingCandidate(
  RegexpMatching::RootTerm root, string str, boolean ignorePrefix, boolean testWithGroups
) {
  exists(
    Routing::RouteSetup middleware, Routing::RouteSetup endPoint,
    DataFlow::RegExpCreationNode regexp
  |
    isCaseSensitiveMiddleware(middleware, regexp, _) and
    isGuardedCaseInsensitiveEndpoint(endPoint, middleware)
  |
    root = regexp.getRoot() and
    exists(getCaseSensitiveBypassExample(getARoot(regexp))) and
    ignorePrefix = true and
    testWithGroups = false and
    str =
      [
        getCaseSensitiveBypassExample(getARoot(regexp)), getAnEndpointExample(endPoint),
        toOtherCase(getAnEndpointExample(endPoint))
      ]
  )
}

import RegexpMatching::RegexpMatching<isMatchingCandidate/4> as Matcher

/**
 * Holds if `s` exits the route handler `handler` after invoking its continuation (`next`),
 * as in `return next();` or `{ next(); return; }`.
 */
predicate returnsAfterContinuation(Stmt s, DataFlow::FunctionNode handler) {
  s.(ReturnStmt).getExpr().stripParens() = handler.getParameter(2).getACall().asExpr()
  or
  exists(BlockStmt block | block = s |
    returnsAfterContinuation(block.getStmt(block.getNumStmt() - 1), handler)
  )
  or
  exists(BlockStmt block | block = s |
    block.getStmt(block.getNumStmt() - 1) instanceof ReturnStmt and
    block.getAStmt().(ExprStmt).getExpr().stripParens() =
      handler.getParameter(2).getACall().asExpr()
  )
}

/**
 * Holds if `setup` installs middleware that is skipped for request paths where testing the
 * case-sensitive `regexp` (at `use`) yields `skipOnMatch`.
 */
predicate isCaseSensitiveExclusionMiddleware(
  Routing::RouteSetup setup, DataFlow::RegExpCreationNode regexp, DataFlow::Node use,
  boolean skipOnMatch
) {
  exists(DataFlow::MethodCallNode call |
    setup = Routing::getRouteSetupNode(call) and
    setup.mayResumeDispatch() and
    not exists(setup.getOwnHttpMethod()) and
    not exists(setup.getRelativePath()) and
    exists(string flags |
      flags = regexp.tryGetFlags() and
      not RegExp::maybeIgnoreCase(flags)
    )
  |
    // `app.use(middleware.unless({ path: /.../ }))`, as in `express-unless` and `express-jwt`
    exists(DataFlow::MethodCallNode unless, DataFlow::Node path |
      unless.getMethodName() = "unless" and
      unless.flowsTo(call.getAnArgument()) and
      path = unless.getOptionArgument(0, "path") and
      (use = path or use = path.(DataFlow::ArrayCreationNode).getAnElement()) and
      regexp.getAReference().flowsTo(use) and
      skipOnMatch = true
    )
    or
    // `app.use((req, res, next) => { if (/.../.test(req.path)) return next(); ... })`
    exists(DataFlow::FunctionNode handler, IfStmt guard, DataFlow::MethodCallNode test, Expr cond |
      handler.flowsTo(call.getAnArgument()) and
      guard.getContainer() = handler.getFunction() and
      test = regexp.getAReference().getAMethodCall("test") and
      handler
          .getParameter(0)
          .getAPropertyRead(["path", "url", "originalUrl"])
          .flowsTo(test.getArgument(0)) and
      cond = guard.getCondition().stripParens() and
      (
        cond = test.asExpr() and skipOnMatch = true
        or
        cond.(LogNotExpr).getOperand().stripParens() = test.asExpr() and skipOnMatch = false
      ) and
      returnsAfterContinuation(guard.getThen(), handler) and
      use = test
    )
  )
}

/**
 * Holds if `endpoint` has a constant path and is guarded by the exclusion middleware `middleware`
 * that uses `regexp`.
 */
predicate isGuardedByExclusionMiddleware(
  Routing::RouteSetup endpoint, Routing::RouteSetup middleware, DataFlow::RegExpCreationNode regexp
) {
  isCaseSensitiveExclusionMiddleware(middleware, regexp, _, _) and
  exists(DataFlow::MethodCallNode call |
    endpoint = Routing::getRouteSetupNode(call) and
    endpoint.isGuardedByNode(middleware) and
    call.getArgument(0).mayHaveStringValue(_)
  )
}

/** Holds if `str` should be tested against the exclusion regular expression `regexp`. */
predicate isExclusionCandidate(DataFlow::RegExpCreationNode regexp, string str) {
  exists(Routing::RouteSetup endpoint, string example |
    isGuardedByExclusionMiddleware(endpoint, _, regexp) and
    example = getAnEndpointExample(endpoint) and
    str = [example, toOtherCase(example)]
  )
}

/** Gets a literal string matched by `term`, which consists only of constants, groups and alternations. */
string getALiteralString(RegExpTerm term) {
  result = term.(RegExpConstant).getValue()
  or
  result = getALiteralString(term.(RegExpGroup).getAChild())
  or
  result = getALiteralString(term.(RegExpAlt).getAChild())
  or
  result = getALiteralSequencePrefix(term, term.getNumChild()) and
  term instanceof RegExpSequence
}

/** Gets a literal string matched by the first `n` children of the sequence `seq`. */
private string getALiteralSequencePrefix(RegExpSequence seq, int n) {
  n = 0 and result = ""
  or
  result = getALiteralSequencePrefix(seq, n - 1) + getALiteralString(seq.getChild(n - 1)) and
  result.length() < 100
}

/**
 * Holds if `root` has the form `^(?!X)` optionally followed by `.*`, where `lookahead` is the
 * negative lookahead `(?!X)`. Such a regular expression matches exactly the strings that do not
 * start with a string matched by `X`.
 */
predicate isNegatedPrefixRegExp(RegExpTerm root, RegExpNegativeLookahead lookahead) {
  root.(RegExpSequence).getChild(0) instanceof RegExpCaret and
  root.(RegExpSequence).getChild(1) = lookahead and
  exists(getALiteralString(lookahead.getOperand())) and
  forall(int i, RegExpTerm rest | rest = root.(RegExpSequence).getChild(i) and i > 1 |
    rest.(RegExpStar).getChild(0) instanceof RegExpDot
  )
}

/**
 * Holds if the regexp matcher should test whether `root` matches `str`, using the semantics of
 * `RegExp.prototype.test` (that is, the match may start anywhere unless anchored).
 */
predicate isExclusionMatchingCandidate(
  RegexpMatching::RootTerm root, string str, boolean ignorePrefix, boolean testWithGroups
) {
  exists(DataFlow::RegExpCreationNode regexp |
    isExclusionCandidate(regexp, str) and
    root = regexp.getRoot() and
    not isNegatedPrefixRegExp(root, _) and
    ignorePrefix = false and
    testWithGroups = false
  )
}

import RegexpMatching::RegexpMatching<isExclusionMatchingCandidate/4> as ExclusionMatcher

/** Holds if the exclusion regular expression `regexp` matches the candidate string `str`. */
predicate exclusionRegExpMatches(DataFlow::RegExpCreationNode regexp, string str) {
  isExclusionCandidate(regexp, str) and
  (
    exists(RegExpNegativeLookahead lookahead | isNegatedPrefixRegExp(regexp.getRoot(), lookahead) |
      not exists(string prefix | prefix = getALiteralString(lookahead.getOperand()) |
        str.prefix(prefix.length()) = prefix
      )
    )
    or
    ExclusionMatcher::matches(regexp.getRoot(), str)
  )
}

/**
 * Holds if a request for the candidate path `str` is processed by the exclusion middleware
 * that is skipped when testing `regexp` yields `skipOnMatch`.
 */
bindingset[skipOnMatch]
predicate isProcessedByExclusionMiddleware(
  DataFlow::RegExpCreationNode regexp, boolean skipOnMatch, string str
) {
  isExclusionCandidate(regexp, str) and
  if exclusionRegExpMatches(regexp, str) then skipOnMatch = false else skipOnMatch = true
}

/**
 * Holds if `use` is a case-sensitive exclusion pattern `regexp` that makes the middleware
 * `middleware` skip `byPassEndPoint`, a differently cased variant of a path of `endpoint`
 * that is otherwise processed by `middleware`.
 */
predicate isCaseSensitiveExclusionBypass(
  DataFlow::Node use, DataFlow::RegExpCreationNode regexp, Routing::RouteSetup endpoint,
  string byPassEndPoint
) {
  exists(Routing::RouteSetup middleware, boolean skipOnMatch, string endpointExample |
    isCaseSensitiveExclusionMiddleware(middleware, regexp, use, skipOnMatch) and
    isGuardedByExclusionMiddleware(endpoint, middleware, regexp) and
    // only report one example.
    endpointExample =
      min(string ex |
        ex = getAnEndpointExample(endpoint) and
        isProcessedByExclusionMiddleware(regexp, skipOnMatch, ex) and
        not isProcessedByExclusionMiddleware(regexp, skipOnMatch, toOtherCase(ex))
      ) and
    byPassEndPoint = toOtherCase(endpointExample)
  )
}

from
  DataFlow::Node arg, DataFlow::RegExpCreationNode regexp, Routing::RouteSetup endpoint, string msg
where
  exists(
    Routing::RouteSetup middleware, string byPassExample, string endpointExample,
    string byPassEndPoint
  |
    isCaseSensitiveMiddleware(middleware, regexp, arg) and
    byPassExample = getCaseSensitiveBypassExample(getARoot(regexp)) and
    isGuardedCaseInsensitiveEndpoint(endpoint, middleware) and
    // only report one example.
    endpointExample =
      min(string ex | ex = getAnEndpointExample(endpoint) and Matcher::matches(regexp.getRoot(), ex)) and
    not Matcher::matches(regexp.getRoot(), byPassExample) and
    byPassEndPoint = toOtherCase(endpointExample) and
    not Matcher::matches(regexp.getRoot(), byPassEndPoint) and
    msg =
      "This route uses a case-sensitive path $@, but is guarding a $@. A path such as '" +
        byPassEndPoint + "' will bypass the middleware."
  )
  or
  exists(string byPassEndPoint |
    isCaseSensitiveExclusionBypass(arg, regexp, endpoint, byPassEndPoint) and
    msg =
      "This middleware is skipped for paths matching the case-sensitive exclusion $@, but is guarding a $@. A path such as '"
        + byPassEndPoint + "' will bypass the middleware."
  )
select arg, msg, regexp, "pattern", endpoint, "case-insensitive path"
