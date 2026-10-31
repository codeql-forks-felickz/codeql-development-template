/**
 * @name Inefficient regular expression with large bounded repetition
 * @description A regular expression that nests a quantified term inside a bounded repetition
 *              with a large upper bound, such as `(a+){1,100}`, can require exponential time
 *              to match certain inputs and may be vulnerable to denial-of-service attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/redos-bounded-repetition
 * @tags security
 *       external/cwe/cwe-1333
 *       external/cwe/cwe-730
 *       external/cwe/cwe-400
 */

private import semmle.code.java.regex.RegexTreeView::RegexTreeView as TreeView
private import codeql.regex.RegexTreeView
import codeql.regex.nfa.ExponentialBackTracking::Make<TreeView> as StandardBackTracking

/**
 * Holds if `range` is a bounded repetition such as `{1,100}` or `{0,50}`.
 *
 * The shared NFA construction already treats these as `+` or `*` (an upper bound of 30
 * is enough for an exponential blow-up), but the shared exponential back-tracking analysis
 * only considers states nested inside an unbounded quantifier as back-tracking candidates.
 */
predicate isLargeBoundedRepetition(TreeView::RegExpRange range) {
  range.getLowerBound() in [0, 1] and
  range.getUpperBound() >= 30
}

/**
 * A view of the Java regular expression tree in which a large bounded repetition counts as an
 * infinite repetition. Everything else is the standard Java tree view.
 */
module BoundedRepetitionTreeView implements RegexTreeViewSig {
  class Top = TreeView::Top;

  class RegExpParent = TreeView::RegExpParent;

  class RegExpLiteral = TreeView::RegExpLiteral;

  class RegExpTerm = TreeView::RegExpTerm;

  class RegExpQuantifier = TreeView::RegExpQuantifier;

  class RegExpStar = TreeView::RegExpStar;

  class RegExpOpt = TreeView::RegExpOpt;

  class RegExpPlus = TreeView::RegExpPlus;

  class RegExpRange = TreeView::RegExpRange;

  class RegExpNonWordBoundary = TreeView::RegExpNonWordBoundary;

  class RegExpEscape = TreeView::RegExpEscape;

  class RegExpCharacterClassEscape = TreeView::RegExpCharacterClassEscape;

  class RegExpAlt = TreeView::RegExpAlt;

  class RegExpGroup = TreeView::RegExpGroup;

  class RegExpBackRef = TreeView::RegExpBackRef;

  class RegExpSequence = TreeView::RegExpSequence;

  class RegExpSubPattern = TreeView::RegExpSubPattern;

  class RegExpLookahead = TreeView::RegExpLookahead;

  class RegExpPositiveLookahead = TreeView::RegExpPositiveLookahead;

  class RegExpLookbehind = TreeView::RegExpLookbehind;

  class RegExpPositiveLookbehind = TreeView::RegExpPositiveLookbehind;

  class RegExpConstant = TreeView::RegExpConstant;

  class RegExpCharEscape = TreeView::RegExpCharEscape;

  class RegExpCharacterClass = TreeView::RegExpCharacterClass;

  class RegExpCharacterRange = TreeView::RegExpCharacterRange;

  class RegExpDot = TreeView::RegExpDot;

  class RegExpAnchor = TreeView::RegExpAnchor;

  class RegExpDollar = TreeView::RegExpDollar;

  class RegExpCaret = TreeView::RegExpCaret;

  class RegExpWordBoundary = TreeView::RegExpWordBoundary;

  /** An unbounded repetition, or a bounded repetition with a large upper bound. */
  class InfiniteRepetitionQuantifier extends TreeView::RegExpQuantifier {
    InfiniteRepetitionQuantifier() {
      this instanceof TreeView::InfiniteRepetitionQuantifier or
      isLargeBoundedRepetition(this)
    }
  }

  predicate isExcluded = TreeView::isExcluded/1;

  predicate isPossessive = TreeView::isPossessive/1;

  predicate matchesAnyPrefix = TreeView::matchesAnyPrefix/1;

  predicate matchesAnySuffix = TreeView::matchesAnySuffix/1;

  predicate isEscapeClass = TreeView::isEscapeClass/2;

  predicate isIgnoreCase = TreeView::isIgnoreCase/1;

  predicate isDotAll = TreeView::isDotAll/1;
}

import codeql.regex.nfa.ExponentialBackTracking::Make<BoundedRepetitionTreeView> as BoundedBackTracking

from TreeView::RegExpTerm t, string pump, BoundedBackTracking::State s, string prefixMsg
where
  BoundedBackTracking::hasReDoSResult(t, pump, s, prefixMsg) and
  // Only report terms whose exponential behavior depends on a large bounded repetition;
  // terms nested in unbounded repetitions are already reported by `java/redos`.
  isLargeBoundedRepetition(t.getParent*()) and
  not StandardBackTracking::hasReDoSResult(t, _, _, _) and
  // exclude verbose mode regexes, as `java/redos` does
  not t.getRegex().getAMode() = "VERBOSE"
select t,
  "This part of the regular expression may cause exponential backtracking on strings " + prefixMsg +
    "containing many repetitions of '" + pump + "'."
