/**
 * Provides a refinement of the standard Go XSS sanitizers that is shared by the
 * custom XSS queries in this pack.
 */

import go
import semmle.go.security.Xss

/**
 * A regular-expression replacement whose pattern matches specific HTML tag
 * names, such as `<script>`, rather than HTML meta-characters in general.
 *
 * The standard `SharedXss::MetacharEscapeSanitizer` treats every regexp
 * replacement whose pattern contains an HTML meta-character as a complete
 * sanitizer. A tag-name blocklist does not neutralize HTML: other tags (for
 * example `<img src=x onerror=...>` or `<svg onload=...>`), event-handler
 * attributes and case or spacing variants of the blocked tag still execute
 * script. Such replacements are therefore not treated as XSS sanitizers by the
 * custom queries.
 *
 * Patterns that remove every tag or meta-character (for example `<[^>]*>`,
 * `<\/?[^>]+>` or `[<>]`) are not matched, and remain sanitizers.
 */
class TagNameBlocklistReplacement extends DataFlow::CallNode {
  TagNameBlocklistReplacement() {
    exists(RegexpReplaceFunction f | f = this.getCall().getTarget() |
      // a `<` followed, possibly after a `/`, optional whitespace, a group
      // opening or a case-insensitivity flag, by a literal tag-name letter
      f.getRegexp(this)
          .getPattern()
          .regexpMatch("(?s).*<(/|\\?|\\(\\?:|\\(\\?i\\)|\\(|\\\\s[*+?]?|\\\\/)*[a-zA-Z].*")
    )
  }
}

/**
 * Holds if `node` is a standard XSS sanitizer that the custom XSS queries
 * still trust, that is, it is not a tag-name blocklist replacement.
 */
predicate isTrustedXssSanitizer(DataFlow::Node node) {
  node instanceof SharedXss::Sanitizer and
  not node instanceof TagNameBlocklistReplacement
}
