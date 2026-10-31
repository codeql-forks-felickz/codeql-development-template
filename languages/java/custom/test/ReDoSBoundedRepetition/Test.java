import java.util.regex.Pattern;

public class Test {
  boolean bad1(String word) {
    // BAD: nested quantifier inside a large bounded repetition; the separator is optional.
    return Pattern.compile("^([a-z0-9]+[-]{0,1}){1,100}$").matcher(word).matches(); // $ Alert
  }

  boolean bad2(String word) {
    // BAD: same pattern with `?` for the optional separator.
    return word.matches("^([a-z0-9]+-?){1,100}$"); // $ Alert
  }

  boolean bad3(String word) {
    // BAD: `{0,N}` with a large upper bound behaves like `*`.
    return Pattern.matches("(\\w+\\s?){0,50}x", word); // $ Alert
  }

  boolean bad4(String word) {
    // BAD: alternation of overlapping terms inside a large bounded repetition.
    return word.matches("^(a|a){1,64}$"); // $ Alert
  }

  boolean alreadyReported(String word) {
    // NOT REPORTED HERE: unbounded outer repetition, already reported by `java/redos`.
    return word.matches("^([a-z0-9]+-?)+$");
  }

  boolean good1(String word) {
    // GOOD: the separator is mandatory, so each iteration can only be matched one way.
    return word.matches("^([a-z0-9]+-){1,100}[a-z0-9]+$");
  }

  boolean good2(String word) {
    // GOOD: a small upper bound limits the amount of backtracking.
    return word.matches("^([a-z0-9]+-?){1,5}$");
  }

  boolean good3(String word) {
    // GOOD: linear-time equivalent of `bad1`.
    return word.matches("^[a-z0-9]+(-[a-z0-9]+)*-?$");
  }

  boolean good4(String word) {
    // GOOD: possessive inner quantifier cannot backtrack.
    return word.matches("^([a-z0-9]++-?){1,100}$");
  }
}
