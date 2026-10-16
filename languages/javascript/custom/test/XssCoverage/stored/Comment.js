export function Parse(comment) {
  const k = comment.substring(8);
  eval(k); // $ MISSING: Alert[js/code-injection]
}
