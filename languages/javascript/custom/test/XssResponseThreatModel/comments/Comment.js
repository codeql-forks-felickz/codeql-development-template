export function Parse(comment) {
  const k = comment.substring(8);
  const z = k.substring(0, k.lastIndexOf("<"));
  eval(z); // $ Alert[js/code-injection]
}

export function Count(comment) {
  // Safe: written as text, not evaluated.
  document.title = comment;
}
