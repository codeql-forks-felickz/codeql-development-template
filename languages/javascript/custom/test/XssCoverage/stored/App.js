import { GetComments } from "./Http.js";
import { Parse } from "./Comment.js";

// Out of scope: comments are loaded from the application's own backend API (stored /
// second-order flow). Treating all same-origin API responses as remote sources would be
// far too noisy for the default query suite, so this remains a known false negative.
export async function loadComments() {
  const response = await GetComments();
  Object.values(response.comments).forEach(function (comment) {
    Parse(comment);
  });
}
