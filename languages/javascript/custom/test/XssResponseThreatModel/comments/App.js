import { GetComments } from "./Http.js";
import { Parse, Count } from "./Comment.js";

export async function loadComments() {
  const response = await GetComments();
  Object.values(response.comments).forEach(function (comment) {
    Parse(comment);
    Count(comment);
  });
}
