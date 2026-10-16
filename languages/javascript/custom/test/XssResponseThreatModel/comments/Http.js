export async function GetComments() {
  const response = await fetch("http://localhost:10017/comments"); // $ Source[js/code-injection]
  const body = await response.json();
  return body;
}
