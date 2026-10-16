export async function GetComments() {
  const response = await fetch("http://localhost:10017/comments");
  return await response.json();
}
