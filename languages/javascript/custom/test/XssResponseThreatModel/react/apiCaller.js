export function callApi(opts) {
  return fetch("https://api.example.com/order", { method: "post", body: JSON.stringify(opts) });
}
