function login(password) {
  return fetch("/login", { method: "POST", body: JSON.stringify({ password: password }) }); // OK: not a literal
}
