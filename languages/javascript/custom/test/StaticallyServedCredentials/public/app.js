// Client-side code: form labels and empty defaults are not credentials.
var form = {
  passwordLabel: "Enter your password", // OK: contains whitespace
  password: "", // OK: empty
  passwordHash: "5f4dcc3b5aa765d61d8327deb882cf99", // OK: hashed
  inputType: "password" // OK: name is not sensitive
};
var apiKey = "AKIAEXAMPLEKEY123"; // NOT OK
