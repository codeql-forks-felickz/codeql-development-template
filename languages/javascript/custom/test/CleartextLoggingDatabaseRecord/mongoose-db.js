const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const Todo = new Schema({ content: Buffer, updated_at: Date });
mongoose.model("Todo", Todo);

let User = new Schema({ username: String, password: String });
mongoose.model("User", User);

// Reduced from nodejs-goof: the startup check logs the whole admin user documents.
User = mongoose.model("User");
User.find({ username: "admin@example.com" }).exec(function (err, users) { // $ Source
  console.log(users); // $ Alert
  console.log(users.length); // Safe: not a record field.
  console.log(users[0].username); // Safe: a non-sensitive field.
  if (users.length === 0) {
    console.log("no admin");
  }
});

// Safe: the Todo model has no sensitive fields.
mongoose.model("Todo").find().exec(function (err, todos) {
  console.log(todos);
});

async function lookups(email) {
  const user = await User.findOne({ email }); // $ Source
  console.log(user); // $ Alert
  console.log("password is " + user.password); // $ Alert
  console.log(JSON.stringify(user.toObject())); // $ Alert

  User.findById(email, (err, u) => console.log(u)); // $ Alert
  User.findOne({ email }).then((u) => console.log(u)); // $ Alert

  // Safe: the query only returns the selected fields.
  const named = await User.findOne({ email }, "username");
  console.log(named);
  const projected = await User.findOne({ email }).select("-password");
  console.log(projected);
}

// Safe: the password path is excluded from query results by default.
const HiddenUser = mongoose.model(
  "HiddenUser",
  new Schema({ username: String, password: { type: String, select: false } })
);

async function hidden(email) {
  console.log(await HiddenUser.findOne({ email }));
}
