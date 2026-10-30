const User = require('./models/user');

// Not reported by this query: a top-level field is already reported by `js/sql-injection`.
const register = async (user) => {
  const { email, password } = user;
  const existUser = await User.findOne({ email: email });
  if (existUser) { return null; }
  const newUser = new User({ email: email, password: password });
  await newUser.save();
  return newUser;
};

// Vulnerable: `$and` sub-documents receive request values that may be objects.
const login = async (credentials) => {
  const { email, password } = credentials;
  const existsUser = await User.find({ $and: [{ email: email }, { password: password }] }); // $ Alert
  return existsUser.map((user) => user.email);
};

// Safe: both values are checked to be strings before use.
const safeLogin = async (credentials) => {
  const { email, password } = credentials;
  if (typeof email !== 'string' || typeof password !== 'string') { return null; }
  const existsUser = await User.find({ $and: [{ email: email }, { password: password }] });
  return existsUser.map((user) => user.email);
};

module.exports = { register, login, safeLogin };
