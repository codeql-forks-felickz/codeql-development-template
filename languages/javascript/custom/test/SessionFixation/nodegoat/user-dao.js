function UserDAO(db) {
  const usersCol = db.collection("users");
  this.validateLogin = (userName, password, callback) => {
    usersCol.findOne({ userName: userName }, (err, user) => {
      if (err) return callback(err, null);
      if (user && user.password === password) return callback(null, user);
      return callback({ invalidPassword: true }, null);
    });
  };
}

module.exports = { UserDAO };
