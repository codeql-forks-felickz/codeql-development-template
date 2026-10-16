const bcrypt = require("bcrypt-nodejs");

// Reduced from the NodeGoat `UserDAO`: a password is written to a MongoDB document as-is.
function UserDAO(db) {
    const usersCol = db.collection("users");

    this.addUser = (userName, firstName, lastName, password, email, callback) => {
        const user = {
            userName,
            firstName,
            lastName,
            password // $ Alert
        };

        if (email) {
            user.email = email;
        }

        this.getNextSequence("userId", (err, id) => {
            user._id = id;
            usersCol.insert(user, (err, result) => callback(err, result));
        });
    };

    // Safe: the password is hashed before it is persisted.
    this.addUserHashed = (userName, password, callback) => {
        const user = {
            userName,
            password: bcrypt.hashSync(password, bcrypt.genSaltSync())
        };
        usersCol.insertOne(user, callback);
    };

    // Safe: the sensitive variable already holds a hash.
    this.changePassword = (userName, newPassword, callback) => {
        const password = bcrypt.hashSync(newPassword, bcrypt.genSaltSync());
        usersCol.updateOne({ userName }, { $set: { password } }, callback);
    };

    // Safe: only non-sensitive fields are persisted.
    this.touchUser = (userName, lastLogin, callback) => {
        usersCol.updateOne({ userName }, { $set: { lastLogin } }, callback);
    };

    // Safe: the password is only used as a query filter, not written to the database.
    this.validateLogin = (userName, password, callback) => {
        usersCol.findOne({ userName, password }, callback);
    };

    this.getNextSequence = (name, callback) => {
        db.collection("counters").findAndModify({ _id: name }, [], { $inc: { seq: 1 } }, { new: true },
            (err, data) => callback(err, data && data.value.seq));
    };
}

module.exports = { UserDAO };
