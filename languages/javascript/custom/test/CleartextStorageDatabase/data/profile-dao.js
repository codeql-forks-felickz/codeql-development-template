const crypto = require("crypto");

// Reduced from the NodeGoat `ProfileDAO`: private data (SSN) is written to MongoDB as-is.
function ProfileDAO(db) {
    const users = db.collection("users");

    const encrypt = (toEncrypt) => {
        const cipher = crypto.createCipheriv("aes-256-gcm", process.env.KEY, process.env.IV);
        return cipher.update(toEncrypt, "utf8", "hex") + cipher.final("hex");
    };

    this.updateUser = (userId, firstName, ssn, callback) => {
        const user = {};
        if (firstName) {
            user.firstName = firstName;
        }
        if (ssn) {
            user.ssn = ssn; // $ Alert
        }
        users.update({ _id: parseInt(userId) }, { $set: user }, callback);
    };

    // A sensitive value stored under a field whose name does not look sensitive.
    this.setTaxId = (userId, ssn, callback) => {
        users.updateOne({ _id: parseInt(userId) }, { $set: { taxId: ssn } }, callback); // $ Alert
    };

    // Safe: the SSN is encrypted before it is persisted.
    this.updateUserEncrypted = (userId, ssn, callback) => {
        const user = {};
        if (ssn) {
            user.ssn = encrypt(ssn);
        }
        users.updateOne({ _id: parseInt(userId) }, { $set: user }, callback);
    };
}

module.exports = { ProfileDAO };
