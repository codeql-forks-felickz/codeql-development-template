const { Sequelize, DataTypes } = require("sequelize");

const sequelize = new Sequelize("sqlite::memory:");

const Login = sequelize.define("Login", {
  email: DataTypes.STRING,
  password: DataTypes.STRING
});

async function audit() {
  const logins = await Login.findAll(); // $ Source
  console.info("logins", logins); // $ Alert

  // Safe: only non-sensitive attributes are loaded.
  const emails = await Login.findAll({ attributes: ["email"] });
  console.info("emails", emails);
}
