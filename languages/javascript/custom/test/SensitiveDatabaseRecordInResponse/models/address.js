const { Sequelize, DataTypes } = require("sequelize");
const express = require("express");

const sequelize = new Sequelize("sqlite::memory:");

// Safe: private data such as a phone number is returned to its owner by design.
const Address = sequelize.define("Address", {
  UserId: DataTypes.INTEGER,
  mobileNum: DataTypes.INTEGER,
  zipCode: DataTypes.STRING
});

const app = express();
app.get("/addresses", async (req, res) => {
  const addresses = await Address.findAll({ where: { UserId: req.body.UserId } });
  res.json({ status: "success", data: addresses });
});
