const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
  id: String,
  owner: String,
  title: String,
  content: String
});

module.exports = mongoose.model('Note', noteSchema);
