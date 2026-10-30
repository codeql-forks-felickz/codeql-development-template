var express = require('express');
var bodyParser = require('body-parser');
var mongo = require('mongodb').MongoClient;

var app = express();
app.use(bodyParser.json());

// Reduced from the Pixi `api_register` function: the new account's `is_admin`
// flag is chosen by the (anonymous) caller.
function api_register(user, pass, req, res) {
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').findOne({ email: user }, function (err, result) {
      if (result !== null) {
        res.status(202).json({ message: user + ' is already registered.' });
      } else {
        if (req.body.is_admin) {
          var admin = true;
        } else {
          var admin = false;
        }
        db.collection('counters').findAndModify({ _id: 'userid' }, [], { $inc: { seq: 1 } }, function (err, doc) {
          db.collection('users').insert({
            _id: doc.value.seq,
            email: user,
            password: pass,
            is_admin: admin, // $ Alert
            all_pictures: []
          });
        });
      }
    });
  });
}

app.post('/api/register', function (req, res) {
  api_register(req.body.user, req.body.pass, req, res);
});

// Reduced from the Pixi `/api/user/edit_info` handler: any authenticated user
// can promote themselves by sending `is_admin` in the body.
app.put('/api/user/edit_info', function (req, res) {
  var objForUpdate = {};
  if (req.body.email) { objForUpdate.email = req.body.email; }
  if (req.body.name) { objForUpdate.name = req.body.name; }
  if (req.body.is_admin) { objForUpdate.is_admin = true; } // $ Alert
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').findOneAndUpdate({ _id: Number(req.user.user._id) }, { $set: objForUpdate }, function (err, u) {
      res.status(200).json({ message: 'User Successfully Updated' });
    });
  });
});

// Direct taint from the request body into a privilege field of a stored record.
app.post('/api/signup', function (req, res) {
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').insertOne({ email: req.body.email, role: req.body.role }); // $ Alert
  });
});

// Ternary on a user-controlled privilege flag.
app.post('/api/signup2', function (req, res) {
  var admin = req.body.isAdmin ? true : false;
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').insertOne({ email: req.body.email, isAdmin: admin }); // $ Alert
  });
});

// Property write on a loaded model followed by `save()`.
app.post('/api/profile', function (req, res) {
  var user = loadUser(req.user.id);
  user.name = req.body.name;
  user.role = req.body.role; // $ Alert
  user.save();
});

// ---------------------------------------------------------------------------
// Safe counterparts: none of these should alert.
// ---------------------------------------------------------------------------

// The privilege flag is fixed by the server.
app.post('/api/register_safe', function (req, res) {
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').insert({ email: req.body.user, password: req.body.pass, is_admin: false });
  });
});

// The requested role is restricted to an allow-list of unprivileged roles.
app.post('/api/signup_safe', function (req, res) {
  if (['customer', 'deluxe'].includes(req.body.role)) {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ email: req.body.email, role: req.body.role });
    });
  }
});

// Checking a different request property does not constrain the value being stored.
app.post('/api/signup_cookie_check', function (req, res) {
  if (['customer', 'deluxe'].includes(req.cookies.role)) {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role }); // $ Alert
    });
  }
});

// A check of a nested property does not constrain the top-level property.
app.post('/api/signup_nested_check', function (req, res) {
  if (['customer', 'deluxe'].includes(req.body.user.role)) {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role }); // $ Alert
    });
  }
});

// Equality with an unprivileged value restricts the stored role.
app.post('/api/signup_equality_safe', function (req, res) {
  if (req.body.role === 'customer') {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role });
    });
  }
});

// Equality with a privileged value still permits a privilege grant.
app.post('/api/signup_equality_admin', function (req, res) {
  if (req.body.role === 'admin') {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role }); // $ Alert
    });
  }
});

// Only an existing administrator may grant the privilege.
app.put('/api/admin/edit_info', function (req, res) {
  var objForUpdate = {};
  if (req.user.is_admin) {
    if (req.body.is_admin) { objForUpdate.is_admin = true; }
  }
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').findOneAndUpdate({ _id: Number(req.body.user_id) }, { $set: objForUpdate });
  });
});

// A negated privilege check does not authorize the then-branch.
app.post('/api/not_admin', function (req, res) {
  if (!req.user.is_admin) {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role }); // $ Alert
    });
  }
});

// The else-branch of a positive privilege check is not authorized.
app.post('/api/admin_else', function (req, res) {
  if (req.user.is_admin) {
    res.send('not changing the role');
  } else {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role }); // $ Alert
    });
  }
});

// A disjunction does not prove that either privilege check succeeded.
app.post('/api/admin_or_staff', function (req, res) {
  if (req.user.is_admin || req.user.is_staff) {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role }); // $ Alert
    });
  }
});

// The else-branch of a negated privilege check is authorized.
app.post('/api/not_admin_else', function (req, res) {
  if (!req.user.is_admin) {
    res.send('not changing the role');
  } else {
    mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
      db.collection('users').insertOne({ role: req.body.role });
    });
  }
});

// An unrelated guarded assignment must not suppress the unchecked value.
app.post('/api/admin_conditional_value', function (req, res) {
  var role = req.body.role;
  if (req.user.is_admin) {
    role = 'admin';
  }
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').insertOne({ role: role }); // $ Alert
  });
});

// An earlier conditional definition does not reach the persisted value.
app.post('/api/unconditional_overwrite', function (req, res) {
  var admin = false;
  if (req.body.is_admin) {
    admin = true;
  }
  admin = false;
  db.collection('users').insertOne({ is_admin: admin });
});

// User input used only to filter a query, not to write a record.
app.get('/api/users_by_role', function (req, res) {
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').find({ role: req.query.role }).toArray(function (err, users) {
      res.json(users);
    });
  });
});

// Update filters are not persisted, but the update document is.
app.put('/api/update_one', function (req, res) {
  var users = mongo.connect('mongodb://pixidb:27017/Pixidb');
  users.updateOne({ role: req.query.role }, { $set: { name: req.body.name } });
  users.updateOne({ role: req.query.role }, { $set: { role: req.body.role } }); // $ Alert
});

app.put('/api/find_one_and_update', function (req, res) {
  var users = mongo.connect('mongodb://pixidb:27017/Pixidb');
  users.findOneAndUpdate({ role: req.query.role }, { $set: { name: req.body.name } });
  users.findOneAndUpdate({ role: req.query.role }, { $set: { role: req.body.role } }); // $ Alert
});

app.put('/api/find_and_modify', function (req, res) {
  var users = mongo.connect('mongodb://pixidb:27017/Pixidb');
  users.findAndModify({ role: req.query.role }, [], { $set: { name: req.body.name } });
  users.findAndModify({ role: req.query.role }, [], { $set: { role: req.body.role } }); // $ Alert
});

app.put('/api/sequelize_update', function (req, res) {
  var User = require('./models/user');
  User.update({ name: req.body.name }, { where: { role: req.query.role } });
  User.update({ role: req.body.role }, { where: { role: req.query.role } }); // $ Alert
});

// Echoing the value back in a response does not change any privileges.
app.post('/api/echo', function (req, res) {
  res.json({ role: req.body.role });
});

// Non-privileged fields may come from the request body.
app.put('/api/user/rename', function (req, res) {
  var objForUpdate = {};
  if (req.body.name) { objForUpdate.name = req.body.name; }
  mongo.connect('mongodb://pixidb:27017/Pixidb', function (err, db) {
    db.collection('users').findOneAndUpdate({ _id: Number(req.user.user._id) }, { $set: objForUpdate });
  });
});

app.listen(8090);
