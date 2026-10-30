var express = require('express');
var mysql = require('db-mysql');

var app = express();
var db = new mysql.Database({ hostname: 'localhost', user: 'user', password: 'password', database: 'test' });

app.get('/customers', function (req, res) {
  var name = req.query.name;

  // BAD: request data concatenated into SQL passed to `Database.query`
  db.query('SELECT * FROM Customers WHERE ContactName = ' + name).execute(function (error, rows) {});

  // BAD: request data concatenated into SQL passed to `Query.execute`
  db.query().execute("SELECT * FROM Customers WHERE ContactName = '" + name + "'", function (error, rows) {});

  // GOOD: request data bound as a placeholder value
  db.query('SELECT * FROM Customers WHERE ContactName = ?', [name]).execute(function (error, rows) {});

  // GOOD: request data escaped with `Database.escape`
  db.query("SELECT * FROM Customers WHERE ContactName = '" + db.escape(name) + "'").execute(function () {});

  // GOOD: query builder with placeholder values
  db.query().select('*').from('Customers').where('ContactName = ?', [name]).execute(function () {});
});

app.post('/customers', function (req, res) {
  new mysql.Database({ hostname: 'localhost', user: 'user', password: 'password', database: 'test' }).connect(
    function (error) {
      // BAD: `this` is the connected `Database`
      this.query("INSERT INTO Customers (CustomerName) VALUES ('" + req.body.name + "')").execute(function () {});
    }
  );
});
