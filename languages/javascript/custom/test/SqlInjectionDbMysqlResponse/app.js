var mysql = require('db-mysql');
var http = require('http');
var valTom;

http.request({ hostname: 'example.com', path: '/name' }, function (res) {
  res.on('data', function (chunk) {
    valTom = chunk;
  });
}).end();

new mysql.Database({ hostname: 'localhost', user: 'user', password: 'password', database: 'test' }).connect(
  function (error) {
    // BAD: HTTP response data concatenated into SQL passed to `Database.query`
    var theQuery = "INSERT INTO Customers (CustomerName, ContactName) VALUES ('Tom'," + valTom + ')';
    this.query(theQuery).execute(function (error, result) {});

    // BAD: HTTP response data concatenated into SQL passed to `Query.execute`
    this.query().execute('SELECT * FROM Customers WHERE ContactName = ' + valTom, function (error, rows) {});

    // GOOD: response data is bound as a placeholder value, not concatenated
    this.query('SELECT * FROM Customers WHERE ContactName = ?', [valTom]).execute(function (error, rows) {});

    // GOOD: constant query
    this.query("SELECT * FROM Customers WHERE ContactName = 'Tom'").execute(function (error, rows) {});
  }
);

var db = new mysql.Database({ hostname: 'localhost', user: 'user', password: 'password', database: 'test' });
db.connect(function (error) {
  // BAD: same flow through a `Database` stored in a variable
  db.query('DELETE FROM Customers WHERE ContactName = ' + valTom).execute(function (error, result) {});

  // GOOD: value escaped with `Database.escape`
  db.query("DELETE FROM Customers WHERE ContactName = '" + db.escape(valTom) + "'").execute(function () {});
});
