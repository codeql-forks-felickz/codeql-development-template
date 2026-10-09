# Case-sensitive middleware path
Using a case-sensitive regular expression path in a middleware route enables an attacker to bypass that middleware when accessing an endpoint with a case-insensitive path. Paths specified using a string are case-insensitive, whereas regular expressions are case-sensitive by default.

This is a customized variant of the standard `js/case-sensitive-middleware-path` query. In addition to case-sensitive middleware paths, it also reports middleware that is *skipped* for request paths matching a case-sensitive exclusion regular expression, for example through the `unless({ path: ... })` option of `express-unless` or `express-jwt`, or through an early `return next()` guarded by a regular expression test of `req.path`. If a path such as `/admin/users` is processed by the middleware, but a differently cased path such as `/ADMIN/USERS` is excluded, the middleware can be bypassed.


## Recommendation
When using a regular expression as a middleware path, make sure the regular expression is case-insensitive by adding the `i` flag.


## Example
The following example restricts access to paths in the `/admin` path to users logged in as administrators:


```javascript
const app = require('express')();

app.use(/\/admin\/.*/, (req, res, next) => {
    if (!req.user.isAdmin) {
        res.status(401).send('Unauthorized');
    } else {
        next();
    }
});

app.get('/admin/users/:id', (req, res) => {
    res.send(app.database.users[req.params.id]);
});

```
A path such as `/admin/users/45` can only be accessed by an administrator. However, the path `/ADMIN/USERS/45` can be accessed by anyone because the upper-case path doesn't match the case-sensitive regular expression, whereas Express considers it to match the path string `/admin/users`.

The issue can be fixed by adding the `i` flag to the regular expression:


```javascript
const app = require('express')();

app.use(/\/admin\/.*/i, (req, res, next) => {
    if (!req.user.isAdmin) {
        res.status(401).send('Unauthorized');
    } else {
        next();
    }
});

app.get('/admin/users/:id', (req, res) => {
    res.send(app.database.users[req.params.id]);
});

```

The same problem occurs when the middleware is skipped for all paths that do not start with a case-sensitive prefix. In the following example, `/ADMIN/users/45` does not start with `/admin`, so it matches the exclusion pattern and the administrator check is skipped:


```javascript
const app = require('express')();
const unless = require('express-unless');

const adminCheck = (req, res, next) => {
    if (!req.user.isAdmin) {
        res.status(401).send('Unauthorized');
    } else {
        next();
    }
};
adminCheck.unless = unless;

app.use(adminCheck.unless({ path: /^(?!\/admin).*/ }));

app.get('/admin/users/:id', (req, res) => {
    res.send(app.database.users[req.params.id]);
});

```
Adding the `i` flag to the exclusion regular expression (`/^(?!\/admin).*/i`) fixes the issue. Note that excluding only specific public paths (such as `/^\/public\//`) is not reported, because a differently cased path is then still processed by the middleware.


## References
* MDN [Regular Expression Flags](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions#advanced_searching_with_flags).
* Common Weakness Enumeration: [CWE-178](https://cwe.mitre.org/data/definitions/178.html).
