# Information exposure through an error message or stack trace (extended)

This query is a variant of the standard `js/stack-trace-exposure` query. It reuses the standard sources (caught exceptions) and sinks (HTTP response bodies, including values passed to `res.render`), and adds the following models:

- **Express error-handling middleware**: the `err` parameter of `(err, req, res, next) => { ... }` is treated as an error.
- **Node.js-style callbacks**: a first callback parameter named `e`, `err` or `error`, as in `db.all(sql, function (err, rows) { res.json(err) })`, is treated as an error.
- **Promise rejection handlers**: the parameter of `p.catch(err => ...)` and of the second callback of `p.then(..., err => ...)` is treated as an error.
- **Error messages**: reads of `message` propagate like reads of `stack`, so `res.json({ error: e.message })` is reported. String concatenation of `message` or `stack` is tracked; concatenating the error object itself is not, as in `js/stack-trace-exposure`.
- **Response objects**: all properties of an object sent in a response, such as `res.json({ error })`, are considered exposed.
- **`errorhandler` middleware**: `app.use(errorhandler())` sends the message and stack trace of every unhandled error to the client.

Values and middleware that are only used when the application checks that it runs in the `development` environment (for example `req.app.get('env') === 'development' ? err : {}` or `if (app.get('env') == 'development') app.use(errorhandler())`) are not reported, because this depends on deployment configuration rather than code.

## Recommendation

Send a generic error message to the client and log the error details on the server. Install development error handlers such as `errorhandler` only in development.

## Example

```javascript
searchService.searchByName(text, function (err, rows) {
  // BAD: the database error is sent to the client
  if (err) return res.json(err)
  res.json(rows)
})
```

```javascript
searchService.searchByName(text, function (err, rows) {
  if (err) {
    // GOOD: the error is logged, and a generic message is sent to the client
    console.error(err)
    return res.status(500).json({ error: 'Search failed' })
  }
  res.json(rows)
})
```

## References

- OWASP: [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling).
- Express: [Error handling](https://expressjs.com/en/guide/error-handling.html).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-497](https://cwe.mitre.org/data/definitions/497.html).
