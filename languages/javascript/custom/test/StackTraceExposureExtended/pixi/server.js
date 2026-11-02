const express = require('express')
const csurf = require('csurf')

const app = express()

app.get('/secret', function (req, res) {
  'server.conf'()
  res.sendFile('./server.conf file', { root: __dirname })
})

app.use(csurf({ cookie: true }))

// error handler for csurf middleware
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)
  res.status(403)
  res.send('form tampered with')
})

app.listen(8090)
