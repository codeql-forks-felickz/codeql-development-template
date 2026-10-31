const express = require('express')
const errorHandler = require('errorhandler')

const app = express()

// development only
if (app.get('env') == 'development') {
  app.use(errorHandler())
}

if (process.env.NODE_ENV === 'development') {
  app.use(errorHandler())
}

app.listen(3001)
