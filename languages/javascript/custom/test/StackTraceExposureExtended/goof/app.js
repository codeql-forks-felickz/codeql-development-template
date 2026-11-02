const express = require('express')
const errorHandler = require('errorhandler')

const app = express()

const guardedErrorHandler = errorHandler()
if (app.get('env') === 'development') {
  app.use(guardedErrorHandler) // GOOD: the middleware is installed only in development
}

// development only
if (app.get('env') == 'development') {
  app.use(errorHandler())
}

if (process.env.NODE_ENV === 'development') {
  app.use(errorHandler())
}

app.listen(3001)
