// Error handling middleware

const errorHandler = (err, req, res, next) => { // $ Source
  'use strict'

  console.error(err.message)
  console.error(err.stack)
  res.status(500)
  res.render('error-template', {
    error: err // $ Alert
  })
}

const safeErrorHandler = (err, req, res, next) => {
  console.error(err.stack)
  res.status(err.status || 500)
  res.render('error-template', {
    error: 'An unexpected error occurred'
  })
}

module.exports = { errorHandler, safeErrorHandler }
