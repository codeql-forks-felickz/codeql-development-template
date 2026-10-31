const express = require('express')
const { errorHandler, safeErrorHandler } = require('./error')

const app = express()
app.use(errorHandler)
app.use(safeErrorHandler)
app.listen(4000)
