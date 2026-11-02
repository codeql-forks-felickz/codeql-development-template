import express from 'express'
const errorhandler = require('errorhandler')

const app = express()

/* Error Handling */
app.use(errorhandler()) // $ Alert

app.listen(3000)
