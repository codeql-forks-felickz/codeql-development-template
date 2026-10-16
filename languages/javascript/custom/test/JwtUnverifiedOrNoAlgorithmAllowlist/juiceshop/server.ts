import express from 'express'
import * as security from './lib/insecurity'
import { chat } from './routes/chat'

const app = express()
app.post('/rest/chatbot', chat())
app.get('/rest/accounting', security.isAccounting(), (req, res) => { res.json({}) })
export default app
