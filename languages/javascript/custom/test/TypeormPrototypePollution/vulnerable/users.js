var express = require('express')
var bodyParser = require('body-parser')
var typeorm = require('typeorm')

var app = express()
app.use(bodyParser.json())

// Reduced from a real-world finding: attacker JSON such as
// {"name": {"__proto__": {"where": ...}}} is deep-merged by TypeORM < 0.2.25
// (`OrmUtils.mergeDeep`) during `save`, polluting `Object.prototype`.
app.post('/users', async (req, res) => {
  const repo = typeorm.getConnection('mysql').getRepository('Users')

  const user = {}
  user.name = req.body.name // $ Source
  user.address = req.body.address // $ Source
  await repo.save(user) // $ Alert
  res.sendStatus(200)
})

app.post('/users/direct', async (req, res) => {
  const repo = typeorm.getRepository('Users')
  await repo.save(req.body) // $ Alert
  res.sendStatus(200)
})

app.post('/users/manager', async (req, res) => {
  const manager = typeorm.getManager()
  await manager.save('Users', req.body) // $ Alert
  res.sendStatus(200)
})

app.post('/users/connection-manager', async (req, res) => {
  const connection = await typeorm.createConnection()
  await connection.manager.save('Users', req.body) // $ Alert
  res.sendStatus(200)
})

app.post('/users/transaction', async (req, res) => {
  await typeorm.getConnection().transaction(async (manager) => {
    await manager.getRepository('Users').save(req.body) // $ Alert
  })
  res.sendStatus(200)
})

// Safe: only string values reach `save`, so no nested `__proto__` key can be merged.
app.post('/users/scalar', async (req, res) => {
  const repo = typeorm.getRepository('Users')
  const name = req.body.name
  if (typeof name !== 'string') {
    return res.sendStatus(400)
  }
  await repo.save({ name: name })
  res.sendStatus(200)
})

// Safe: `insert` does not go through `OrmUtils.mergeDeep` in TypeORM 0.2.24.
app.post('/users/insert', async (req, res) => {
  const repo = typeorm.getRepository('Users')
  await repo.insert(req.body)
  res.sendStatus(200)
})

// Safe: constant data.
app.post('/users/seed', async (req, res) => {
  const repo = typeorm.getRepository('Users')
  await repo.save({ name: 'Liran', address: 'IL', role: 'user' })
  res.sendStatus(200)
})
