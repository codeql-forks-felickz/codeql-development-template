var express = require('express')
var bodyParser = require('body-parser')
var typeorm = require('typeorm')

var app = express()
app.use(bodyParser.json())

// Safe: TypeORM 0.2.25 ignores `__proto__` keys in `OrmUtils.mergeDeep` (CVE-2020-8158 fix).
app.post('/users', async (req, res) => {
  const repo = typeorm.getConnection('mysql').getRepository('Users')

  const user = {}
  user.name = req.body.name
  user.address = req.body.address
  await repo.save(user)
  res.sendStatus(200)
})

app.post('/users/manager', async (req, res) => {
  await typeorm.getManager().save('Users', req.body)
  res.sendStatus(200)
})
