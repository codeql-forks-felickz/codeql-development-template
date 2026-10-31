const jsyaml = require('js-yaml')
const express = require('express')
const app = express()

app.post('/store/:id', (req, res) => {
  const unsafeConfig = { schema: jsyaml.DEFAULT_FULL_SCHEMA }
  jsyaml.safeLoad(req.params.data, unsafeConfig)
  jsyaml.load(req.params.data, { schema: jsyaml.DEFAULT_SCHEMA })
})
