const serialize = require('node-serialize')
const { unserialize } = require('node-serialize')

exports.handler = (event, context, callback) => {
  var req = serialize.unserialize(event.body) // NOT OK
  var headers = serialize.unserialize(event.headers) // NOT OK
  var direct = require('node-serialize').unserialize(event.body) // NOT OK
  var destructured = unserialize(event.queryStringParameters.data) // NOT OK

  // Safe: constant input is not user-controlled
  var constant = serialize.unserialize('{"a":1}')

  // Safe: serialize (not unserialize) is not a deserialization sink
  var serialized = serialize.serialize(event.body)

  callback(null, { req, headers, direct, destructured, constant, serialized })
}
