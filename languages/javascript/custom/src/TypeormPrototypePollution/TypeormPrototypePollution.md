# Prototype-polluting TypeORM save

TypeORM versions before 0.2.25 deep-merge entity values with `OrmUtils.mergeDeep` when an entity is saved with `Repository.save` or `EntityManager.save`. That function does not skip `__proto__` keys, so saving a user-controlled object such as `{"name": {"__proto__": {"where": "..."}}}` modifies `Object.prototype` (CVE-2020-8158). Polluted properties can then change the behavior of later code, for example the criteria of a subsequent `find` call.

The stock `js/prototype-pollution` query only models deep `extend`/`merge` utilities, so it does not report this. This query reuses its data flow configuration and adds TypeORM `save` sinks from the `typeorm-deep-merge` data extension (`languages/javascript/custom/models/cwe-1321.model.yml`), reported only when the enclosing `package.json` depends on TypeORM before 0.2.25.

## Recommendation

Upgrade TypeORM to 0.2.25 or later. Additionally, copy only expected, primitive-typed fields from request bodies into entities before saving them.

## Example

```javascript
app.post('/users', async (req, res) => {
  const user = {}
  user.name = req.body.name // may be an object containing `__proto__`
  await typeorm.getRepository('Users').save(user) // BAD with typeorm < 0.2.25
})
```

## References

- [CVE-2020-8158](https://nvd.nist.gov/vuln/detail/CVE-2020-8158)
- [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)
