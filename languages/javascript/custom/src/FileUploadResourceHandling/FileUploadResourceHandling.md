# Unbounded file upload or resource handling

Server code that accepts uploads, keeps session state, executes GraphQL queries, expands archives or downloads remote content must bound the resources each request can consume. Without type, size, capacity or cost limits, an attacker can exhaust memory, disk space or CPU (CWE-400, CWE-409), or store files of unexpected types (CWE-434).

This query reports the following patterns:

- **Unrestricted multer uploads**: `multer(...)` configured without a `fileFilter` (file type or extension validation) or without `limits.fileSize`.
- **Default session store**: `express-session` configured without a `store`, so the default in-process `MemoryStore` is used. It has no capacity limit and leaks memory.
- **GraphQL without cost limits**: an `express-graphql`, `graphql-http` or Apollo server whose statically known `validationRules` limit only depth (or nothing), with no rule that limits query cost, complexity or aliases.
- **Unbounded archive extraction**: `unzipper` archives (`Open.*`, `Parse`, `ParseOne`, `Extract`) whose entries are expanded without checking `uncompressedSize`.
- **Unbounded download**: the response to a request whose URL is user-controlled (as determined by `js/request-forgery`) is written to a file with `pipe` or `pipeline` without a size limit.

## Recommendation

- Configure `multer` with a `fileFilter` that checks the MIME type and extension, and with `limits.fileSize` (and `limits.files` where appropriate).
- Use a production session store (for example Redis) with expiry, instead of the default `MemoryStore`.
- Add query cost or complexity limiting (for example `graphql-validation-complexity`, `graphql-query-complexity`, `graphql-cost-analysis` or GraphQL Armor) in addition to depth limiting, and limit aliases.
- Check the expanded size of each archive entry, and cap the entry count and total output size before writing entries to disk.
- Restrict the URLs that can be fetched, and stop reading the response once a maximum number of bytes has been received.

## Example

The following code accepts uploads with no type or size validation, uses the default session store, limits only GraphQL query depth, extracts every entry of an uploaded archive and streams an arbitrary URL to disk:

```javascript
const upload = multer({ dest: 'uploads/' });

app.use(session({ secret: 'keyboard cat' }));

app.use('/graphql', graphqlHTTP({ schema, validationRules: [depthLimit(10)] }));

const directory = await unzipper.Open.buffer(buffer);
for (const entry of directory.files) {
  await pipeline(entry.stream(), fs.createWriteStream('uploads/' + path.basename(entry.path)));
}

const response = await fetch(req.body.imageUrl);
await finished(Readable.fromWeb(response.body).pipe(fs.createWriteStream('uploads/avatar.jpg')));
```

The following code bounds each of these resources:

```javascript
const upload = multer({ dest: 'uploads/', limits: { fileSize: 1024 * 1024 }, fileFilter: imageFilter });

app.use(session({ secret: process.env.SESSION_SECRET, store: new RedisStore({ client }) }));

app.use('/graphql', graphqlHTTP({
  schema,
  validationRules: [depthLimit(10), createComplexityLimitRule(1000)]
}));

for (const entry of directory.files) {
  if (entry.uncompressedSize > MAX_ENTRY_SIZE) continue;
  await pipeline(entry.stream(), fs.createWriteStream('uploads/' + path.basename(entry.path)));
}
```

## Limitations

- Options that are not statically known (for example spread properties or values computed elsewhere) are not reported.
- GraphQL servers without any `validationRules` are not reported.
- A read of `uncompressedSize` anywhere in the function that expands an entry (including nested callbacks) is treated as a sufficient expansion check.
- Unbounded downloads are only reported when the request URL is user-controlled.

## References

- CWE-400: [Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- CWE-409: [Improper Handling of Highly Compressed Data (Data Amplification)](https://cwe.mitre.org/data/definitions/409.html)
- CWE-434: [Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [multer limits and fileFilter](https://github.com/expressjs/multer#limits)
- [express-session: MemoryStore warning](https://github.com/expressjs/session#sessionoptions)
- OWASP: [GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
