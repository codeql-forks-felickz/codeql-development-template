# Insecure mass assignment from an unfiltered request hash

Passing a whole hash of user-controlled data to a model constructor or update method (mass assignment) lets a client set any attribute of the model, including sensitive ones such as `admin`, `api_token` or `user_id`.

Rails protects `params` with strong parameters (`ActionController::Parameters`), which `rb/insecure-mass-assignment` covers when that protection is bypassed with `permit!` or `to_unsafe_h`. This query covers hashes that never had that protection:

- Sinatra `params`, in classic (top-level) applications and in `Sinatra::Base` subclasses.
- Request bodies decoded with `JSON.parse`, `MultiJson.load` or `Oj.load`, in any framework (including Rails).

Sinks are ActiveRecord mass assignment methods (`new`, `create`, `update`, ...) and DataMapper model methods (`new`, `create`, `first_or_create`, `update`, ...).

## Recommendation

Only assign attributes that the client is allowed to set, for example with `slice` or by building the attribute hash explicitly.

## Example

The following Sinatra route passes the entire decoded JSON body to `User.new`, so a client can set `api_token` or `is_active`:

```ruby
post '/users/register' do
  params = MultiJson.load(request.body.read)
  @user = User.new(params)
  @user.save
end
```

Select the allowed attributes instead:

```ruby
post '/users/register' do
  body = MultiJson.load(request.body.read)
  @user = User.new(body.slice("fname", "lname", "email"))
  @user.save
end
```

## References

- OWASP: [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-915](https://cwe.mitre.org/data/definitions/915.html).
