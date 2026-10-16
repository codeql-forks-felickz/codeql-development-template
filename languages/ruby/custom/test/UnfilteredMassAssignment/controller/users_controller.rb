# Classic (top-level) Sinatra routes with DataMapper models.

post '/users/register' do
  params = MultiJson.load(request.body.read) # $ Source
  params.delete("password")

  # The whole JSON body is mass-assigned, so a client can set `api_token`, `is_active`, ...
  @user = User.new(params) # $ Alert
  @user.save
end

post '/users/register_json' do
  attrs = JSON.parse(request.body.read) # $ Source
  User.create(attrs) # $ Alert
end

put '/users/:id' do
  user = User.get(params[:id])
  user.update(params) # $ Alert
end

post '/users/form' do
  User.first_or_create(params) # $ Alert
end

post '/users/register_safe' do
  body = MultiJson.load(request.body.read)
  # Only explicitly chosen attributes are assigned.
  User.new(fname: body["fname"], lname: body["lname"], email: body["email"])
end

post '/users/register_slice' do
  body = MultiJson.load(request.body.read)
  User.new(body.slice("fname", "lname", "email"))
end

put '/users/:id/name' do
  user = User.get(params[:id])
  user.update(fname: params[:fname])
end
