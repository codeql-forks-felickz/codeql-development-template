class User
  include DataMapper::Resource
  property :id, Serial
  property :fname, String
  property :lname, String
  property :email, String
  property :password_hash, String
  property :is_active, Boolean
  property :api_token, String
end
