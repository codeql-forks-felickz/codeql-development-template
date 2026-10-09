class ApplicationRecord < ActiveRecord::Base
end

class User < ApplicationRecord
end

class Widget
  def self.create(attrs)
  end
end

# BAD: keyword arguments with a short literal password (stock rb/hardcoded-credentials misses it)
User.create(email: "admin@example.com", password: "admin1234", admin: true)

# BAD: explicit hash literal argument
User.create!({ email: "admin@example.com", password: "admin1234" })

# BAD: string keys
User.new("email" => "admin@example.com", "password" => "s3cr3t")

# BAD: seed data defined as an array of hashes and iterated
users = [
  {
    email: "admin@metacorp.com",
    admin: true,
    password: "admin1234",
    password_confirmation: "admin1234",
    first_name: "Admin",
  },
]

user_map = users.each_with_object({}) do |user_info, h|
  h[user_info[:email]] = User.create!(user_info).id
end

# BAD: hash built in a local variable
attrs = { email: "user@example.com", password: "letmein" }
User.find_or_create_by!(attrs)

# GOOD: password comes from the environment
User.create(email: "admin@example.com", password: ENV["ADMIN_PASSWORD"])

# GOOD: empty password literal
User.create(email: "admin@example.com", password: "")

# GOOD: literal in a non-credential attribute
User.create(email: "admin@example.com", first_name: "admin1234")

# GOOD: not an ActiveRecord model
Widget.create(password: "admin1234")

# GOOD: not a model creation call
User.where(password: "admin1234")
