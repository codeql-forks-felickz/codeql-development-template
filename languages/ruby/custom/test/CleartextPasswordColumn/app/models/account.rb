# Hashes the value before it is stored in the `password` column.
class Account < ApplicationRecord
  before_save :hash_password

  def hash_password
    self.password = BCrypt::Password.create(password)
  end
end
