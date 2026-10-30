class ArrayAssignmentClient < ApplicationRecord
  def hash_api_password(value)
    self[:api_password] = Argon2::Password.create(value)
  end
end
