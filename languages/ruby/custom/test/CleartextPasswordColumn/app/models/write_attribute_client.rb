class WriteAttributeClient < ApplicationRecord
  def hash_api_password(value)
    write_attribute(:api_password, SCrypt::Password.create(value))
  end
end
