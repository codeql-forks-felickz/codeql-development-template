class ApiCredential < ApplicationRecord
  has_secure_password :api_password
end
