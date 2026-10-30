class EncryptedRecord < ApplicationRecord
  self.abstract_class = true
  encrypts :api_password
end
