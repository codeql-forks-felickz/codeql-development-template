module EncryptedApiPassword
  extend ActiveSupport::Concern

  included do
    encrypts :api_password
  end
end
