# Uses Active Record encryption for the column.
class ApiClient < ApplicationRecord
  encrypts :api_password
end
