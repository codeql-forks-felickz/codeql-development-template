class SetterClient < ApplicationRecord
  def api_password=(value)
    @api_password = Digest::SHA256.hexdigest(value)
  end
end
