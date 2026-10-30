class ApplicationRecord < ActiveRecord::Base
  self.abstract_class = true

  def digest_login
    self.login = Digest::SHA256.hexdigest(login)
  end
end
