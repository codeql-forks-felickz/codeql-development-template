# Test fixtures are not deployed accounts: must not alert.
class UserTest < ActiveSupport::TestCase
  def test_login
    User.create(login: 'tester', password: 'password')
  end
end
