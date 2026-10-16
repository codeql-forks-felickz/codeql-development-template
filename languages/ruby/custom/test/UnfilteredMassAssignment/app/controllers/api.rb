class Api < Sinatra::Base
  post "/accounts" do
    Account.create(params) # $ Alert
  end

  post "/accounts/safe" do
    Account.create(name: params["name"])
  end
end
