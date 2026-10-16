class AccountsController < ActionController::Base
  # A raw JSON body is a plain Hash, so strong parameters do not protect it.
  def create
    Account.create(JSON.parse(request.raw_post)) # $ Alert
  end

  # ActionController::Parameters raise ForbiddenAttributesError when unpermitted: not reported.
  def create_params
    Account.create(params[:account])
  end

  def create_permitted
    Account.create(params.require(:account).permit(:name))
  end
end
