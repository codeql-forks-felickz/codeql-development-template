class ApplicationController < ActionController::Base
  before_action :authenticated

  private

  def authenticated
    redirect_to root_url unless session[:user_id]
  end
end
