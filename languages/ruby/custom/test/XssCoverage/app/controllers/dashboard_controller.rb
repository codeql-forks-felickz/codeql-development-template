class DashboardController < ApplicationController
  def home
    @user = current_user

    # See if the user has a font preference
    if params[:font]
      cookies[:font] = params[:font]
    end
  end
end
