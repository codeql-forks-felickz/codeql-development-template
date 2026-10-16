class DashboardController < ApplicationController
  def home
    @user = current_user

    # See if the user has a font preference
    if params[:font]
      cookies[:font] = params[:font] # $ Source[rb/cookie-stored-xss]
    end

    # Cookie stored through the hash form of the cookie API.
    cookies.permanent[:color] = { value: params[:color], expires: 1.year } # $ Source[rb/cookie-stored-xss]

    # Cookie only ever set to a constant value: not attacker controlled.
    cookies[:theme] = "dark"
  end
end
