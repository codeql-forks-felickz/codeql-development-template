class SessionsController < ApplicationController
  def new
    @url = params[:url]
  end

  # Post-login redirect: `url` is carried from the login page into the login
  # form, so a phishing link can still drive the redirect after the POST.
  def create
    path = params[:url].present? ? params[:url] : home_dashboard_index_path # $ Source
    user = User.authenticate(params[:email], params[:password])
    if user
      session[:user_id] = user.id
      redirect_to path # $ Alert
    else
      render "sessions/new"
    end
  end

  # Redirect-target parameter read with `fetch`.
  def update
    redirect_to params.fetch(:return_to) # $ Alert
  end

  # Safe: the redirect target is restricted to the same host.
  def destroy
    redirect_to params[:url], allow_other_host: false
  end
end
