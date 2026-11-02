class AccountsController < ApplicationController
  # Safe (not a redirect-target parameter): a POST handler redirecting to a
  # value from an arbitrary form field is not reachable from a link.
  def create
    account = Account.create(name: params[:name])
    redirect_to params[:name]

    p = params
    redirect_to p[:name]
    redirect_to p[:url] # $ Alert
  end

  # Safe: constant-string comparison guard.
  def update
    url = params[:return_to]
    if url == "/home"
      redirect_to url
    end
  end

  # Safe: a prefixed string interpolation cannot change the host.
  def destroy
    redirect_to "/accounts/#{params[:next]}"
  end

  # Already reported by the shipped rb/url-redirection query (GET handler), so
  # this query does not report it again.
  def show
    redirect_to params[:url]
  end
end
