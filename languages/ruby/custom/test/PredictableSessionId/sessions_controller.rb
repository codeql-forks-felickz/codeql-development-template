require 'securerandom'

class SessionsController < ActionController::Base
  @@next_id = 1000

  def create
    id = next_session_number
    # BAD: sequential session token written to a cookie.
    cookies[:session_token] = "sess_#{id}" # $ Alert
    # BAD: local counter incremented with `+ 1`.
    n = @@next_id + 1 # $ Source
    @@next_id = n
    cookies.signed[:auth_token] = "tok-#{n}" # $ Alert
  end

  def create_safe
    # GOOD: secure random session token.
    cookies[:session_token] = SecureRandom.uuid
    # GOOD: counter stored in a non-session cookie.
    cookies[:page_views] = "#{next_session_number}"
    # GOOD: "sidebar" is not a session identifier name.
    cookies[:sidebar_state] = "panel-#{next_session_number}"
    # GOOD: arithmetic on a per-request local value is not a persistent counter.
    attempt = params[:attempt].to_i
    cookies[:session_attempt] = (attempt + 1).to_s
  end

  private

  def next_session_number
    @@next_id += 1 # $ Source
  end
end

class LoginController < ActionController::Base
  @@login_count = 0

  def login
    @@login_count += 1
    # BAD: hash form of a cookie assignment.
    cookies[:session_id] = { value: "S-#{@@login_count}", httponly: true } # $ Alert
  end
end
