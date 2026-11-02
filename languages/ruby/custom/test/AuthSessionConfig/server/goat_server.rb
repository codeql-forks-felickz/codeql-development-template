require 'sinatra/base'

class GoatServer < Sinatra::Base
  get "/login" do
    # BAD: session cookie set without Secure or HttpOnly
    response.set_cookie("SessionID", "34A7EF-115C24-8F21CD-#{increment_count}") # $ Alert

    # BAD: session cookie set with a hash lacking Secure
    response.set_cookie("auth_token", value: token, httponly: true) # $ Alert

    # BAD: session cookie set with a hash lacking HttpOnly
    response.set_cookie("remember_me", { value: token, secure: true }) # $ Alert

    # BAD: Secure and HttpOnly explicitly disabled
    response.set_cookie(:session_id, value: token, secure: false, httponly: false) # $ Alert

    # GOOD: Secure and HttpOnly set
    response.set_cookie("SessionID", value: token, secure: true, httponly: true, same_site: :strict)

    # GOOD: Secure computed at runtime
    response.set_cookie("SessionID", value: token, secure: request.secure?, httponly: true)

    # GOOD: not an authentication or session cookie
    response.set_cookie("theme", "dark")

    # GOOD: options cannot be determined statically
    response.set_cookie("SessionID", cookie_options)
    response.set_cookie("SessionID", value: token, **cookie_options)

    # GOOD: later splats may override the disabled flags
    response.set_cookie("SessionID", value: token, secure: false, httponly: false, **cookie_options)
    response.set_cookie("SessionID", { value: token, secure: nil, httponly: nil, **cookie_options })

    # BAD: explicit disabled flags override earlier splats
    response.set_cookie("SessionID", value: token, **cookie_options, secure: false, httponly: false) # $ Alert
    response.set_cookie("SessionID", { **cookie_options, value: token, secure: nil, httponly: nil }) # $ Alert

    # GOOD: unsupported options beginning with a splat are not inspected
    response.set_cookie("SessionID", **cookie_options, secure: false, httponly: false)
  end
end
