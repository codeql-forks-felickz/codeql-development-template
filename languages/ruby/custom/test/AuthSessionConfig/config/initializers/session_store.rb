# frozen_string_literal: true

# BAD: HttpOnly explicitly disabled and Secure not set (no force_ssl in this app)
Railsgoat::Application.config.session_store :cookie_store, key: "_railsgoat_session", httponly: false # $ Alert

# BAD: HttpOnly explicitly disabled and Secure not set
Rails.application.config.session_store :cookie_store, key: '_todo_security_session', httponly: false # $ Alert

# BAD: Secure explicitly disabled
Rails.application.config.session_store :cookie_store, key: "_app_session", secure: false, httponly: true # $ Alert

# BAD: Secure not set and the application does not enforce SSL
Rails.application.config.session_store :cookie_store, key: "_app_session" # $ Alert

# GOOD: Secure and HttpOnly set
Rails.application.config.session_store :cookie_store, key: "_app_session", secure: true, httponly: true

# GOOD: Secure computed at runtime, HttpOnly left at its default (true)
Rails.application.config.session_store :cookie_store, key: "_app_session", secure: Rails.env.production?

# GOOD: options cannot be determined statically
Rails.application.config.session_store :cookie_store, **SESSION_OPTIONS

# GOOD: sessions are disabled
Rails.application.config.session_store :disabled

module Todo
  class Application < Rails::Application
    # BAD: HttpOnly explicitly disabled inside the application class
    config.session_store :cookie_store, key: "_todo_session", secure: true, httponly: false # $ Alert

    # GOOD
    config.session_store :cookie_store, key: "_todo_session", secure: true
  end

  # GOOD: positional options cannot be determined statically
  Rails.application.config.session_store :cookie_store, SESSION_OPTIONS
  Rails.application.config.session_store :cookie_store, session_options

  # BAD: a literal options hash still lacks Secure
  Rails.application.config.session_store :cookie_store, { key: "_app_session" } # $ Alert
end
