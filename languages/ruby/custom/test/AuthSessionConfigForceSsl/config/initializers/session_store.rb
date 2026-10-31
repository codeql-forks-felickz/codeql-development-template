# GOOD: Secure not set, but the application enforces SSL with config.force_ssl
Rails.application.config.session_store :cookie_store, key: "_app_session"

# BAD: HttpOnly explicitly disabled
Rails.application.config.session_store :cookie_store, key: "_app_session", httponly: false # $ Alert
