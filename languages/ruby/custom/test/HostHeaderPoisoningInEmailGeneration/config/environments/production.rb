Rails.application.configure do
  # GOOD: a fixed host configured at boot time.
  config.action_mailer.default_url_options = { host: "example.com", protocol: "https" }
end
