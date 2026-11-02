Rails.application.configure do
  # Enabling SSL only in development does not protect production traffic.
  config.force_ssl = true
end
