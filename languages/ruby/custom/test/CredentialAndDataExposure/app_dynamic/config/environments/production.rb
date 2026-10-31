Rails.application.configure do
  config.force_ssl = ENV.fetch("FORCE_SSL", "true") == "true"
end
