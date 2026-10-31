Rails.application.configure do
  config.force_ssl = false # $ Alert
  config.middleware.delete ActionDispatch::SSL
end
