Rails.application.configure do
  config.middleware.insert_before ActionDispatch::Static, Rack::SSL
end
