# config/environments/production.rb
Rails.application.configure do
  # GOOD: links in emails always point to the trusted application host
  config.action_mailer.default_url_options = { host: "www.example.com", protocol: "https" }
end
