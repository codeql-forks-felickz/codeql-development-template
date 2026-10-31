module EnabledApp
  class Application < Rails::Application
    config.force_ssl = true
  end
end
