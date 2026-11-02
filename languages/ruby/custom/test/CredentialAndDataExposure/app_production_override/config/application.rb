module OverrideApp
  class Application < Rails::Application
    config.force_ssl = true
  end
end
