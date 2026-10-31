module Rails
  class Application
    class DefaultMiddlewareStack
      def build_stack
        ActionDispatch::MiddlewareStack.new do |middleware|
          middleware.use ::ActionDispatch::SSL, **config.ssl_options if config.force_ssl
        end
      end
    end
  end
end
