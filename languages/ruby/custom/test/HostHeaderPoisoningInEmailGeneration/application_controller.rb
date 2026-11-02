class ApplicationController < ActionController::Base
  before_action :mailer_options

  ALLOWED_HOSTS = ["example.com", "www.example.com"]

  private

  # BAD: reduced from a password-reset flow; the Host header controls links in every email.
  def mailer_options
    ActionMailer::Base.default_url_options[:protocol] = request.protocol
    ActionMailer::Base.default_url_options[:host] = request.host_with_port # $ Alert
  end

  # BAD: the whole options hash is replaced with request-derived values.
  def mailer_options_hash
    ActionMailer::Base.default_url_options = { host: request.host } # $ Alert
  end

  # BAD: merged into the existing options.
  def mailer_options_merge
    host = request.env["HTTP_X_FORWARDED_HOST"] # $ Source
    ActionMailer::Base.default_url_options.merge!(host: host) # $ Alert
  end

  # BAD: request data in the second positional hash is merged into the options.
  def mailer_options_merge_second_hash
    ActionMailer::Base.default_url_options.merge!({ protocol: "https" }, { host: request.host }) # $ Alert
  end

  # GOOD: a constant host in the second positional hash.
  def mailer_options_merge_second_hash_constant
    ActionMailer::Base.default_url_options.merge!({ protocol: "https" }, { host: "example.com" })
  end

  # BAD: set on a mailer subclass.
  def mailer_options_subclass
    UserMailer.default_url_options[:host] = request.domain # $ Alert
  end

  # BAD: set through the Rails application configuration.
  def mailer_options_config
    Rails.application.config.action_mailer.default_url_options = { host: request.host } # $ Alert
  end

  # BAD: the options hash is built in a local variable first.
  def mailer_options_variable
    options = { host: request.host, protocol: "https" } # $ Source
    ActionMailer::Base.default_url_options = options # $ Alert
  end

  # GOOD: request input only flows into a non-location option of the hash.
  def mailer_options_hash_other_key
    ActionMailer::Base.default_url_options = { host: "example.com", locale: params[:locale] }
  end

  # GOOD: a fixed, trusted host.
  def mailer_options_fixed
    ActionMailer::Base.default_url_options[:host] = "example.com"
  end

  # GOOD: the host is checked against an allow-list first.
  def mailer_options_allowlisted
    host = request.host
    if ALLOWED_HOSTS.include?(host)
      ActionMailer::Base.default_url_options[:host] = host
    end
  end

  # GOOD: the host is compared with a constant first.
  def mailer_options_compared
    host = request.host
    if host == "example.com"
      ActionMailer::Base.default_url_options[:host] = host
    end
  end

  # GOOD: request input only flows into a non-host option.
  def mailer_options_other_key
    ActionMailer::Base.default_url_options[:locale] = params[:locale]
  end

  # GOOD: a controller-local hash unrelated to ActionMailer.
  def url_options_local
    options = {}
    options[:host] = request.host
    options
  end
end

class UserMailer < ActionMailer::Base
end
