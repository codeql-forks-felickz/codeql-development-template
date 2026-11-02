class ApplicationController < ActionController::Base
  before_action :mailer_options

  private

  def mailer_options
    # BAD: the Host header of every request decides where links in emails point to
    ActionMailer::Base.default_url_options[:host] = request.host_with_port
  end
end
