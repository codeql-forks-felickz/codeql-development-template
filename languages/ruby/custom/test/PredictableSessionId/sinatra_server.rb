require 'sinatra/base'
require 'securerandom'

$request_count = 0
$mutex = Mutex.new

class TokenServer < Sinatra::Base
  get "/token" do
    # BAD: constant prefix plus a process-wide counter returned from a helper.
    response.set_cookie("SessionID", "34A7EF-115C24-8F21CD-#{increment_count}") # $ Alert
  end

  get "/token/hash" do
    # BAD: same pattern, using the hash form of set_cookie.
    response.set_cookie("SessionID", value: "34A7EF-#{increment_count}", secure: true) # $ Alert
  end

  get "/token/global" do
    $request_count += 1
    # BAD: the counter variable is read directly.
    response.set_cookie("sid", "PREFIX-" + $request_count.to_s) # $ Alert
  end

  get "/token/secure" do
    # GOOD: identifier generated from a cryptographically secure source.
    response.set_cookie("SessionID", SecureRandom.hex(32))
  end

  get "/token/mixed" do
    # GOOD: the counter is combined with a secure random component.
    response.set_cookie("SessionID", "#{SecureRandom.urlsafe_base64(32)}-#{increment_count}")
  end

  get "/visits" do
    # GOOD: a counter in a cookie that is not a session identifier.
    response.set_cookie("visit_count", "v-#{increment_count}")
  end

  private

  def increment_count
    $mutex.synchronize do
      return $request_count += 1 # $ Source
    end
  end
end
