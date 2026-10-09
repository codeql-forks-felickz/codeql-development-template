require "json"

# --- Positive cases -----------------------------------------------------------

# Module prepended into the Rails cookie session store (pattern from the issue).
module InsecureStore
  def unpacked_cookie_data(req)
    JSON.parse(req.cookies[@key]) # $ Alert
  end
end
ActionDispatch::Session::CookieStore.prepend(InsecureStore)

# Module included into the cookie session store.
module IncludedInsecureStore
  def get_cookie(req)
    ActiveSupport::JSON.decode(req.cookie_jar[@key]) # $ Alert
  end
end
ActionDispatch::Session::CookieStore.include(IncludedInsecureStore)

# Prepend issued from inside the reopened class body.
module SelfPrependedStore
  def unpacked_cookie_data(req)
    raw = req.cookies["_app_session"]
    raw ? JSON.parse!(raw) : {} # $ Alert
  end
end

module ActionDispatch
  module Session
    class CookieStore
      prepend SelfPrependedStore
    end
  end
end

# Direct reopening of the cookie session store (nested modules).
module ActionDispatch
  module Session
    class CookieStore
      def get_cookie(req)
        JSON.load(req.cookies[@key]) # $ Alert
      end
    end
  end
end

# Direct reopening of the cookie session store (compact name).
class ActionDispatch::Session::CookieStore
  def unpacked_cookie_data(req)
    data = req.cookies[@key]
    JSON.parse(data, symbolize_names: false) # $ Alert
  end
end

# Patching through class_eval.
ActionDispatch::Session::CookieStore.class_eval do
  def unpacked_cookie_data(req)
    JSON.parse(req.cookies[@key]) # $ Alert
  end
end

# Custom session store subclassing the cookie store.
class JsonCookieStore < ActionDispatch::Session::CookieStore
  def unpacked_cookie_data(req)
    JSON.parse(req.cookies[@key] || "{}") # $ Alert
  end
end

# Cookie jar patched so that `signed` reads become plain JSON reads.
module PlainSignedJar
  def [](name)
    JSON.parse(@parent_jar[name]) # $ Alert
  end
end
ActionDispatch::Cookies::SignedKeyRotatingCookieJar.prepend(PlainSignedJar)

# --- Negative cases -----------------------------------------------------------

# Uses the signed cookie jar before decoding: OK.
module SignedStore
  def unpacked_cookie_data(req)
    JSON.parse(req.cookie_jar.signed[@key])
  end
end
ActionDispatch::Session::CookieStore.prepend(SignedStore)

# Uses the encrypted cookie jar before decoding: OK.
module EncryptedStore
  def get_cookie(req)
    JSON.parse(req.cookie_jar.encrypted[@key])
  end
end
ActionDispatch::Session::CookieStore.prepend(EncryptedStore)

# Verifies with a MessageVerifier before decoding: OK.
module VerifiedStore
  def unpacked_cookie_data(req)
    payload = verifier.verify(req.cookies[@key])
    JSON.parse(payload)
  end
end
ActionDispatch::Session::CookieStore.prepend(VerifiedStore)

# Post-processes the result of the original (verified) implementation: OK.
module PostProcessingStore
  def unpacked_cookie_data(req)
    data = super
    data.is_a?(String) ? JSON.parse(data) : data
  end
end
ActionDispatch::Session::CookieStore.prepend(PostProcessingStore)

# JSON decoding in a module that is never mixed into a session store: OK.
module UnrelatedJsonHelper
  def unpacked_cookie_data(req)
    JSON.parse(req.cookies["prefs"])
  end
end
SomeOtherClass.prepend(UnrelatedJsonHelper)

# Unrelated class with a method of the same name: OK.
class PreferencesStore
  def unpacked_cookie_data(req)
    JSON.parse(req.cookies["prefs"])
  end
end

# Subclass of an unrelated session store: OK.
class CacheBackedStore < ActionDispatch::Session::CacheStore
  def get_session(env, sid)
    JSON.parse(@cache.read(sid))
  end
end
