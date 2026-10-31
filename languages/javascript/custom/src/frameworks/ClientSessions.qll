/**
 * Provides a model of the `client-sessions` package (https://github.com/mozilla/node-client-sessions)
 * as a `CookieWrites::CookieWrite`, so that cookie flag queries can reason about its `cookie` options.
 *
 * The stock `codeql/javascript-all` library only models `cookie-session` and `express-session`
 * session middleware, and cookie writes cannot be modeled with data extensions.
 */

import javascript

module ClientSessions {
  /**
   * A call that creates a `client-sessions` middleware instance, such as
   * `require('client-sessions')({ cookieName: 'session', secret: s, cookie: { httpOnly: false } })`.
   */
  class MiddlewareInstance extends DataFlow::InvokeNode {
    MiddlewareInstance() { this = DataFlow::moduleImport("client-sessions").getACall() }

    /** Gets the expression for property `name` of the options object of this call. */
    DataFlow::Node getOption(string name) { result = this.getOptionArgument(0, name) }

    /** Gets the value written to property `flag` of the `cookie` options object. */
    DataFlow::Node getCookieFlagValue(string flag) {
      result = this.getOption("cookie").getALocalSource().getAPropertyWrite(flag).getRhs()
    }
  }

  /**
   * The session cookie written by a `client-sessions` middleware instance.
   *
   * Defaults (https://github.com/mozilla/node-client-sessions#usage): `httpOnly` is `true`,
   * `secure` is not set.
   */
  class SessionCookieWrite extends MiddlewareInstance, CookieWrites::CookieWrite {
    override predicate isSecure() {
      // The `secure` flag is not set by default. `secureProxy` is the equivalent flag for
      // applications that terminate SSL in a proxy.
      exists(DataFlow::Node value |
        value = this.getCookieFlagValue([CookieWrites::secure(), "secureProxy"])
      |
        not value.mayHaveBooleanValue(false)
      )
    }

    override predicate isSensitive() {
      any() // It is a session cookie, likely auth sensitive
    }

    override predicate isHttpOnly() {
      // The `httpOnly` flag defaults to `true` when it is not explicitly set.
      not this.getCookieFlagValue(CookieWrites::httpOnly()).mayHaveBooleanValue(false)
    }

    override string getSameSite() {
      exists(DataFlow::Node node | node = this.getCookieFlagValue("sameSite") |
        node.mayHaveStringValue(result)
        or
        node.mayHaveBooleanValue(true) and result = "Strict"
        or
        node.mayHaveBooleanValue(false) and result = "Lax"
      )
    }
  }
}
