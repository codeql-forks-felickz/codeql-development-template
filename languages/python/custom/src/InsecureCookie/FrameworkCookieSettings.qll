/**
 * Provides models of framework-level cookie settings (Flask and Django configuration, and
 * `aiohttp-session` storage options) as `Http::Server::CookieWrite` instances, so that cookie
 * security queries can report session and CSRF cookies that are configured with the `Secure`
 * or `HttpOnly` attribute explicitly disabled.
 *
 * Only settings whose value is a literal `True`/`False` (possibly via local flow) are
 * given a known attribute value. Absent settings are deliberately not modeled.
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts
private import semmle.python.frameworks.Flask

/**
 * Holds if the configuration setting `setting` controls the cookie attribute `attribute`
 * (either `"secure"` or `"httponly"`) of the cookie described by `cookieDescription`.
 *
 * `CSRF_COOKIE_HTTPONLY` is intentionally excluded: Django documents that setting `HttpOnly`
 * on the CSRF cookie offers no practical protection, and it is commonly disabled on purpose.
 */
private predicate cookieSetting(string setting, string attribute, string cookieDescription) {
  setting = "SESSION_COOKIE_SECURE" and
  attribute = "secure" and
  cookieDescription = "session cookie"
  or
  setting = "SESSION_COOKIE_HTTPONLY" and
  attribute = "httponly" and
  cookieDescription = "session cookie"
  or
  setting = "CSRF_COOKIE_SECURE" and attribute = "secure" and cookieDescription = "CSRF cookie"
}

/**
 * A framework-level setting that controls the `Secure` or `HttpOnly` attribute of a cookie
 * set by the framework itself (such as the session cookie). The data-flow node is the value
 * assigned to the setting.
 */
abstract class FrameworkCookieSetting extends Http::Server::CookieWrite::Range {
  /** Gets the name of the setting or option, for example `SESSION_COOKIE_SECURE`. */
  abstract string getSettingName();

  /** Gets the cookie attribute controlled by this setting, `"secure"` or `"httponly"`. */
  abstract string getAttribute();

  /** Gets a description of the cookie affected by this setting, for example `session cookie`. */
  abstract string getCookieDescription();

  /** Holds if the value of this setting is known to be the boolean `b`. */
  private predicate hasBooleanValue(boolean b) {
    exists(BooleanLiteral bool |
      DataFlow::localFlow(DataFlow::exprNode(bool), this) and
      b = bool.booleanValue()
    )
  }

  override DataFlow::Node getHeaderArg() { none() }

  override DataFlow::Node getNameArg() { none() }

  override DataFlow::Node getValueArg() { none() }

  override predicate hasSecureFlag(boolean b) {
    this.getAttribute() = "secure" and this.hasBooleanValue(b)
  }

  override predicate hasHttpOnlyFlag(boolean b) {
    this.getAttribute() = "httponly" and this.hasBooleanValue(b)
  }

  override predicate hasSameSiteAttribute(Http::Server::CookieWrite::SameSiteValue v) { none() }
}

/** A cookie setting identified by a well-known configuration key such as `SESSION_COOKIE_SECURE`. */
abstract private class ConfigKeyCookieSetting extends FrameworkCookieSetting {
  string setting;

  ConfigKeyCookieSetting() { cookieSetting(setting, _, _) }

  override string getSettingName() { result = setting }

  override string getAttribute() { cookieSetting(setting, result, _) }

  override string getCookieDescription() { cookieSetting(setting, _, result) }
}

/** Gets a reference to the `config` attribute of a Flask application. */
private API::Node flaskConfig() { result = Flask::FlaskApp::instance().getMember("config") }

/**
 * The value assigned to a Flask cookie setting, as in
 * `app.config["SESSION_COOKIE_SECURE"] = False`.
 *
 * See https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_SECURE
 */
private class FlaskConfigSubscriptCookieSetting extends ConfigKeyCookieSetting {
  FlaskConfigSubscriptCookieSetting() {
    exists(AssignStmt assign, Subscript sub |
      sub = assign.getATarget() and
      sub.getObject() = flaskConfig().getAValueReachableFromSource().asExpr() and
      sub.getIndex().(StringLiteral).getText() = setting and
      this.asExpr() = assign.getValue()
    )
  }
}

/**
 * The value given to a Flask cookie setting in a call to `app.config.update` or
 * `app.config.from_mapping`, either as a keyword argument or as an entry of a dictionary
 * literal.
 */
private class FlaskConfigUpdateCookieSetting extends ConfigKeyCookieSetting {
  FlaskConfigUpdateCookieSetting() {
    exists(DataFlow::CallCfgNode call |
      call = flaskConfig().getMember(["update", "from_mapping"]).getACall()
    |
      this = call.getArgByName(setting)
      or
      exists(Dict dict, KeyValuePair item |
        DataFlow::localFlow(DataFlow::exprNode(dict), call.getArg(0)) and
        item = dict.getAnItem() and
        item.getKey().(StringLiteral).getText() = setting and
        this.asExpr() = item.getValue()
      )
    )
  }
}

/**
 * The value assigned to a cookie setting at module level or in a class body, as in a Django
 * settings module (`SESSION_COOKIE_HTTPONLY = False`) or a Flask configuration object loaded
 * with `app.config.from_object(...)`.
 *
 * See https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-httponly
 */
private class SettingsAssignmentCookieSetting extends ConfigKeyCookieSetting {
  SettingsAssignmentCookieSetting() {
    exists(AssignStmt assign, Name target |
      target = assign.getATarget() and
      target.getId() = setting and
      (assign.getScope() instanceof Module or assign.getScope() instanceof Class) and
      this.asExpr() = assign.getValue()
    )
  }
}

/**
 * Gets a reference to an `aiohttp-session` storage class (such as `RedisStorage` or
 * `EncryptedCookieStorage`), or a subclass of one.
 *
 * See https://aiohttp-session.readthedocs.io/en/stable/reference.html#abstract-storage
 */
private API::Node aiohttpSessionStorageClass() {
  exists(string name | name.matches("%Storage") |
    result = API::moduleImport("aiohttp_session").getMember(name).getASubclass*()
    or
    result = API::moduleImport("aiohttp_session").getMember(_).getMember(name).getASubclass*()
  )
}

/**
 * The value of the `secure` or `httponly` argument when constructing an `aiohttp-session`
 * storage, as in `RedisStorage(redis, httponly=False)`.
 */
private class AiohttpSessionStorageCookieSetting extends FrameworkCookieSetting {
  string attribute;

  AiohttpSessionStorageCookieSetting() {
    attribute = ["secure", "httponly"] and
    this = aiohttpSessionStorageClass().getACall().getArgByName(attribute)
  }

  override string getSettingName() { result = attribute }

  override string getAttribute() { result = attribute }

  override string getCookieDescription() { result = "aiohttp-session cookie" }
}

/**
 * Gets a regular expression matching cookie names that indicate an authentication token,
 * such as `access_token`, `refresh_token`, or `jwt`, which are not recognized by the standard
 * sensitive data heuristics.
 */
private string tokenCookieNameRegexp() {
  result = "(?is).*((access|refresh|id|auth|bearer|session)[_.-]?tok(en)?|jwt).*"
}

/**
 * Holds if `cookie` may contain sensitive information: its name is recognized by the standard
 * heuristics or indicates an authentication token, or it is a cookie (such as the session
 * cookie) that is configured by a framework-level setting.
 */
predicate isSensitiveCookie(Http::Server::CookieWrite cookie) {
  cookie.isSensitive()
  or
  cookie instanceof FrameworkCookieSetting
  or
  exists(StringLiteral name |
    DataFlow::localFlow(DataFlow::exprNode(name), cookie.getNameArg()) and
    name.getText().regexpMatch(tokenCookieNameRegexp())
  )
}
