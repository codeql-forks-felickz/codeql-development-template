/**
 * @name Rails cookie session store patched to decode unsigned JSON
 * @description Patching the Rails cookie session store or cookie jar so that cookie
 *              values are decoded as plain JSON, without verifying a signature or
 *              decrypting them, lets a client forge arbitrary session data.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id rb/unsigned-json-cookie-store
 * @tags security
 *       external/cwe/cwe-565
 *       external/cwe/cwe-345
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.DataFlow

/**
 * Gets an API node for a Rails class or module that is responsible for reading
 * signed or encrypted cookie data, named `name`.
 */
API::Node cookieStoreClass(string name) {
  name = "ActionDispatch::Session::CookieStore" and
  result = API::getTopLevelMember("ActionDispatch").getMember("Session").getMember("CookieStore")
  or
  exists(string jar |
    jar =
      [
        "CookieJar", "SignedKeyRotatingCookieJar", "EncryptedKeyRotatingCookieJar",
        "ChainedCookieJars", "SerializedCookieJars"
      ] and
    name = "ActionDispatch::Cookies::" + jar and
    result = API::getTopLevelMember("ActionDispatch").getMember("Cookies").getMember(jar)
  )
}

/**
 * Holds if the instance methods of `mod` become instance methods of the Rails
 * cookie store or cookie jar class `name`, because `mod` reopens, subclasses,
 * or is prepended or included into that class.
 */
predicate patchesCookieStore(DataFlow::ModuleNode mod, string name) {
  // Reopening or subclassing the class.
  mod = cookieStoreClass(name).getADescendentModule()
  or
  // `CookieStore.prepend(Mod)`, `CookieStore.include(Mod)`, or the same calls
  // made from within the body of the reopened class.
  exists(DataFlow::CallNode call |
    call = cookieStoreClass(name).getAMethodCall(["prepend", "include"])
    or
    call = cookieStoreClass(name).getADescendentModule().getAModuleLevelCall(["prepend", "include"])
  |
    mod.getAnImmediateReference().flowsTo(call.getArgument(_))
  )
}

/**
 * Holds if `m` is an instance method that ends up on the Rails cookie store or
 * cookie jar class `name`.
 */
predicate cookieStoreMethod(MethodBase m, string name) {
  exists(DataFlow::ModuleNode mod |
    patchesCookieStore(mod, name) and
    m = mod.getAnOwnInstanceMethod().asCallableAstNode()
  )
  or
  // `CookieStore.class_eval do def unpacked_cookie_data(req) ... end end`
  exists(DataFlow::CallNode call |
    call =
      cookieStoreClass(name)
          .getAMethodCall(["class_eval", "class_exec", "module_eval", "module_exec"]) and
    m.getParent+() = call.getBlock().asExpr().getExpr()
  )
}

/** A call that decodes a JSON document. */
DataFlow::CallNode jsonDecodeCall() {
  result =
    API::getTopLevelMember("JSON")
        .getAMethodCall(["parse", "parse!", "load", "unsafe_load", "restore"])
  or
  result =
    API::getTopLevelMember("ActiveSupport").getMember("JSON").getAMethodCall(["decode", "load"])
  or
  result =
    API::getTopLevelMember("Oj").getAMethodCall(["load", "safe_load", "strict_load", "compat_load"])
  or
  result = API::getTopLevelMember("MultiJson").getAMethodCall(["load", "decode"])
}

/**
 * Holds if `m` verifies or decrypts cookie data, either through the signed or
 * encrypted cookie jars, a message verifier or encryptor, or by delegating to
 * the original implementation with `super`.
 */
predicate verifiesCookieData(MethodBase m) {
  exists(MethodCall c | c.getEnclosingMethod() = m |
    c.getMethodName() =
      [
        "signed", "encrypted", "signed_or_encrypted", "verify", "verified", "valid_message?",
        "decrypt_and_verify"
      ]
    or
    c instanceof SuperCall
  )
}

from MethodBase m, DataFlow::CallNode decode, string name
where
  cookieStoreMethod(m, name) and
  decode = jsonDecodeCall() and
  decode.asExpr().getExpr().getEnclosingMethod() = m and
  not verifiesCookieData(m)
select decode,
  "Method '" + m.getName() +
    "' patches $@ to decode cookie data as plain JSON without verifying a signature or decrypting it, so clients can forge session data.",
  m, name
