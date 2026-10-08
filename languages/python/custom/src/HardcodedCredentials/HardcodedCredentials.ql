/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision low
 * @id py/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.filters.Tests
private import semmle.python.dataflow.new.internal.DataFlowDispatch as DataFlowDispatch
private import semmle.python.dataflow.new.internal.Builtins::Builtins as Builtins
private import semmle.python.frameworks.data.ModelsAsData
private import semmle.python.ApiGraphs
private import semmle.python.frameworks.Flask

bindingset[char, fraction]
predicate fewer_characters_than(StringLiteral str, string char, float fraction) {
  exists(string text, int chars |
    text = str.getText() and
    chars = count(int i | text.charAt(i) = char)
  |
    /* Allow one character */
    chars = 1 or
    chars < text.length() * fraction
  )
}

predicate possible_reflective_name(string name) {
  any(Function f).getName() = name
  or
  any(Class c).getName() = name
  or
  any(Module m).getName() = name
  or
  exists(Builtins::likelyBuiltin(name))
}

int char_count(StringLiteral str) { result = count(string c | c = str.getText().charAt(_)) }

predicate capitalized_word(StringLiteral str) { str.getText().regexpMatch("[A-Z][a-z]+") }

predicate format_string(StringLiteral str) { str.getText().matches("%{%}%") }

predicate maybeCredential(ControlFlowNode f) {
  /* A string that is not too short and unlikely to be text or an identifier. */
  exists(StringLiteral str | str = f.getNode() |
    /* At least 10 characters */
    str.getText().length() > 9 and
    /* Not too much whitespace */
    fewer_characters_than(str, " ", 0.05) and
    /* or underscores */
    fewer_characters_than(str, "_", 0.2) and
    /* Not too repetitive */
    exists(int chars | chars = char_count(str) |
      chars > 15 or
      chars * 3 > str.getText().length() * 2
    ) and
    not possible_reflective_name(str.getText()) and
    not capitalized_word(str) and
    not format_string(str)
  )
  or
  /* Or, an integer with over 32 bits */
  exists(IntegerLiteral lit | f.getNode() = lit |
    not exists(lit.getValue()) and
    /* Not a set of flags or round number */
    not lit.getN().matches("%00%")
  )
}

class HardcodedValueSource extends DataFlow::Node {
  HardcodedValueSource() { maybeCredential(this.asCfgNode()) }
}

class CredentialSink extends DataFlow::Node {
  CredentialSink() {
    exists(string s | s.matches("credentials-%") |
      // Actual sink-type will be things like `credentials-password` or `credentials-username`
      ModelOutput::sinkNode(this, s)
    )
    or
    exists(string name |
      name.regexpMatch(getACredentialRegex()) and
      not name.matches("%file")
    |
      exists(DataFlowDispatch::ArgumentPosition pos | pos.isKeyword(name) |
        this.(DataFlow::ArgumentNode).argumentOf(_, pos)
      )
      or
      exists(Keyword k | k.getArg() = name and this.asCfgNode().getNode() = k.getValue())
      or
      exists(CompareNode cmp, NameNode n | n.getId() = name |
        cmp.operands(this.asCfgNode(), any(Eq eq), n)
        or
        cmp.operands(n, any(Eq eq), this.asCfgNode())
      )
    )
  }
}

/**
 * A non-empty string literal. Framework signing secrets are secrets regardless of their
 * length or shape, so any such literal is a source for a `FrameworkSecretSink`.
 */
class FrameworkSecretLiteral extends DataFlow::Node {
  FrameworkSecretLiteral() { this.asExpr().(StringLiteral).getText() != "" }
}

/**
 * A value written to a named web framework signing secret setting, such as Flask's
 * `app.secret_key`, Django's `SECRET_KEY` or SimpleJWT's `SIGNING_KEY`.
 */
abstract class FrameworkSecretWrite extends DataFlow::Node {
  /** Gets the name of the setting that this value is written to, such as `SECRET_KEY`. */
  abstract string getSettingName();
}

/**
 * A value written to the secret key of a Flask application, either as
 * `app.secret_key = value`, `app.config["SECRET_KEY"] = value` or
 * `app.config.update(SECRET_KEY=value)`.
 */
class FlaskSecretKeyWrite extends FrameworkSecretWrite {
  FlaskSecretKeyWrite() {
    exists(API::Node app | app = Flask::FlaskApp::instance() |
      this = app.getMember("secret_key").asSink()
      or
      this = app.getMember("config").getSubscript("SECRET_KEY").asSink()
      or
      this =
        app.getMember("config")
            .getMember(["update", "from_mapping"])
            .getKeywordParameter("SECRET_KEY")
            .asSink()
    )
  }

  override string getSettingName() { result = "SECRET_KEY" }
}

/**
 * Holds if `m` looks like a Django settings module, that is, a module named `settings`
 * (or `*settings`), a module inside a `settings` package, or a module that defines
 * `INSTALLED_APPS`.
 */
predicate isDjangoSettingsModule(Module m) {
  m.getFile().getStem().matches("%settings")
  or
  m.getFile().getParent().getBaseName() = "settings"
  or
  exists(AssignStmt a | a.getScope() = m and a.getATarget().(Name).getId() = "INSTALLED_APPS")
}

/** A value assigned to the module-level `SECRET_KEY` of a Django settings module. */
class DjangoSecretKeyWrite extends FrameworkSecretWrite {
  DjangoSecretKeyWrite() {
    exists(AssignStmt a |
      isDjangoSettingsModule(a.getScope()) and
      a.getATarget().(Name).getId() = "SECRET_KEY" and
      this.asExpr() = a.getValue()
    )
  }

  override string getSettingName() { result = "SECRET_KEY" }
}

/**
 * A value of the `SIGNING_KEY` entry of a module-level `SIMPLE_JWT` settings dictionary
 * (Django REST framework SimpleJWT).
 */
class SimpleJwtSigningKeyWrite extends FrameworkSecretWrite {
  SimpleJwtSigningKeyWrite() {
    exists(AssignStmt a, KeyValuePair item |
      a.getScope() instanceof Module and
      a.getATarget().(Name).getId() = "SIMPLE_JWT" and
      item = a.getValue().(Dict).getAnItem() and
      item.getKey().(StringLiteral).getText() = "SIGNING_KEY" and
      this.asExpr() = item.getValue()
    )
  }

  override string getSettingName() { result = "SIGNING_KEY" }
}

/**
 * Gets a call that reads a value from the environment, such as `os.environ["X"]`,
 * `os.getenv("X")`, `environ.Env()("X")` or `decouple.config("X")`.
 */
DataFlow::Node environmentRead() {
  result = API::moduleImport("os").getMember("environ").getASubscript().asSource()
  or
  result = API::moduleImport("os").getMember("environ").getMember(["get", "setdefault"]).getACall()
  or
  result = API::moduleImport("os").getMember(["getenv", "getenvb"]).getACall()
  or
  exists(API::Node env | env = API::moduleImport("environ").getMember("Env").getReturn() |
    result = env.getACall() or result = env.getAMember().getACall()
  )
  or
  result = API::moduleImport("decouple").getMember("config").getACall()
}

/** Holds if `node` is (locally) derived from a value read from the environment. */
predicate isEnvironmentDerived(DataFlow::Node node) {
  TaintTracking::localTaint(environmentRead(), node)
}

/**
 * A sink for framework signing secrets: a `FrameworkSecretWrite`, or an argument modeled
 * with the `credentials-key` sink kind (for example the `key` argument of PyJWT's
 * `jwt.encode` / `jwt.decode`).
 *
 * Values that are read from the environment are excluded, as are writes to a setting that
 * is also assigned from the environment elsewhere in the same file (a common pattern for
 * development defaults that are overridden in production).
 */
class FrameworkSecretSink extends DataFlow::Node {
  FrameworkSecretSink() {
    (
      exists(FrameworkSecretWrite w | w = this |
        not exists(FrameworkSecretWrite other |
          other.getSettingName() = w.getSettingName() and
          other.getLocation().getFile() = w.getLocation().getFile() and
          isEnvironmentDerived(other)
        )
      )
      or
      ModelOutput::sinkNode(this, "credentials-key")
    ) and
    not isEnvironmentDerived(this)
  }
}

/** Holds if `f` is a test file, or is located in a test directory. */
predicate isInTestLocation(File f) {
  f.getRelativePath().regexpMatch("(.*/)?(tests?|testing)/.*")
  or
  f.getShortName().regexpMatch("test_.*\\.py|.*_tests?\\.py|conftest\\.py")
}

class CredentialSanitizer extends DataFlow::Node {
  CredentialSanitizer() {
    exists(string s | s.matches("credentials-%") |
      // Whatever the string, this will sanitize flow to all credential sinks.
      ModelOutput::barrierNode(this, s)
    )
  }
}

/**
 * Gets a regular expression for matching names of locations (variables, parameters, keys) that
 * indicate the value being held is a credential.
 */
private string getACredentialRegex() {
  result = "(?i).*pass(wd|word|code|phrase)(?!.*question).*" or
  result = "(?i).*(puid|username|userid).*" or
  result = "(?i).*(cert)(?!.*(format|name)).*"
}

private newtype TCredentialFlowState =
  /** A hard-coded value that looks like a credential (generic credential heuristics). */
  TGenericCredential() or
  /** Any non-empty string literal, which is only reported at framework secret sinks. */
  TFrameworkSecret()

/** A flow state distinguishing generic credential flow from framework secret flow. */
class CredentialFlowState extends TCredentialFlowState {
  string toString() {
    this = TGenericCredential() and result = "generic credential"
    or
    this = TFrameworkSecret() and result = "framework secret"
  }
}

private module HardcodedCredentialsConfig implements DataFlow::StateConfigSig {
  class FlowState = CredentialFlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof HardcodedValueSource and state = TGenericCredential()
    or
    source instanceof FrameworkSecretLiteral and
    not isInTestLocation(source.getLocation().getFile()) and
    state = TFrameworkSecret()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof CredentialSink and
    not sink instanceof FrameworkSecretSink and
    state = TGenericCredential()
    or
    sink instanceof FrameworkSecretSink and state = TFrameworkSecret()
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof CredentialSanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module HardcodedCredentialsFlow = TaintTracking::GlobalWithState<HardcodedCredentialsConfig>;

import HardcodedCredentialsFlow::PathGraph

from HardcodedCredentialsFlow::PathNode src, HardcodedCredentialsFlow::PathNode sink
where
  HardcodedCredentialsFlow::flowPath(src, sink) and
  not any(TestScope test).contains(src.getNode().asCfgNode().getNode())
select src.getNode(), src, sink, "This hardcoded value is $@.", sink.getNode(),
  "used as credentials"
