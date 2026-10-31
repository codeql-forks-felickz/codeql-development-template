/**
 * @name Clear-text sensitive data stored in a database or user store
 * @description Writing sensitive data to a database or an application's user store
 *              without protecting it exposes the data if the store is read by an attacker.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/cleartext-password-storage
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-312
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.SensitiveDataSources
import semmle.python.ApiGraphs

/** Gets a regular expression matching a password column or key name. */
string passwordName() { result = "(?i)[\"'`\\[]?pass(word|wd)?[\"'`\\]]?" }

/** Gets a regular expression matching a single SQL or format-string placeholder. */
string placeholder() { result = "%[sdr]|%\\([A-Za-z_]\\w*\\)s|\\?|\\{\\}|:[A-Za-z_]\\w*" }

/** Gets the number of placeholders in `s`. */
bindingset[s]
int placeholderCount(string s) { result = count(int i | exists(s.regexpFind(placeholder(), i, _))) }

/** Holds if the SQL value expression `item` is a single placeholder. */
bindingset[item]
predicate isPlaceholderItem(string item) {
  item.trim().regexpMatch("[\"']?(" + placeholder() + ")[\"']?")
}

/** Holds if the SQL value expression `item` is a non-empty quoted string literal. */
bindingset[item]
predicate isHardcodedItem(string item) {
  item.trim().regexpMatch("'[^'%{}?]+'|\"[^\"%{}?]+\"") and
  not looksLikePasswordHash(item.trim().regexpCapture("['\"](.*)['\"]", 1))
}

/** Holds if `pos` is inside a quoted SQL string in `s`. */
bindingset[s, pos]
predicate isInQuotedSqlString(string s, int pos) {
  exists(string quoted, int start, int occurrence |
    quoted = s.regexpFind("'([^']|'')*'|\"([^\"]|\"\")*\"", occurrence, start) and
    start < pos and pos < start + quoted.length()
  )
}

/** Holds if `pos` is a comma outside quoted strings and balanced parentheses in `s`. */
bindingset[s, pos]
predicate isTopLevelSqlComma(string s, int pos) {
  exists(string comma, int opening, int closing, int occurrence |
    comma = s.regexpFind(",", occurrence, pos) and
    not isInQuotedSqlString(s, pos) and
    opening =
      count(int p |
        p in [0 .. s.length()] and
        exists(string open, int matchIndex | open = s.regexpFind("\\(", matchIndex, p)) and
        p < pos and not isInQuotedSqlString(s, p)
      ) and
    closing =
      count(int p |
        p in [0 .. s.length()] and
        exists(string close, int matchIndex | close = s.regexpFind("\\)", matchIndex, p)) and
        p < pos and not isInQuotedSqlString(s, p)
      ) and
    opening = closing
  )
}

/** Gets the `index`th SQL value item, keeping quoted strings and parenthesized expressions intact. */
bindingset[values, index]
predicate sqlValueItem(string values, string item, int index) {
  exists(int start, int end |
    start in [0 .. values.length()] and
    end in [0 .. values.length()] and
    (
      index = 0 and start = 0
      or
      exists(int p |
        p in [0 .. values.length()] and
        isTopLevelSqlComma(values, p) and
        count(int before |
          before in [0 .. values.length()] and
          isTopLevelSqlComma(values, before) and before < p
        ) = index - 1 and
        start = p + 1
      )
    ) and
    (
      exists(int p |
        p in [0 .. values.length()] and
        isTopLevelSqlComma(values, p) and
        count(int before |
          before in [0 .. values.length()] and
          isTopLevelSqlComma(values, before) and before < p
        ) = index and
        end = p
      )
      or
      not exists(int p |
        p in [0 .. values.length()] and
        isTopLevelSqlComma(values, p) and
        count(int before |
          before in [0 .. values.length()] and
          isTopLevelSqlComma(values, before) and before < p
        ) = index
      ) and
      end = values.length()
    ) and
    item = values.prefix(end).suffix(start)
  )
}

/** Gets the number of placeholders in an SQL value item. */
bindingset[values, index]
int sqlValueItemPlaceholderCount(string values, int index) {
  exists(string item | sqlValueItem(values, item, index) |
    result = placeholderCount(item)
  )
}

/**
 * Holds if `s` looks like an already hashed password, such as a hex digest or a
 * modular crypt / Django encoded hash, rather than a clear-text password.
 */
bindingset[s]
predicate looksLikePasswordHash(string s) {
  s.regexpMatch("[0-9a-fA-F]{32,}")
  or
  s.regexpMatch("\\$[0-9a-z]+\\$.{16,}")
  or
  s.regexpMatch("(pbkdf2_sha256|pbkdf2_sha1|argon2|bcrypt_sha256|bcrypt|scrypt)\\$.+")
}

/**
 * Holds if the SQL statement `sql` writes the value expression `item` to a password column,
 * and `ord` is the number of placeholders in `sql` before that value expression.
 */
predicate passwordValueInSql(string sql, string item, int ord) {
  sql = sqlTemplate(_) and
  (
    // INSERT INTO t (c0, c1, ...) VALUES (v0, v1, ...)
    exists(string cols, string vals, int i |
      cols = sql.regexpCapture(insertRegex(), 3) and
      vals = sql.regexpCapture(insertRegex(), 4) and
      cols.splitAt(",", i).trim().regexpMatch(passwordName()) and
      sqlValueItem(vals, item, i) and
      ord = sum(int j | j in [0 .. i - 1] | sqlValueItemPlaceholderCount(vals, j))
    )
    or
    // UPDATE t SET ..., password = v, ... [WHERE ...]
    exists(string m, int offset, int setPos, int wherePos, string rest |
      sql.regexpMatch("(?is)\\s*update\\b.*") and
      exists(sql.regexpFind("(?i)\\bset\\b", 0, setPos)) and
      (
        exists(sql.regexpFind("(?i)\\bwhere\\b", 0, wherePos))
        or
        not exists(sql.regexpFind("(?i)\\bwhere\\b", 0, _)) and wherePos = sql.length()
      ) and
      m = sql.regexpFind("(?i)[\"'`\\[]?\\bpass(word|wd)?\\b[\"'`\\]]?\\s*=\\s*", _, offset) and
      offset > setPos and
      offset < wherePos and
      rest = sql.suffix(offset + m.length()) and
      item = rest.regexpCapture("(?s)('[^']*'|\"[^\"]*\"|[^\\s,]+).*", 1) and
      ord = placeholderCount(sql.prefix(offset))
    )
  )
}

/** Holds if `call` is a Django model manager's `create` method. */
predicate isDjangoModelCreate(API::CallNode call) {
  exists(API::Node modelClass |
    modelClass =
      API::moduleImport("django").getMember("db").getMember("models").getMember("Model")
        .getASubclass*()
    or
    modelClass =
      API::moduleImport("django").getMember("db").getMember("models").getMember("base")
        .getMember("Model").getASubclass*()
  |
    call = modelClass.getMember("objects").getMember("create").getACall()
  )
}

/** Gets a regular expression matching an `INSERT INTO t (cols) VALUES (vals)` statement. */
string insertRegex() {
  result =
    "(?is)\\s*(insert|replace)(\\s+or\\s+\\w+)?\\s+into\\s+[\\w.\"`\\[\\]]+\\s*\\(([^)]*)\\)\\s*values\\s*\\((.*)\\)[\\s;]*"
}

module SqlExecutionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(BinaryExpr fmt | fmt.getOp() instanceof Mod and node = DataFlow::exprNode(fmt))
    or
    exists(Call fmt | fmt.getFunc().(Attribute).getName() = "format" and node = DataFlow::exprNode(fmt))
    or
    exists(Fstring f | node = DataFlow::exprNode(f))
    or
    exists(StringLiteral lit | node = DataFlow::exprNode(lit))
  }

  predicate isSink(DataFlow::Node node) {
    exists(SqlExecution exec | node = exec.getSql())
  }
}

module SqlExecutionFlow = DataFlow::Global<SqlExecutionConfig>;

/**
 * A string template that is used to build or execute an SQL statement, together with its
 * text. For f-strings each interpolated value is represented by `{}`.
 */
string sqlTemplate(Expr e) {
  exists(BinaryExpr fmt |
    fmt.getOp() instanceof Mod and e = fmt.getLeft() and
    exists(SqlExecution exec | SqlExecutionFlow::flow(DataFlow::exprNode(fmt), exec.getSql()))
  |
    result = e.(StringLiteral).getText()
  )
  or
  exists(Call fmt |
    fmt.getFunc().(Attribute).getName() = "format" and
    exists(SqlExecution exec | SqlExecutionFlow::flow(DataFlow::exprNode(fmt), exec.getSql()))
  |
    e = fmt.getFunc().(Attribute).getObject() and result = e.(StringLiteral).getText()
  )
  or
  exists(SqlExecution exec | SqlExecutionFlow::flow(DataFlow::exprNode(e), exec.getSql())) and
  result =
    concat(int i, Expr part |
      part = e.(Fstring).getValue(i)
    |
      any(string s |
          s = part.(StringLiteral).getText()
          or
          not part instanceof StringLiteral and s = "{}"
        )
      order by
        i
    )
  or
  exists(SqlExecution exec | SqlExecutionFlow::flow(DataFlow::exprNode(e), exec.getSql()) |
    result = e.(StringLiteral).getText()
  )
}

/** Gets the `n`th value interpolated into the SQL template `template`. */
bindingset[template, item, n]
Expr templateArgument(Expr template, string item, int n) {
  exists(BinaryExpr fmt | fmt.getOp() instanceof Mod and template = fmt.getLeft() |
    exists(KeyValuePair kv |
      kv = fmt.getRight().(Dict).getAnItem() and
      kv.getKey().(StringLiteral).getText() =
        item.regexpCapture(".*%\\(([A-Za-z_]\\w*)\\)s.*", 1) and
      result = kv.getValue()
    )
    or
    result = fmt.getRight().(Tuple).getElt(n)
    or
    not fmt.getRight() instanceof Tuple and not fmt.getRight() instanceof Dict and
    n = 0 and result = fmt.getRight()
  )
  or
  exists(Call fmt |
    fmt.getFunc().(Attribute).getName() = "format" and
    template = fmt.getFunc().(Attribute).getObject() and
    result = fmt.getPositionalArg(n)
  )
  or
  exists(int i |
    i =
      rank[n + 1](int j |
        exists(template.(Fstring).getValue(j)) and
        not template.(Fstring).getValue(j) instanceof StringLiteral
      ) and
    (
      result = template.(Fstring).getValue(i).(FormattedValue).getValue()
      or
      result = template.(Fstring).getValue(i) and not result instanceof FormattedValue
    )
  )
  or
  exists(SqlExecution exec, Expr params |
    DataFlow::localFlow(DataFlow::exprNode(template), exec.getSql()) and
    params = exec.(DataFlow::CallCfgNode).getArg(1).asExpr()
  |
    result = params.(Tuple).getElt(n) or
    result = params.(List).getElt(n)
  )
}

/** A value written to a password column by an SQL statement. */
class SqlPasswordValue extends DataFlow::Node {
  SqlPasswordValue() {
    exists(Expr template, string sql, string item, int ord |
      sql = sqlTemplate(template) and
      passwordValueInSql(sql, item, ord) and
      isPlaceholderItem(item) and
      this.asExpr() = templateArgument(template, item, ord)
    )
  }
}

/**
 * The parameters argument of a parameterized SQL statement that writes to a password column,
 * when the individual parameters cannot be identified (for example `cursor.execute(sql, args)`).
 */
class SqlPasswordParameters extends DataFlow::Node {
  SqlPasswordParameters() {
    exists(SqlExecution exec, StringLiteral lit, string item |
      DataFlow::localFlow(DataFlow::exprNode(lit), exec.getSql()) and
      passwordValueInSql(lit.getText(), item, _) and
      isPlaceholderItem(item) and
      this = exec.(DataFlow::CallCfgNode).getArg(1) and
      not this.asExpr() instanceof Tuple and
      not this.asExpr() instanceof List
    )
  }
}

/** An SQL statement literal that writes a hard-coded password to a password column. */
class SqlHardcodedPassword extends DataFlow::Node {
  SqlHardcodedPassword() {
    exists(StringLiteral lit, string item |
      lit.getText() = sqlTemplate(lit) and
      passwordValueInSql(lit.getText(), item, _) and
      isHardcodedItem(item) and
      this.asExpr() = lit
    )
  }
}

/** Holds if `n` refers to a module-level variable that looks like an in-memory user store. */
predicate isUserStore(Name n) {
  n.getVariable() instanceof GlobalVariable and
  n.getId().regexpMatch("(?i).*(user|account|member|credential|login|customer).*")
}

/**
 * A value stored under a password key in an in-memory user store held in a module-level
 * variable, such as `users[name] = {"password": pw}` or `users[name]["password"] = pw`.
 */
class UserStorePasswordValue extends DataFlow::Node {
  UserStorePasswordValue() {
    exists(Dict d, KeyValuePair kv |
      kv = d.getAnItem() and
      kv.getKey().(StringLiteral).getText().regexpMatch(passwordName()) and
      this.asExpr() = kv.getValue()
    |
      // users[name] = {"password": pw}
      exists(AssignStmt a |
        isUserStore(a.getATarget().(Subscript).getObject()) and a.getValue() = d
      )
      or
      // users = {"alice": {"password": "..."}}
      exists(AssignStmt a |
        a.getScope() instanceof Module and
        isUserStore(a.getATarget()) and
        a.getValue().getASubExpression*() = d
      )
    )
    or
    // users[name]["password"] = pw
    exists(AssignStmt a, Subscript s |
      s = a.getATarget() and
      s.getIndex().(StringLiteral).getText().regexpMatch(passwordName()) and
      isUserStore(s.getObject().(Subscript).getObject()) and
      this.asExpr() = a.getValue()
    )
  }
}

/** A value passed to `create` on a Django model manager. */
class DjangoModelCreateValue extends DataFlow::Node {
  DjangoModelCreateValue() {
    exists(API::CallNode create |
      isDjangoModelCreate(create) and
      this.asExpr() = create.asExpr().(Call).getAKeyword().getValue()
    )
  }
}

/** Holds if `call` calls a function whose name suggests that it hashes or encrypts its input. */
predicate isHashingCall(DataFlow::CallCfgNode call) {
  exists(string name |
    name = call.getFunction().(DataFlow::AttrRead).getAttributeName()
    or
    name = call.getFunction().asCfgNode().(NameNode).getId()
  |
    name.regexpMatch("(?i).*(hash|crypt|digest|derive|kdf|argon).*")
  )
}

/** Holds if `node` should block the flow of a clear-text password. */
predicate isHashingBarrier(DataFlow::Node node) {
  isHashingCall(node) or
  node = any(Cryptography::CryptographicOperation op).(DataFlow::Node)
}

/** Tracks sensitive values flowing to recognized clear-text storage sinks. */
module SensitiveDataConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(SensitiveDataSource).getClassification() =
      [SensitiveDataClassification::password(), SensitiveDataClassification::private()]
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlPasswordValue or
    sink instanceof SqlPasswordParameters or
    sink instanceof UserStorePasswordValue or
    sink instanceof DjangoModelCreateValue
  }

  predicate isBarrier(DataFlow::Node node) { isHashingBarrier(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/**
 * Tracks hard-coded passwords (such as seed accounts) to a password column or user store.
 */
module HardcodedPasswordConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string text | text = source.asExpr().(StringLiteral).getText() |
      text != "" and not looksLikePasswordHash(text)
    )
    or
    source instanceof SqlHardcodedPassword
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlPasswordValue or
    sink instanceof UserStorePasswordValue or
    sink instanceof SqlHardcodedPassword
  }

  predicate isBarrier(DataFlow::Node node) { isHashingBarrier(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module SensitiveDataFlow = TaintTracking::Global<SensitiveDataConfig>;

module HardcodedPasswordFlow = DataFlow::Global<HardcodedPasswordConfig>;

module CleartextPasswordStorageFlow =
  DataFlow::MergePathGraph<SensitiveDataFlow::PathNode, HardcodedPasswordFlow::PathNode,
    SensitiveDataFlow::PathGraph, HardcodedPasswordFlow::PathGraph>;

import CleartextPasswordStorageFlow::PathGraph

from
  CleartextPasswordStorageFlow::PathNode source, CleartextPasswordStorageFlow::PathNode sink,
  string label
where
  SensitiveDataFlow::flowPath(source.asPathNode1(), sink.asPathNode1()) and
  label = "sensitive data"
  or
  HardcodedPasswordFlow::flowPath(source.asPathNode2(), sink.asPathNode2()) and
  label = "hard-coded password"
select sink.getNode(), source, sink, "This stores $@ in clear text without protecting it.",
  source.getNode(), label
