/**
 * @name Password stored in a clear-text database column
 * @description Declaring a string or text database column for account passwords,
 *              without hashing or encrypting the value in the corresponding
 *              Active Record model, stores recoverable passwords in the database.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id rb/cleartext-password-column
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-312
 */

import codeql.ruby.AST
import codeql.ruby.frameworks.ActiveRecord

/**
 * Holds if `name` is the name of a column that holds a clear-text password
 * (but not a digest or encrypted copy of it).
 */
bindingset[name]
predicate isPasswordColumnName(string name) {
  name.regexpMatch("(?i)(.*_)?(password|passwd|passcode|passphrase|pwd)") and
  not name.regexpMatch("(?i).*(crypt|hash|digest|sha|md5).*")
}

/** Holds if `type` is a schema column type that stores the raw string value. */
predicate isStringColumnType(string type) { type = ["string", "text"] }

/**
 * Holds if `decl` declares a string or text column `column` on table `table`
 * in `db/schema.rb` or a migration, for example:
 * `create_table "users" do |t| t.string "password" end` or
 * `add_column :users, :password, :string`.
 */
predicate stringColumnDeclaration(MethodCall decl, string table, string column) {
  exists(MethodCall tableCall, Block b, LocalVariable t |
    tableCall.getMethodName() = ["create_table", "change_table"] and
    table = tableCall.getArgument(0).getConstantValue().getStringlikeValue() and
    b = tableCall.getBlock() and
    t = b.getParameter(0).(NamedParameter).getVariable() and
    decl.getReceiver() = t.getAnAccess() and
    (
      isStringColumnType(decl.getMethodName()) and
      column = decl.getAnArgument().getConstantValue().getStringlikeValue()
      or
      decl.getMethodName() = "column" and
      column = decl.getArgument(0).getConstantValue().getStringlikeValue() and
      isStringColumnType(decl.getArgument(1).getConstantValue().getStringlikeValue())
    )
  )
  or
  decl.getMethodName() = "add_column" and
  table = decl.getArgument(0).getConstantValue().getStringlikeValue() and
  column = decl.getArgument(1).getConstantValue().getStringlikeValue() and
  isStringColumnType(decl.getArgument(2).getConstantValue().getStringlikeValue())
}

/** Gets the conventional (Rails) table name for the model class `m`. */
string conventionalTableName(ActiveRecordModelClass m) {
  exists(string snake |
    snake =
      m.getName()
        .regexpReplaceAll("([A-Z])(?=[A-Z][a-z])", "$1_")
        .regexpReplaceAll("([a-z0-9])([A-Z])", "$1_$2")
        .toLowerCase()
  |
    if isUncountable(snake)
    then result = snake
    else
      if exists(string plural | irregularPlural(snake, plural))
      then irregularPlural(snake, result)
      else
        if snake.regexpMatch(".*[^aeiou]y")
        then result = snake.prefix(snake.length() - 1) + "ies"
        else
          if snake.regexpMatch(".*(s|x|z|ch|sh)")
          then result = snake + "es"
          else result = snake + "s"
  )
}

predicate isUncountable(string name) {
  name = ["equipment", "information", "rice", "money", "species", "series", "fish", "sheep"]
}

bindingset[singular]
predicate irregularPlural(string singular, string plural) {
  singular.regexpMatch("(^|_)person$") and
  plural = singular.regexpReplaceAll("person$", "people")
  or
  singular.regexpMatch("(^|_)man$") and
  plural = singular.regexpReplaceAll("man$", "men")
  or
  singular.regexpMatch("(^|_)child$") and
  plural = singular.regexpReplaceAll("child$", "children")
  or
  singular.regexpMatch("(^|_)sex$") and
  plural = singular.regexpReplaceAll("sex$", "sexes")
  or
  singular.regexpMatch("(^|_)move$") and
  plural = singular.regexpReplaceAll("move$", "moves")
  or
  singular.regexpMatch("(^|_)zombie$") and
  plural = singular.regexpReplaceAll("zombie$", "zombies")
}

/**
 * Holds if the model `m` shows evidence of hashing or encrypting the value of
 * `column` before it is stored.
 */
bindingset[column]
predicate modelProtectsColumn(ActiveRecordModelClass m, string column) {
  exists(MethodCall c |
    m.getClassNode().getAnAncestor() = c.getEnclosingModule().getModule() and
    (
      c.getMethodName() = ["encrypts", "attr_encrypted"] and
      c.getAnArgument().getConstantValue().getStringlikeValue() = column
      or
      c.getMethodName() = "has_secure_password" and
      (
        not exists(c.getArgument(_)) and column = "password"
        or
        c.getArgument(0).getConstantValue().getStringlikeValue() = column
      )
      or
      c.getMethodName() = ["devise", "acts_as_authentic", "authenticates_with_sorcery!"] and
      column = "password"
    )
  )
  or
  exists(ConstantReadAccess k |
    k.getName() = ["BCrypt", "Argon2", "SCrypt", "Digest"] and
    m.getClassNode().getAnAncestor() = k.getEnclosingModule().getModule() and
    (
      exists(AssignExpr assignment |
        assignment.getRightOperand().getAChild*() = k and
        assignmentToColumn(assignment, column)
      )
      or
      exists(MethodCall write |
        write.getMethodName() = "write_attribute" and
        (
          not exists(write.getReceiver())
          or
          write.getReceiver() instanceof SelfVariableAccess
        ) and
        write.getArgument(0).getConstantValue().getStringlikeValue() = column and
        write.getArgument(1).getAChild*() = k
      )
      or
      exists(Method setter |
        setter.getEnclosingModule() = k.getEnclosingModule() and
        setter.getName() = column + "=" and
        setter.getBody().getAChild*() = k
      )
    )
  )
}

predicate assignmentToColumn(AssignExpr assignment, string column) {
  exists(MethodCall lhs |
    lhs = assignment.getLeftOperand() and
    lhs.getReceiver() instanceof SelfVariableAccess and
    (
      lhs.getMethodName() = [column, column + "="]
      or
      lhs.getMethodName() = ["[]", "[]="] and
      lhs.getArgument(0).getConstantValue().getStringlikeValue() = column
    )
  )
}

/**
 * Holds if `decl` declares the clear-text password column `column` of `table`.
 */
predicate plaintextPasswordColumn(MethodCall decl, string table, string column) {
  stringColumnDeclaration(decl, table, column) and
  isPasswordColumnName(column) and
  not exists(ActiveRecordModelClass m |
    conventionalTableName(m) = table and
    modelProtectsColumn(m, column)
  )
}

/** Gets the literal text of `lit`, ignoring interpolated components. */
string literalText(StringlikeLiteral lit) {
  result =
    concat(int i, StringTextComponent c |
      c = lit.getComponent(i)
    |
      c.getConstantValue().getString() order by i
    )
}

/**
 * Holds if the Active Record query `call` on the model `m` filters records by
 * comparing a value directly against the clear-text password column `column`
 * of `table`, for example
 * `User.find_by(password: pw)` or `User.where("password = '#{pw}'")`.
 */
predicate comparesAgainstPlaintextColumn(
  MethodCall call, ActiveRecordModelClass m, string table, string column
) {
  call.getMethodName() =
    [
      "where", "rewhere", "find_by", "find_by!", "exists?", "find_or_create_by",
      "find_or_initialize_by"
    ] and
  call.getReceiver().(ConstantReadAccess).getName() = m.getName() and
  table = conventionalTableName(m) and
  plaintextPasswordColumn(_, table, column) and
  (
    exists(call.getKeywordArgument(column))
    or
    call.getAnArgument()
        .(HashLiteral)
        .getAKeyValuePair()
        .getKey()
        .getConstantValue()
        .getStringlikeValue() = column
    or
    literalText(call.getArgument(0))
        .regexpMatch("(?is)(.*[^\\w])?" + column + "[`\"']?\\s*(=|like\\b|in\\b).*")
  )
}

from AstNode alert, string message
where
  exists(string table, string column |
    plaintextPasswordColumn(alert, table, column) and
    message =
      "Column '" + column + "' of table '" + table +
        "' stores passwords in clear text; store a salted password hash instead."
  )
  or
  exists(ActiveRecordModelClass m, string table, string column |
    comparesAgainstPlaintextColumn(alert, m, table, column) and
    message =
      "Authentication compares directly against the clear-text password column '" + column +
        "' of table '" + table + "'; verify a salted password hash instead."
  )
select alert, message
