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
    column = decl.getArgument(0).getConstantValue().getStringlikeValue() and
    (
      isStringColumnType(decl.getMethodName())
      or
      decl.getMethodName() = "column" and
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
    snake = m.getName().regexpReplaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase()
  |
    if snake.regexpMatch(".*[^aeiou]y")
    then result = snake.prefix(snake.length() - 1) + "ies"
    else
      if snake.regexpMatch(".*(s|x|z|ch|sh)")
      then result = snake + "es"
      else result = snake + "s"
  )
}

/**
 * Holds if the model `m` shows evidence of hashing or encrypting the value of
 * `column` before it is stored.
 */
bindingset[column]
predicate modelProtectsColumn(ActiveRecordModelClass m, string column) {
  exists(MethodCall c | c.getEnclosingModule() = m |
    c.getMethodName() = ["encrypts", "attr_encrypted"] and
    c.getAnArgument().getConstantValue().getStringlikeValue() = column
    or
    c.getMethodName() =
      ["has_secure_password", "devise", "acts_as_authentic", "authenticates_with_sorcery!"]
  )
  or
  exists(ConstantReadAccess k | k.getEnclosingModule() = m |
    k.getName() = ["BCrypt", "Argon2", "SCrypt", "Digest"]
  )
}

from MethodCall decl, string table, string column
where
  stringColumnDeclaration(decl, table, column) and
  isPasswordColumnName(column) and
  not exists(ActiveRecordModelClass m |
    conventionalTableName(m) = table and
    modelProtectsColumn(m, column)
  )
select decl,
  "Column '" + column + "' of table '" + table +
    "' stores passwords in clear text; store a salted password hash instead."
