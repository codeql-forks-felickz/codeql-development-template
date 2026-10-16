/**
 * @name SQL query built from user-controlled sources in a JSP scriptlet
 * @description Building a SQL query from request data inside a JSP scriptlet is vulnerable
 *              to insertion of malicious SQL code by the user. JSP files are not extracted by
 *              the Java extractor, so this query inspects the scriptlet text that the
 *              JavaScript extractor records for `.jsp` files.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id js/jsp-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript

/**
 * A JSP scriptlet (`<% ... %>`), expression (`<%= ... %>`) or declaration (`<%! ... %>`)
 * in a `.jsp` file. Directives (`<%@ ... %>`) and JSP comments (`<%-- ... --%>`) are excluded.
 */
class JspScriptlet extends Templating::TemplatePlaceholderTag {
  JspScriptlet() {
    this.getFile().getExtension() = "jsp" and
    this.getRawText().regexpMatch("(?s)<%[^@-].*%>")
  }

  /** Gets the Java code of this scriptlet, with the delimiters blanked out to preserve offsets. */
  string getCode() {
    result =
      this.getRawText()
          .regexpReplaceAll("^<%", "  ")
          .regexpReplaceAll("^  [=!]", "   ")
          .regexpReplaceAll("%>$", "  ")
  }
}

/** Gets a regular expression matching a Java string or character literal. */
private string literalRegex() { result = "\"(?:[^\"\\\\\\n]|\\\\.)*\"|'(?:[^'\\\\\\n]|\\\\.)*'" }

/** Gets a regular expression matching a single (approximate) Java statement. */
private string statementRegex() {
  result = "(?:" + literalRegex() + "|[^;{}\"'\\s])(?:" + literalRegex() + "|[^;{}\"'])*"
}

/** Gets a regular expression matching a read of user-controlled request data. */
private string sourceRegex() {
  result =
    "\\brequest\\s*\\.\\s*(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getRequestURI|getRequestURL|getPathInfo|getInputStream|getReader)\\s*\\("
}

/** Gets a regular expression matching a conversion that removes SQL meta-characters. */
private string sanitizerRegex() {
  result =
    "(?s).*\\b(?:(?:Integer|Long|Short|Byte|Double|Float|Boolean)\\s*\\.\\s*(?:parse\\w*|valueOf)|encodeForSQL)\\s*\\(.*"
}

/** Gets a regular expression matching a call to a JDBC/JPA/Hibernate SQL execution method. */
private string sinkRegex() {
  result =
    "(?s).*\\b(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|nativeSQL|createQuery|createNativeQuery|createSQLQuery)\\s*\\((.*)"
}

/** An approximate Java statement inside a JSP scriptlet. */
class JspStatement extends TJspStatement {
  JspScriptlet scriptlet;
  int offset;
  string text;

  JspStatement() {
    this = MkJspStatement(scriptlet, offset) and
    text = scriptlet.getCode().regexpFind(statementRegex(), _, offset)
  }

  /** Gets the file containing this statement. */
  File getFile() { result = scriptlet.getFile() }

  /** Gets the code of this statement with literal contents and comments removed. */
  string getCode() {
    result =
      text.regexpReplaceAll(literalRegex(), "\"\"")
          .regexpReplaceAll("(?m)//.*$", "")
          .regexpReplaceAll("(?s)/\\*.*?\\*/", "")
  }

  /** Holds if this statement reads user-controlled data or a tainted variable. */
  bindingset[code]
  predicate mentionsTainted(string code) {
    code.regexpMatch("(?s).*" + sourceRegex() + ".*")
    or
    exists(string v |
      taintedVariable(this.getFile(), v) and
      code.regexpMatch("(?s).*(?<![\\w.])" + v + "\\b(?!\\s*\\().*")
    )
  }

  /** Holds if this statement assigns (or appends) `rhs` to variable `v`. */
  predicate assigns(string v, string rhs) {
    v = this.getCode().regexpCapture("(?s).*?\\b(\\w+)\\s*\\+?=(?!=)\\s*(.*)", 1) and
    rhs = this.getCode().regexpCapture("(?s).*?\\b(\\w+)\\s*\\+?=(?!=)\\s*(.*)", 2)
    or
    v = this.getCode().regexpCapture("(?s).*?\\b(\\w+)\\s*\\.\\s*(?:append|insert)\\s*\\((.*)", 1) and
    rhs = this.getCode().regexpCapture("(?s).*?\\b(\\w+)\\s*\\.\\s*(?:append|insert)\\s*\\((.*)", 2)
  }

  /** Gets the name of the SQL execution method called by this statement, with arguments `args`. */
  string getSinkMethod(string args) {
    result = this.getCode().regexpCapture(sinkRegex(), 1) and
    args = this.getCode().regexpCapture(sinkRegex(), 2)
  }

  /** Gets the source text of this statement, without leading comments and surrounding whitespace. */
  private string getTrimmedText() { result = text.suffix(this.getLeadLength()).trim() }

  /** Gets the length of the comments and whitespace preceding this statement. */
  private int getLeadLength() {
    result = text.regexpCapture("(?s)((?:\\s|//[^\\n]*|/\\*.*?\\*/)*).*", 1).length()
  }

  /** Gets the line and column of the character at `pos` in the scriptlet. */
  private predicate position(int pos, int line, int col) {
    pos = [this.getStartOffset(), this.getEndOffset()] and
    exists(string before, Location loc |
      before = scriptlet.getRawText().prefix(pos) and
      loc = scriptlet.getLocation() and
      line = loc.getStartLine() + count(before.indexOf("\n")) and
      if exists(before.indexOf("\n"))
      then col = pos - max(before.indexOf("\n"))
      else col = loc.getStartColumn() + pos
    )
  }

  /** Holds if this statement is at the specified location. */
  predicate hasLocationInfo(string path, int sl, int sc, int el, int ec) {
    path = this.getFile().getAbsolutePath() and
    this.position(this.getStartOffset(), sl, sc) and
    this.position(this.getEndOffset(), el, ec)
  }

  private int getStartOffset() { result = offset + this.getLeadLength() }

  private int getEndOffset() { result = this.getStartOffset() + this.getTrimmedText().length() - 1 }

  /** Gets a textual representation of this statement. */
  string toString() { result = this.getTrimmedText() }
}

private newtype TJspStatement =
  MkJspStatement(JspScriptlet s, int offset) {
    exists(s.getCode().regexpFind(statementRegex(), _, offset))
  }

/** Holds if variable `v` in JSP file `f` holds user-controlled data. */
predicate taintedVariable(File f, string v) {
  exists(JspStatement s, string rhs |
    s.getFile() = f and
    s.assigns(v, rhs) and
    not rhs.regexpMatch(sanitizerRegex()) and
    not rhs.regexpMatch(sinkRegex()) and
    s.mentionsTainted(rhs)
  )
}

from JspStatement s, string method, string args
where
  method = s.getSinkMethod(args) and
  s.mentionsTainted(args)
select s,
  "This JSP scriptlet passes a SQL query built from user-controlled request data to '" + method +
    "'."
