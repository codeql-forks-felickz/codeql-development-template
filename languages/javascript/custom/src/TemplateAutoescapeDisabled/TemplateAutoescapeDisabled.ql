/**
 * @name Template engine HTML autoescaping disabled
 * @description Turning off HTML autoescaping in a template engine makes every plain
 *              interpolation of user-controlled data a cross-site scripting vulnerability.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/template-autoescape-disabled
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript

/** Holds if `value` is the constant `b`. */
predicate isBooleanConstant(DataFlow::Node value, boolean b) {
  value.mayHaveBooleanValue(b) and not value.mayHaveBooleanValue(b.booleanNot())
}

/**
 * Holds if `call` configures the template engine `engine` and its option object at
 * argument `i` has an option named `name` whose value disables escaping when it is `unsafe`.
 */
predicate escapingOption(
  DataFlow::InvokeNode call, string engine, int i, string name, boolean unsafe
) {
  engine = "Swig" and
  name = "autoescape" and
  unsafe = false and
  exists(API::Node swig | swig = API::moduleImport("swig") |
    call = swig.getMember("setDefaults").getACall() and i = 0
    or
    call = swig.getMember("Swig").getAnInstantiation() and i = 0
    or
    call =
      [swig, swig.getMember("Swig").getInstance()]
          .getMember(["compile", "compileFile", "render"])
          .getACall() and
    i = 1
  )
  or
  engine = "Nunjucks" and
  name = "autoescape" and
  unsafe = false and
  exists(API::Node nunjucks | nunjucks = API::moduleImport("nunjucks") |
    call = nunjucks.getMember("configure").getACall() and i = call.getNumArgument() - 1
    or
    call = nunjucks.getMember("Environment").getAnInstantiation() and i = 1
  )
  or
  engine = "Handlebars" and
  name = "noEscape" and
  unsafe = true and
  call =
    API::moduleImport(["handlebars", "handlebars/runtime"])
        .getMember(["compile", "precompile"])
        .getACall() and
  i = 1
}

from
  DataFlow::InvokeNode call, string engine, int i, string name, boolean unsafe, DataFlow::Node value
where
  escapingOption(call, engine, i, name, unsafe) and
  value = call.getOptionArgument(i, name) and
  isBooleanConstant(value, unsafe)
select value, engine + " HTML autoescaping is disabled here, so template output is not escaped."
