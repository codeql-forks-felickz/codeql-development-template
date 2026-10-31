/**
 * Provides path-injection sinks for Django template names.
 *
 * A user-controlled template name passed to `django.shortcuts.render` can select
 * templates outside the intended application directory.
 */

private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.DataFlow

predicate isDjangoTemplateNameSink(DataFlow::Node sink) {
  sink = API::moduleImport("django")
    .getMember("shortcuts")
    .getMember("render")
    .getACall()
    .getParameter(1, "template_name")
    .asSink()
}
