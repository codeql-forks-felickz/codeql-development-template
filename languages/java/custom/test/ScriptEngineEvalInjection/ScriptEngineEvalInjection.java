import java.io.StringReader;
import javax.script.Bindings;
import javax.script.Compilable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletRequest;

public class ScriptEngineEvalInjection {

  private final ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

  // BAD: request data interpolated into JavaScript source passed to eval
  public Object bad1(HttpServletRequest request) throws ScriptException {
    String js = "var o = " + request.getParameter("jsonString") + ";";
    return engine.eval(js);
  }

  // BAD: request data used as the script, with bindings
  public Object bad2(HttpServletRequest request, Bindings bindings) throws ScriptException {
    return engine.eval(request.getHeader("X-Script"), bindings);
  }

  // BAD: request data wrapped in a Reader and evaluated
  public Object bad3(HttpServletRequest request) throws ScriptException {
    StringReader reader = new StringReader("var o = " + request.getParameter("jsonString"));
    return engine.eval(reader);
  }

  // BAD: request data compiled via Compilable
  public void bad4(HttpServletRequest request) throws ScriptException {
    String js = "var o = " + request.getParameter("jsonString") + ";";
    ((Compilable) engine).compile(js).eval();
  }

  // GOOD: constant script
  public Object good1() throws ScriptException {
    return engine.eval("var o = {};");
  }

  // GOOD: request data converted to an integer
  public Object good2(HttpServletRequest request) throws ScriptException {
    int n = Integer.parseInt(request.getParameter("n"));
    return engine.eval("var o = " + n + ";");
  }

  // GOOD: request data converted to a boolean
  public Object good3(HttpServletRequest request) throws ScriptException {
    boolean b = Boolean.parseBoolean(request.getParameter("b"));
    return engine.eval("var o = " + b + ";");
  }

  // GOOD: request data passed as a binding value, not as script source
  public Object good4(HttpServletRequest request) throws ScriptException {
    engine.put("input", request.getParameter("jsonString"));
    return engine.eval("JSON.parse(input)");
  }
}
