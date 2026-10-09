package javax.script;

import java.io.Reader;

public interface ScriptEngine {
  Object eval(String script, ScriptContext context) throws ScriptException;

  Object eval(Reader reader, ScriptContext context) throws ScriptException;

  Object eval(String script) throws ScriptException;

  Object eval(Reader reader) throws ScriptException;

  Object eval(String script, Bindings n) throws ScriptException;

  Object eval(Reader reader, Bindings n) throws ScriptException;

  void put(String key, Object value);

  Object get(String key);
}
