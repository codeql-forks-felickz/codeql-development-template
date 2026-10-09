package javax.script;

import java.io.Reader;

public interface Compilable {
  CompiledScript compile(String script) throws ScriptException;

  CompiledScript compile(Reader script) throws ScriptException;
}
