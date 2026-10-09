package javax.script;

public abstract class CompiledScript {
  public abstract Object eval(ScriptContext context) throws ScriptException;

  public Object eval() throws ScriptException {
    return null;
  }
}
