using System.CodeDom.Compiler;
using System.IO;
using System.Net.Sockets;
using System.Text;
using Microsoft.CSharp;
using Microsoft.VisualBasic;

public class CodeInjectionTest
{
    private static string ReadUntrusted(TcpClient client)
    {
        using (var reader = new StreamReader(client.GetStream())) // $ Source
        {
            return reader.ReadLine();
        }
    }

    // Concatenation into generated source compiled by CSharpCodeProvider (issue example).
    public void ConcatCSharpProvider(TcpClient client)
    {
        string userInput = ReadUntrusted(client);
        string src = "class Calc { public int Run() { return " + userInput + "; } }";
        new CSharpCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), src); // $ Alert
    }

    // string.Format into generated source, provider typed as the CodeDomProvider base class.
    public void FormatCodeDomProvider(TcpClient client)
    {
        string userInput = ReadUntrusted(client);
        string src = string.Format("class Calc {{ public int Run() {{ return {0}; }} }}", userInput);
        CodeDomProvider provider = new CSharpCodeProvider();
        CompilerParameters cp = new CompilerParameters();
        cp.GenerateInMemory = true;
        CompilerResults cr = provider.CompileAssemblyFromSource(cp, src); // $ Alert
    }

    // StringBuilder into generated source, Juliet-style Calculator method.
    public void StringBuilderCalculator(TcpClient client)
    {
        string data = ReadUntrusted(client);
        StringBuilder sourceCode = new StringBuilder("");
        sourceCode.Append("public class Calculator \n{\n");
        sourceCode.Append("\tpublic int Sum()\n\t{\n");
        sourceCode.Append("\t\treturn (" + data + ");\n");
        sourceCode.Append("\t}\n");
        sourceCode.Append("}\n");
        CSharpCodeProvider codeProvider = new CSharpCodeProvider();
        CompilerParameters cp = new CompilerParameters();
        CompilerResults cr = codeProvider.CompileAssemblyFromSource(cp, sourceCode.ToString()); // $ Alert
    }

    // Explicit params array argument.
    public void ExplicitArray(TcpClient client)
    {
        string userInput = ReadUntrusted(client);
        string[] sources = new string[] { "class A {}", "class B { int X = " + userInput + "; }" };
        new VBCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), sources); // $ Alert
    }

    // Untrusted value in a later params argument.
    public void SecondParamsArgument(TcpClient client)
    {
        string userInput = ReadUntrusted(client);
        new CSharpCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), "class A {}", userInput); // $ Alert
    }

    // ICodeCompiler overloads are already reported by the standard cs/code-injection query.
    public void ICodeCompilerSource(TcpClient client)
    {
        string userInput = ReadUntrusted(client);
        ICodeCompiler compiler = new CSharpCodeProvider().CreateCompiler();
        compiler.CompileAssemblyFromSource(new CompilerParameters(), userInput);
    }

    // Safe: constant source text.
    public void ConstantSource()
    {
        string src = "class Calc { public int Run() { return 1 + 1; } }";
        new CSharpCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), src);
    }

    // Safe: untrusted value only used as a parsed integer.
    public void IntegerSanitized(TcpClient client)
    {
        int value = int.Parse(ReadUntrusted(client));
        string src = "class Calc { public int Run() { return " + value + "; } }";
        new CSharpCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), src);
    }

    // Not a sink: file names are not source text.
    public void FromFile(TcpClient client)
    {
        string path = ReadUntrusted(client);
        new CSharpCodeProvider().CompileAssemblyFromFile(new CompilerParameters(), path);
    }
}
