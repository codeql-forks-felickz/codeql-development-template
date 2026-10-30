using System;
using System.CodeDom.Compiler;
using System.Text;
using System.Web;

// Mirrors the Juliet CWE94 *_Web_01 test cases: an ASP.NET request value is
// embedded in source text compiled through CodeDomProvider.CreateProvider.
public class JulietWebCodeInjection
{
    private static CompilerResults Compile(string data)
    {
        StringBuilder sourceCode = new StringBuilder("");
        sourceCode.Append("public class Calculator \n{\n");
        sourceCode.Append("\tpublic int Sum()\n\t{\n");
        sourceCode.Append("\t\treturn (10 + " + data.ToString() + ");\n");
        sourceCode.Append("\t}\n");
        sourceCode.Append("}\n");
        CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
        CompilerParameters cp = new CompilerParameters();
        return provider.CompileAssemblyFromSource(cp, sourceCode.ToString()); // $ Alert
    }

    // Params_Get_Web_01: req.Params.Get("name")
    public void ParamsGetBad(HttpRequest req, HttpResponse resp)
    {
        string data = req.Params.Get("name"); // $ Source
        StringBuilder sourceCode = new StringBuilder("");
        sourceCode.Append("public class Calculator \n{\n");
        sourceCode.Append("\tpublic int Sum()\n\t{\n");
        sourceCode.Append("\t\treturn (10 + " + data.ToString() + ");\n");
        sourceCode.Append("\t}\n");
        sourceCode.Append("}\n");
        CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
        CompilerParameters cp = new CompilerParameters();
        CompilerResults cr = provider.CompileAssemblyFromSource(cp, sourceCode.ToString()); // $ Alert
    }

    // QueryString_Web_01: req.QueryString["id"]
    public void QueryStringBad(HttpRequest req, HttpResponse resp)
    {
        string data = "";
        if (req.QueryString["id"] != null)
        {
            data = req.QueryString["id"]; // $ Source
        }
        StringBuilder sourceCode = new StringBuilder("");
        sourceCode.Append("public class Calculator \n{\n");
        sourceCode.Append("\tpublic int Sum()\n\t{\n");
        sourceCode.Append("\t\treturn (10 + " + data.ToString() + ");\n");
        sourceCode.Append("\t}\n");
        sourceCode.Append("}\n");
        CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
        CompilerParameters cp = new CompilerParameters();
        CompilerResults cr = provider.CompileAssemblyFromSource(cp, sourceCode.ToString()); // $ Alert
    }

    // Interprocedural variant: request value reaches the sink through a helper.
    public void QueryStringViaHelper(HttpRequest req)
    {
        Compile(req.QueryString["id"]); // $ Source
    }

    // GoodG2B: constant data.
    public void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data = "10";
        StringBuilder sourceCode = new StringBuilder("");
        sourceCode.Append("public class Calculator \n{\n");
        sourceCode.Append("\tpublic int Sum()\n\t{\n");
        sourceCode.Append("\t\treturn (10 + " + data.ToString() + ");\n");
        sourceCode.Append("\t}\n");
        sourceCode.Append("}\n");
        CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
        CompilerParameters cp = new CompilerParameters();
        CompilerResults cr = provider.CompileAssemblyFromSource(cp, sourceCode.ToString());
    }

    // GoodB2G-style: only the parsed integer is embedded.
    public void GoodB2GParsed(HttpRequest req, HttpResponse resp)
    {
        int parsedNum = int.Parse(req.Params.Get("name"));
        StringBuilder sourceCode = new StringBuilder("");
        sourceCode.Append("\t\treturn (10 + " + parsedNum.ToString() + ");\n");
        CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
        CompilerParameters cp = new CompilerParameters();
        CompilerResults cr = provider.CompileAssemblyFromSource(cp, sourceCode.ToString());
    }
}
