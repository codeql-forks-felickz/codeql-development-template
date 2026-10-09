// Minimal stubs for the System.CodeDom NuGet package (not part of the .NET shared framework).
namespace System.CodeDom.Compiler
{
    public class CompilerParameters
    {
        public bool GenerateInMemory { get; set; }
    }

    public class CompilerResults
    {
    }

    public interface ICodeCompiler
    {
        CompilerResults CompileAssemblyFromSource(CompilerParameters options, string source);
        CompilerResults CompileAssemblyFromSourceBatch(CompilerParameters options, string[] sources);
    }

    public abstract class CodeDomProvider
    {
        public virtual CompilerResults CompileAssemblyFromSource(CompilerParameters options, params string[] sources) => null;
        public virtual CompilerResults CompileAssemblyFromFile(CompilerParameters options, params string[] fileNames) => null;
        public abstract ICodeCompiler CreateCompiler();
    }
}

namespace Microsoft.CSharp
{
    using System.CodeDom.Compiler;

    public class CSharpCodeProvider : CodeDomProvider
    {
        public override ICodeCompiler CreateCompiler() => null;
    }
}

namespace Microsoft.VisualBasic
{
    using System.CodeDom.Compiler;

    public class VBCodeProvider : CodeDomProvider
    {
        public override ICodeCompiler CreateCompiler() => null;
    }
}
