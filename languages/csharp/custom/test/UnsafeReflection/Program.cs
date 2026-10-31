// Reduced from a console program that instantiates a type named on the command line.
// (Written with an explicit Main because the test extractor compiles a library.)
using System;

public static class Program
{
    public static void Main(string[] args) // $ Source
    {
        Console.WriteLine("I don't need a ctor!");
        Type type = Type.GetType(Environment.GetCommandLineArgs()[1]); // $ Alert
        var surprise = Activator.CreateInstance(type!);
        Console.WriteLine(surprise.ToString());

        Type fromArgs = Type.GetType(args[0]); // $ Alert
        Activator.CreateInstance(fromArgs);
    }
}
