using System;

public class UncontrolledFormatStringLocalTest
{
    // Reduced from Juliet CWE134 Environment_Format.
    public void Bad()
    {
        string data = Environment.GetEnvironmentVariable("ADD"); // $ Source
        if (data != null)
        {
            Console.Write(string.Format(data)); // $ Alert
        }
    }

    // GOOD: hardcoded format string (Juliet goodG2B).
    public void GoodConstant()
    {
        string data = "foo";
        Console.Write(string.Format(data));
    }

    // GOOD: environment value passed as a format argument (Juliet goodB2G).
    public void GoodArgument()
    {
        string data = Environment.GetEnvironmentVariable("ADD");
        if (data != null)
        {
            Console.Write(string.Format("{0}{1}", data, Environment.NewLine));
        }
    }
}
