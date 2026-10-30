// Reduced from Broken-Vulnerable-Code-Snippets "Path Traversal/PT1.cs" to "PT4.cs": route
// parameters of controllers that derive from ControllerBase reach file-system sinks.
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace WebFox.Controllers.PathTraversal
{
    public class PathTraversalTest1 : ControllerBase
    {
        [HttpGet("{path}")]
        public void Test(string path) // $ Source[cs/path-injection] Source[cs/path-injection-extended]
        {
            System.IO.File.Delete(path); // $ Alert[cs/path-injection] Alert[cs/path-injection-extended]
        }
    }

    public class PathTraversalTest2 : ControllerBase
    {
        private const string RootFolder = @"C:\Temp\Data\";

        [HttpGet("{userInput}")]
        public void Test(string userInput) // $ Source[cs/path-injection] Source[cs/path-injection-extended]
        {
            var fullPath = Path.Combine(RootFolder, userInput);
            System.IO.File.Delete(fullPath); // $ Alert[cs/path-injection] Alert[cs/path-injection-extended]
        }
    }

    public class PathTraversalTest3 : ControllerBase
    {
        private const string RootFolder = @"C:\Temp\Data\";

        [HttpGet("{userInput}")]
        public void Test(string userInput) // $ Source[cs/path-injection] Source[cs/path-injection-extended]
        {
            using (var outputFile = new StreamWriter(RootFolder + userInput)) // $ Alert[cs/path-injection] Alert[cs/path-injection-extended]
            {
                outputFile.WriteLine("First line");
            }
        }
    }

    public class PathTraversalTest4 : ControllerBase
    {
        private const string RootFolder = @"C:\Temp\Data\";

        [HttpGet("{userInput}")]
        public void Test(string userInput) // $ Source[cs/path-injection] Source[cs/path-injection-extended]
        {
            using var outputFile = new StreamWriter(RootFolder + userInput); // $ Alert[cs/path-injection] Alert[cs/path-injection-extended]
            outputFile.WriteLine("First line");
        }

        [HttpGet("safe/{userInput}")]
        public void Safe(string userInput)
        {
            using var outputFile = new StreamWriter(RootFolder + "output.txt");
            outputFile.WriteLine("First line");
        }
    }
}
