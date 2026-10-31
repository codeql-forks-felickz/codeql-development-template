using System;
using System.Web;

namespace Testcases
{
    // Reduced from Juliet CWE606_Unchecked_Loop_Condition__Params_Get_Web_01.
    public class UncheckedLoopCondition
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("name"); // $ Source
            int numberOfLoops;
            try
            {
                numberOfLoops = int.Parse(data);
            }
            catch (FormatException)
            {
                numberOfLoops = 1;
            }
            for (int i = 0; i < numberOfLoops; i++) // $ Alert
            {
                Console.WriteLine("hello world");
            }
        }

        public void BadQueryStringWhile(HttpRequest req)
        {
            int count = int.Parse(req.QueryString["count"]); // $ Source
            int i = 0;
            while (i < count) // $ Alert
            {
                Console.WriteLine("hello world");
                i++;
            }
        }

        public void BadReversedComparison(HttpRequest req)
        {
            int count = Convert.ToInt32(req.QueryString["count"]); // $ Source
            for (int i = 0; count > i; i += 1) // $ Alert
            {
                Console.WriteLine("hello world");
            }
        }

        public void BadCountdown(HttpRequest req)
        {
            int count = int.Parse(req.QueryString["count"]); // $ Source
            while (count > 0) // $ Alert
            {
                Console.WriteLine("hello world");
                count--;
            }
        }

        public void BadDoWhile(HttpRequest req)
        {
            int count = int.Parse(req.Params.Get("count")); // $ Source
            int i = 0;
            do
            {
                Console.WriteLine("hello world");
                i++;
            } while (i <= count); // $ Alert
        }

        // GOOD: hardcoded loop bound (Juliet goodG2B).
        public void GoodG2B(HttpRequest req)
        {
            string data = "5";
            int numberOfLoops = int.Parse(data);
            for (int i = 0; i < numberOfLoops; i++)
            {
                Console.WriteLine("hello world");
            }
        }

        // GOOD: loop bound validated against an upper limit (Juliet goodB2G).
        public void GoodB2G(HttpRequest req)
        {
            string data = req.Params.Get("name");
            int numberOfLoops;
            try
            {
                numberOfLoops = int.Parse(data);
            }
            catch (FormatException)
            {
                numberOfLoops = 1;
            }
            if (numberOfLoops >= 0 && numberOfLoops <= 5)
            {
                for (int i = 0; i < numberOfLoops; i++)
                {
                    Console.WriteLine("hello world");
                }
            }
        }

        // GOOD: early return when the bound is too large.
        public void GoodEarlyReturn(HttpRequest req)
        {
            int count = int.Parse(req.QueryString["count"]);
            if (count > 100)
            {
                return;
            }
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("hello world");
            }
        }

        // GOOD: bound clamped with Math.Min.
        public void GoodMathMin(HttpRequest req)
        {
            int count = Math.Min(int.Parse(req.QueryString["count"]), 100);
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("hello world");
            }
        }

        // GOOD: bound clamped with Math.Clamp.
        public void GoodMathClamp(HttpRequest req)
        {
            int count = Math.Clamp(int.Parse(req.QueryString["count"]), 0, 100);
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("hello world");
            }
        }

        // GOOD: iterating over the characters of the input is bounded by the request size.
        public void GoodLength(HttpRequest req)
        {
            string data = req.QueryString["data"];
            for (int i = 0; i < data.Length; i++)
            {
                Console.WriteLine(data[i]);
            }
        }
    }
}
