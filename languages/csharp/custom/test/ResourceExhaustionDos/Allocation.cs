using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace Testcases
{
    public class UncontrolledAllocation
    {
        public void BadArray(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            byte[] buffer = new byte[size]; // $ Alert
            Console.WriteLine(buffer.Length);
        }

        public void BadListCapacity(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            var list = new List<string>(size); // $ Alert
            Console.WriteLine(list.Count);
        }

        public void BadStringBuilderCapacity(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            var sb = new StringBuilder(size); // $ Alert
            Console.WriteLine(sb.Length);
        }

        public void BadStringRepeat(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            string s = new string('a', size); // $ Alert
            Console.WriteLine(s);
        }

        public void BadEnumerableRepeat(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            var items = Enumerable.Repeat("x", size).ToList(); // $ Alert
            Console.WriteLine(items.Count);
        }

        public void BadArrayAfterLoop(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            for (int i = 0; i < size; i++) // $ Alert
            {
                Console.WriteLine(i);
            }
            byte[] buffer = new byte[size]; // $ Alert
            Console.WriteLine(buffer.Length);
        }

        // GOOD: size limited before allocation.
        public void GoodArrayChecked(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]);
            if (size < 0 || size > 4096)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }
            byte[] buffer = new byte[size];
            Console.WriteLine(buffer.Length);
        }

        // GOOD: size clamped with Math.Min.
        public void GoodArrayMin(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]);
            byte[] buffer = new byte[Math.Min(size, 4096)];
            Console.WriteLine(buffer.Length);
        }

        // GOOD: constant size.
        public void GoodConstant()
        {
            var list = new List<string>(16);
            Console.WriteLine(list.Count);
        }

        private static readonly int MaximumSize = 4096;

        public void BadArrayMinWithTaintedBound(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            byte[] buffer = new byte[Math.Min(size, size)]; // $ Alert
            Console.WriteLine(buffer.Length);
        }

        public void BadArrayClampWithTaintedMaximum(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]); // $ Source
            byte[] buffer = new byte[Math.Clamp(size, 0, size)]; // $ Alert
            Console.WriteLine(buffer.Length);
        }

        // GOOD: the readonly limit is independent of the request value.
        public void GoodArrayMinWithReadonlyBound(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]);
            byte[] buffer = new byte[Math.Min(size, MaximumSize)];
            Console.WriteLine(buffer.Length);
        }

        // GOOD: the readonly limit is independent of the request value.
        public void GoodArrayClampWithReadonlyMaximum(HttpRequest req)
        {
            int size = int.Parse(req.QueryString["size"]);
            byte[] buffer = new byte[Math.Clamp(size, 0, MaximumSize)];
            Console.WriteLine(buffer.Length);
        }
    }
}
