using System;
using System.Web;

namespace Test
{
    class IntegerOverflow
    {
        // CWE-190: request-derived integer incremented without a range check.
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            int data = int.MinValue;
            string stringNumber = req.Params.Get("name"); // $ Source
            try
            {
                data = int.Parse(stringNumber.Trim());
            }
            catch (FormatException) { }
            int result = (int)(data + 1); // $ Alert
            resp.Write("result: " + result);
        }

        public void BadCompound(HttpRequest req, HttpResponse resp)
        {
            long data = long.Parse(req.QueryString["count"]); // $ Source
            data *= 1024; // $ Alert
            resp.Write("result: " + data);
        }

        public void BadSubtract(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.Form["offset"]); // $ Source
            int result = data - 10; // $ Alert
            resp.Write("result: " + result);
        }

        public void BadTryParse(HttpRequest req, HttpResponse resp)
        {
            if (int.TryParse(req.QueryString["size"], out int data)) // $ Source
            {
                int result = data * 4; // $ Alert
                resp.Write("result: " + result);
            }
        }

        // Hardcoded source: no alert.
        public void GoodG2B(HttpRequest req, HttpResponse resp)
        {
            int data = 2;
            int result = (int)(data + 1);
            resp.Write("result: " + result);
        }

        // Range check before the addition: no alert.
        public void GoodB2G(HttpRequest req, HttpResponse resp)
        {
            int data = int.MinValue;
            string stringNumber = req.Params.Get("name");
            try
            {
                data = int.Parse(stringNumber.Trim());
            }
            catch (FormatException) { }
            if (data < int.MaxValue)
            {
                int result = (int)(data + 1);
                resp.Write("result: " + result);
            }
            else
            {
                resp.Write("data value is too large to perform addition.");
            }
        }

        // Early-return range check: no alert.
        public void GoodEarlyReturn(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]);
            if (data >= 1000 || data <= -1000)
                return;
            int result = data * 2;
            resp.Write("result: " + result);
        }

        // Checked context throws OverflowException instead of wrapping: no alert.
        public void GoodChecked(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]);
            int result = checked(data + 1);
            resp.Write("result: " + result);
        }

        // An inner unchecked context overrides its enclosing checked block.
        public void BadNestedUnchecked(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]); // $ Source
            checked
            {
                int result = unchecked(data + 1); // $ Alert
                resp.Write("result: " + result);
            }
        }

        // An inner checked context overrides its enclosing unchecked block.
        public void GoodNestedChecked(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]);
            unchecked
            {
                int result = checked(data + 1);
                resp.Write("result: " + result);
            }
        }

        // Arithmetic promoted from byte to int cannot overflow byte's range.
        public void GoodBytePromotion(HttpRequest req, HttpResponse resp)
        {
            byte data = byte.Parse(req.QueryString["n"]);
            int result = data + 1;
            resp.Write("result: " + result);
        }

        // Arithmetic widened from int to long cannot overflow int's range.
        public void GoodLongWidening(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]);
            long result = data + 1L;
            resp.Write("result: " + result);
        }

        // Value clamped with Math.Min/Math.Max: no alert.
        public void GoodClamped(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]);
            int bounded = Math.Max(0, Math.Min(data, 100));
            int result = bounded + 1;
            resp.Write("result: " + result);
        }

        // A lower bound alone does not prevent overflow at int.MaxValue.
        public void BadOneSidedClamp(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]); // $ Source
            int result = Math.Max(data, 0) + 1; // $ Alert
            resp.Write("result: " + result);
        }

        // String concatenation is not arithmetic: no alert.
        public void GoodConcat(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["n"]);
            resp.Write("value: " + data);
        }

        // Floating-point arithmetic does not wrap: no alert.
        public void GoodDouble(HttpRequest req, HttpResponse resp)
        {
            double data = double.Parse(req.QueryString["n"]);
            double result = data + 1;
            resp.Write("result: " + result);
        }
    }

    class DivideByZero
    {
        // CWE-369: request-derived integer used as a divisor without a zero check.
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            int data = int.MinValue;
            if (req.QueryString["id"] != null)
            {
                try
                {
                    data = int.Parse(req.QueryString["id"]); // $ Source
                }
                catch (FormatException) { }
            }
            resp.Write("bad: 100/" + data + " = " + (100 / data) + "\n"); // $ Alert
        }

        public void BadRemainder(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.Params.Get("name")); // $ Source
            resp.Write("bad: 100%" + data + " = " + (100 % data) + "\n"); // $ Alert
        }

        public void BadCompound(HttpRequest req, HttpResponse resp)
        {
            int total = 100;
            int data = int.Parse(req.QueryString["parts"]); // $ Source
            total /= data; // $ Alert
            resp.Write("bad: " + total);
        }

        // Hardcoded source: no alert.
        public void GoodG2B(HttpRequest req, HttpResponse resp)
        {
            int data = 2;
            resp.Write("100/" + data + " = " + (100 / data) + "\n");
        }

        // Zero check before the division: no alert.
        public void GoodB2G(HttpRequest req, HttpResponse resp)
        {
            int data = int.MinValue;
            if (req.QueryString["id"] != null)
            {
                try
                {
                    data = int.Parse(req.QueryString["id"]);
                }
                catch (FormatException) { }
            }
            if (data != 0)
            {
                resp.Write("100/" + data + " = " + (100 / data) + "\n");
            }
            else
            {
                resp.Write("This would result in a divide by zero");
            }
        }

        // Early-return zero check: no alert.
        public void GoodEarlyReturn(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]);
            if (data == 0)
                return;
            resp.Write("100/" + data + " = " + (100 / data) + "\n");
        }

        // Positive range check: no alert.
        public void GoodPositive(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]);
            if (data > 0)
            {
                resp.Write("100/" + data + " = " + (100 / data) + "\n");
            }
        }

        // A clamp that can return zero does not make the divisor safe.
        public void BadClampCanReturnZero(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]); // $ Source
            int divisor = Math.Clamp(data, 0, 100);
            resp.Write("100/" + divisor + " = " + (100 / divisor) + "\n"); // $ Alert
        }

        // A strictly positive lower bound excludes zero.
        public void GoodPositiveMathBound(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]);
            int divisor = Math.Max(data, 1);
            resp.Write("100/" + divisor + " = " + (100 / divisor) + "\n");
        }

        // Tainted value as the dividend only: no alert.
        public void GoodDividend(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]);
            resp.Write("" + (data / 2));
        }

        // Floating-point division does not throw: no alert.
        public void GoodDouble(HttpRequest req, HttpResponse resp)
        {
            double data = double.Parse(req.QueryString["id"]);
            resp.Write("" + (100.0 / data));
        }
    }
}
