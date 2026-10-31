using System;
using System.Web;

public class ImproperValidationOfArrayIndexTest
{
    // Reduced from Juliet CWE129 Params_Get_Web array_write_no_check.
    public void BadParamsGet(HttpRequest req, HttpResponse resp)
    {
        int data = int.MinValue;
        string stringNumber = req.Params.Get("name"); // $ Source
        try
        {
            data = int.Parse(stringNumber.Trim());
        }
        catch (FormatException) { }
        int[] array = { 0, 1, 2, 3, 4 };
        array[data] = 42; // $ Alert
    }

    // Reduced from Juliet CWE129 QueryString_Web array_write_no_check.
    public void BadQueryString(HttpRequest req, HttpResponse resp)
    {
        int data = int.MinValue;
        if (req.QueryString["id"] != null)
        {
            data = int.Parse(req.QueryString["id"]); // $ Source
        }
        int[] array = { 0, 1, 2, 3, 4 };
        array[data] = 42; // $ Alert
    }

    public void BadRead(HttpRequest req, HttpResponse resp)
    {
        int data = int.Parse(req.QueryString["id"]); // $ Source
        int[] array = { 0, 1, 2, 3, 4 };
        Console.WriteLine(array[data]); // $ Alert
    }

    public void BadTryParse(HttpRequest req, HttpResponse resp)
    {
        int data;
        int.TryParse(req.QueryString["id"], out data); // $ Source
        int[] array = { 0, 1, 2, 3, 4 };
        array[data] = 42; // $ Alert
    }

    // Only the upper bound is checked: negative values still fail.
    public void BadUpperBoundOnly(HttpRequest req, HttpResponse resp)
    {
        int data = int.Parse(req.QueryString["id"]); // $ Source
        int[] array = { 0, 1, 2, 3, 4 };
        if (data < array.Length)
        {
            array[data] = 42; // $ Alert
        }
    }

    // Only the lower bound is checked: large values still fail.
    public void BadLowerBoundOnly(HttpRequest req, HttpResponse resp)
    {
        int data = int.Parse(req.QueryString["id"]); // $ Source
        int[] array = { 0, 1, 2, 3, 4 };
        if (data >= 0)
        {
            array[data] = 42; // $ Alert
        }
    }

    // GOOD: hardcoded index (Juliet goodG2B).
    public void GoodConstant(HttpRequest req, HttpResponse resp)
    {
        int data = 2;
        int[] array = { 0, 1, 2, 3, 4 };
        array[data] = 42;
    }

    // GOOD: index verified before write (Juliet goodB2G).
    public void GoodChecked(HttpRequest req, HttpResponse resp)
    {
        int data = int.Parse(req.QueryString["id"]);
        int[] array = { 0, 1, 2, 3, 4 };
        if (data >= 0 && data < array.Length)
        {
            array[data] = 42;
        }
        else
        {
            Console.WriteLine("Array index out of bounds");
        }
    }

    // GOOD: early exit when the index is out of range.
    public void GoodEarlyReturn(HttpRequest req, HttpResponse resp)
    {
        int data = int.Parse(req.QueryString["id"]);
        int[] array = { 0, 1, 2, 3, 4 };
        if (data < 0 || data >= array.Length)
        {
            return;
        }
        array[data] = 42;
    }

    // GOOD: reversed operand order in the comparisons.
    public void GoodReversedComparison(HttpRequest req, HttpResponse resp)
    {
        int data = int.Parse(req.QueryString["id"]);
        int[] array = { 0, 1, 2, 3, 4 };
        if (0 <= data && array.Length > data)
        {
            array[data] = 42;
        }
    }

    // GOOD: an unsigned index cannot be negative, so the upper bound check is enough.
    public void GoodUnsignedUpperBound(HttpRequest req, HttpResponse resp)
    {
        uint data = (uint)int.Parse(req.QueryString["id"]);
        int[] array = { 0, 1, 2, 3, 4 };
        if (data < array.Length)
        {
            array[data] = 42;
        }
    }

    // An unsigned index without an upper bound check is still flagged.
    public void BadUnsignedUnchecked(HttpRequest req, HttpResponse resp)
    {
        uint data = (uint)int.Parse(req.QueryString["id"]); // $ Source
        int[] array = { 0, 1, 2, 3, 4 };
        array[data] = 42; // $ Alert
    }
}
