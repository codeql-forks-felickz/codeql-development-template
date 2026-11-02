using System.Web;

public class ArrayIndexHandler
{
    public void Handle(HttpRequest req)
    {
        int index = int.Parse(req.QueryString["id"]);
        int[] array = { 0, 1, 2, 3, 4 };
        // GOOD: the index is checked against both bounds of the array
        if (index >= 0 && index < array.Length)
        {
            array[index] = 42;
        }
    }
}
