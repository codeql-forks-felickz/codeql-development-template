using System.Web;

public class ArrayIndexHandler
{
    public void Handle(HttpRequest req)
    {
        int index = int.Parse(req.QueryString["id"]);
        int[] array = { 0, 1, 2, 3, 4 };
        // BAD: the index is not checked against the bounds of the array
        array[index] = 42;
    }
}
