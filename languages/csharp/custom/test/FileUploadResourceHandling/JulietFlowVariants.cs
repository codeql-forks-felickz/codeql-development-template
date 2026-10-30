using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web;

namespace Testcases
{
    // CWE-400 for_loop: the request value reaches a loop bound in another method,
    // and output is performed on every iteration.
    public class CWE400_QueryString_Web_for_loop_Variants
    {
        public void BadCrossMethod(HttpRequest req, HttpResponse resp)
        {
            int count = int.MinValue;
            if (req.QueryString["id"] != null)
            {
                count = int.Parse(req.QueryString["id"]); // $ Source
            }
            BadSink(count);
        }

        private static void BadSink(int count)
        {
            for (int i = 0; i < count; i++) // $ Alert
            {
                Console.WriteLine("Hello");
            }
        }

        public void GoodB2G(HttpRequest req, HttpResponse resp)
        {
            int count = int.Parse(req.QueryString["id"]);
            GoodB2GSink(count);
        }

        private static void GoodB2GSink(int count)
        {
            if (count > 0 && count <= 20)
            {
                for (int i = 0; i < count; i++)
                {
                    Console.WriteLine("Hello");
                }
            }
        }

        // Juliet flow variant 73: data passed in a LinkedList.
        public void BadLinkedList(HttpRequest req, HttpResponse resp)
        {
            int count = int.Parse(req.QueryString["id"]); // $ Source
            var countLinkedList = new LinkedList<int>();
            countLinkedList.AddLast(count);
            LinkedListSink(countLinkedList);
        }

        private static void LinkedListSink(LinkedList<int> countLinkedList)
        {
            int count = countLinkedList.Last.Value;
            for (int i = 0; i < count; i++) // $ Alert
            {
                Console.WriteLine("Hello");
            }
        }

        public void GoodLinkedList()
        {
            var countLinkedList = new LinkedList<int>();
            countLinkedList.AddLast(2);
            int count = countLinkedList.Last.Value;
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("Hello");
            }
        }

        // Juliet flow variant 75: data passed as a serialized object.
        public void BadSerialized(HttpRequest req, HttpResponse resp)
        {
            int count = int.Parse(req.QueryString["id"]); // $ Source
            byte[] countSerialized;
            var bf = new BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                bf.Serialize(ms, count);
                countSerialized = ms.ToArray();
            }
            SerializedSink(countSerialized);
        }

        private static void SerializedSink(byte[] countSerialized)
        {
            int count;
            var binForm = new BinaryFormatter();
            using (var memStream = new MemoryStream())
            {
                memStream.Write(countSerialized, 0, countSerialized.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                count = (int)binForm.Deserialize(memStream);
            }
            for (int i = 0; i < count; i++) // $ Alert
            {
                Console.WriteLine("Hello");
            }
        }

        public void GoodSerialized()
        {
            int count;
            var bf = new BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                bf.Serialize(ms, 2);
                ms.Seek(0, SeekOrigin.Begin);
                count = (int)bf.Deserialize(ms);
            }
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("Hello");
            }
        }
    }
}
