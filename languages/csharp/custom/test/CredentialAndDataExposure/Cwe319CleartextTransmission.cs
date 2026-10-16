using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security;
using System.Text;

namespace Cwe319
{
    public class CleartextTransmission
    {
        private static string ReadSecret()
        {
            string data;
            using (SecureString securePwd = new SecureString())
            {
                securePwd.AppendChar('x');
                data = securePwd.ToString();
            }
            return data;
        }

        public void BadStreamWriter()
        {
            string data = ReadSecret();
            using (TcpClient tcpClient = new TcpClient("remote_host", 1337))
            {
                using (StreamWriter writer = new StreamWriter(tcpClient.GetStream()))
                {
                    writer.WriteLine(data); // $ Alert
                }
            }
        }

        public void BadInterprocedural(string password)
        {
            BadSink(password);
        }

        private static void BadSink(string data)
        {
            using (TcpClient tcpClient = new TcpClient("remote_host", 1337))
            {
                NetworkStream stream = tcpClient.GetStream();
                byte[] bytes = Encoding.UTF8.GetBytes(data);
                stream.Write(bytes, 0, bytes.Length); // $ Alert
            }
        }

        public void BadSocket(Socket socket, string userPassword)
        {
            socket.Send(Encoding.UTF8.GetBytes(userPassword)); // $ Alert
        }

        public void GoodNonSensitive()
        {
            string data = "Hello World";
            using (TcpClient tcpClient = new TcpClient("remote_host", 1337))
            {
                using (StreamWriter writer = new StreamWriter(tcpClient.GetStream()))
                {
                    writer.WriteLine(data);
                }
            }
        }

        public void GoodSsl()
        {
            string data = ReadSecret();
            using (TcpClient client = new TcpClient("remote_host", 1337))
            {
                using (SslStream sslStream = new SslStream(client.GetStream()))
                {
                    sslStream.Write(Encoding.UTF8.GetBytes(data));
                }
            }
        }
    }
}
