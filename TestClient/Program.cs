using AnsiDukptKey;

namespace TestClient
{
    class Program
    {
        static void Main(string[] args)
        {
            var dec = new AnsiProvider();
            string bdk = "[YOUR BDK]";
            string sample = "[YOUR ENCRYPTED STRING]";
            string ksn = "YOUR KSN";

            dec.Decrypt(ksn, bdk, sample);
        }
    }
}
