using System;
using System.Text;
using HyperDES.LUtils;

namespace HyperDES
{
    internal class Program
    {
        static void Main(String[] args)
        {

            const String s = "The quick brown fox jumps over the lazy dog";
            var p = UCryptoUtils.GenerateHyperDesKey("password");
            var d = Encoding.UTF8.GetBytes(s);
            var c = UCryptoUtils.EncryptHyperDes(d, p);
            var t = UCryptoUtils.DecryptHyperDes(c, p);
            var e = Encoding.UTF8.GetString(t);
            Console.WriteLine("CipherText");
            Console.WriteLine(UBinaryUtils.Expand(c, false));
            Console.WriteLine("PlainText");
            Console.WriteLine(e);
            Console.WriteLine();

            Console.ReadKey();
            Environment.Exit(0);
        }
    }
}
