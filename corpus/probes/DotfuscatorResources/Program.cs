using System;
using System.IO;
using System.Reflection;
using System.Resources;

namespace ResourceProbe
{
    // Match the strongly typed accessors produced by the .resx custom tool.
    internal static class Secrets
    {
        private static readonly ResourceManager Manager = new ResourceManager("ResourceProbe.Secrets", typeof(Secrets).Assembly);
        public static string Message => Manager.GetString("Message");
        public static string Unicode => Manager.GetString("Unicode");
        public static string Empty => Manager.GetString("Empty");
        public static string Long => Manager.GetString("Long");
        public static byte[] Bytes => (byte[])Manager.GetObject("Bytes");
    }

    public static class Program
    {
        public static int Main()
        {
            Console.WriteLine("Typed:" + Secrets.Message + Secrets.Unicode + Secrets.Empty + Secrets.Long + Convert.ToBase64String(Secrets.Bytes));
            var resources = new ResourceManager("ResourceProbe.Secrets", Assembly.GetExecutingAssembly());
            foreach (var key in new[] { "Message", "Unicode", "Empty", "Long" })
                Console.WriteLine(key + ":" + resources.GetString(key));
            Console.WriteLine("Bytes:" + Convert.ToBase64String((byte[])resources.GetObject("Bytes")));
            using (var input = Assembly.GetExecutingAssembly().GetManifestResourceStream("ResourceProbe.Raw.txt"))
            using (var reader = new StreamReader(input))
                Console.WriteLine("Raw:" + reader.ReadToEnd().Trim());
            resources.ReleaseAllResources();
            Console.WriteLine("Reload:" + resources.GetString("Message"));
            return 0;
        }
    }
}
