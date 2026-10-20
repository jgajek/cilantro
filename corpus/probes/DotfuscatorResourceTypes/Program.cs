using System;
using System.Globalization;
using System.Resources;

namespace ResourceTypesProbe
{
    internal static class Secrets
    {
        private static readonly ResourceManager Manager = new ResourceManager("ResourceTypesProbe.Secrets", typeof(Secrets).Assembly);
        public static string Message => Manager.GetString("Message");
        public static object Get(string name) => Manager.GetObject(name);
    }

    public static class Program
    {
        public static int Main()
        {
            Console.WriteLine(Secrets.Message);
            foreach (var name in new[] { "Integer", "Boolean", "Decimal", "Double", "Character", "Long", "Bytes" })
            {
                var value = Secrets.Get(name);
                Console.WriteLine(name + ":" + value.GetType().FullName + ":" +
                    (value is byte[] bytes ? Convert.ToBase64String(bytes) : Convert.ToString(value, CultureInfo.InvariantCulture)));
            }
            return 0;
        }
    }
}
