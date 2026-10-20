using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace BabelProbe
{
    internal static class Program
    {
        private static int calls;

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Encrypted(int value)
        {
            try
            {
                switch (value & 3)
                {
                    case 0: return unchecked(value * 17 + 3);
                    case 1: return 90 / value;
                    case 2: return value ^ 0x55AA;
                    default: throw new ArgumentException("branch exception 🥬");
                }
            }
            catch (ArgumentException) { return -7; }
            finally { calls++; }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static string Strings(int value) => value == 0 ? "Babel string zero 🥬" : "Babel string other Ω";

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static long Values(int value)
        {
            var array = new byte[] { 3, 17, 91, 255, 42, 0, 129, 8 };
            return unchecked(0x1234567890ABCDEFL + value * 7919L + array[value & 7]);
        }

        private static string Resource()
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("BabelProbe.Secret.txt"))
            using (var reader = new StreamReader(stream, Encoding.UTF8)) return reader.ReadToEnd().TrimEnd('\r', '\n');
        }

        public static void Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            foreach (var value in new[] { -4, -1, 0, 1, 2, 3, 8, 17 })
                Console.WriteLine(value + ":" + Encrypted(value) + ":" + Values(value) + ":" + Strings(value));
            Console.WriteLine("calls=" + calls);
            Console.WriteLine(Resource());
        }
    }
}
