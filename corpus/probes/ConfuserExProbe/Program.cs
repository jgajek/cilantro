using System;
using System.IO;
using System.Reflection;

namespace ConfuserExProbe
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            var value = args.Length == 0 ? 7 : int.Parse(args[0]);
            var text = Describe(value);
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("ConfuserExProbe.Secret.txt"))
            using (var reader = new StreamReader(stream))
                Console.WriteLine(text + ":" + reader.ReadToEnd().Trim());
            return text.Length % 17;
        }

        public static string Describe(int value)
        {
            var word = value % 2 == 0 ? "even" : "odd";
            var score = 0;
            for (var i = 0; i < 4; i++)
                score += value ^ i;
            return string.Concat("probe-", word, "-", score.ToString());
        }
    }
}
