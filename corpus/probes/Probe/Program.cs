using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace Probe
{
    // Ground truth for the recovery measurement. Every string literal below carries a
    // PROBE_STR_nn marker so a run's string recovery can be scored by counting markers in
    // the cleaned output, and every method name is distinctive so renaming can be scored too.
    public static class Program
    {
        public const int ExpectedStringMarkers = 12;

        public static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--recovery-self-test")
            {
                foreach (var input in new[] { int.MinValue, -33, -1, 0, 1, 31, int.MaxValue })
                    Console.WriteLine("branch " + input + " " + RecoveryGroundTruth.Branch(input));
                foreach (var divisor in new[] { 0, 1, -3 })
                {
                    var bytes = new byte[] { 0, 1, 127, 255 };
                    var result = RecoveryGroundTruth.Mutate(bytes, divisor);
                    Console.WriteLine("mutate " + divisor + " " + result + " " + Convert.ToBase64String(bytes));
                }
                return 0;
            }
            Console.WriteLine("PROBE_STR_01 probe entry point");
            Console.WriteLine(DescribeCampaign());
            Console.WriteLine(ClassifyInput(args.Length));
            Console.WriteLine(ComputeChecksum("PROBE_STR_02 checksum input"));
            Console.WriteLine(ReadEmbeddedSecret());
            Console.WriteLine(TransformBuffer(Encoding.UTF8.GetBytes("PROBE_STR_03 buffer")));
            return 0;
        }

        // Straight-line string carrier: scores string encryption on its own.
        public static string DescribeCampaign() =>
            "PROBE_STR_04 https://probe.invalid:8443/gate" +
            "PROBE_STR_05 campaign=aabbccdd" +
            "PROBE_STR_06 blacklist=sbiedll.dll,x64dbg";

        // Branch carrier: scores control-flow obfuscation and constant-predicate folding.
        public static string ClassifyInput(int count)
        {
            if (count < 0)
                return "PROBE_STR_07 negative";
            if (count == 0)
                return "PROBE_STR_08 empty";

            var builder = new StringBuilder();
            for (var index = 0; index < count; index++)
            {
                if (index % 3 == 0)
                    builder.Append("PROBE_STR_09 third;");
                else if (index % 2 == 0)
                    builder.Append("even;");
                else
                    builder.Append("odd;");
            }

            return builder.ToString();
        }

        // Arithmetic carrier: the method most worth virtualizing, and cheap to verify
        // because the expected value can be recomputed from the unprotected build.
        public static uint ComputeChecksum(string text)
        {
            var hash = 2166136261u;
            foreach (var character in text)
            {
                hash ^= character;
                hash *= 16777619u;
                hash = (hash << 7) | (hash >> 25);
            }

            return hash;
        }

        // Resource carrier: scores resource encryption and restoration.
        public static string ReadEmbeddedSecret()
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream("Probe.Secret.txt");
            if (stream is null)
                return "PROBE_STR_10 resource missing";

            using var reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd().Trim();
        }

        // Loop plus byte arithmetic: exercises array handling in the interpreter.
        public static string TransformBuffer(byte[] buffer)
        {
            if (buffer is null || buffer.Length == 0)
                return "PROBE_STR_11 nothing to transform";

            var output = new byte[buffer.Length];
            for (var index = 0; index < buffer.Length; index++)
                output[index] = (byte)(buffer[index] ^ 0x5A);

            return "PROBE_STR_12 " + Convert.ToBase64String(output);
        }
    }
}
