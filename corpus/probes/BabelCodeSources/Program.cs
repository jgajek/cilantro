using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace BabelCodeSources;

internal static class Program
{
    private static int calls;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Encrypted(int value)
    {
        try
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));
            return checked(value * 31 + 17);
        }
        catch (ArgumentOutOfRangeException) { return -19; }
        finally { calls++; }
    }

    // Fixed, public test data; unrelated to the Babel evaluation license.
    [Obfuscation(Feature = "msil encryption get password")]
    internal static string GetSourcePassword(string source) => "CILantro benign code-source password 73";

    [Obfuscation(Feature = "msil encryption get stream")]
    internal static Stream GetSourceStream(string source) =>
        File.OpenRead(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, source + ".eil"));

    public static void Main()
    {
        foreach (var value in new[] { -7, 0, 1, 73, 1024 }) Console.WriteLine(value + ":" + Encrypted(value));
        Console.WriteLine("calls=" + calls);
    }
}
