using System.IO;
using System.Runtime.CompilerServices;

namespace BabelEmbedLibrary
{
    public static class Library
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Combine(int value) => BabelEmbedLeaf.Leaf.Transform(value) + 42;
        public static string Resource()
        {
            using (var stream = typeof(Library).Assembly.GetManifestResourceStream("Library.Payload"))
            using (var reader = new StreamReader(stream)) return reader.ReadToEnd().TrimEnd('\r', '\n');
        }
    }
}
