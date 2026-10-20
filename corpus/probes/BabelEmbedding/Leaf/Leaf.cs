using System.IO;
using System.Runtime.CompilerServices;

namespace BabelEmbedLeaf
{
    public static class Leaf
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Transform(int value) => unchecked(value * 7 - 11);
        public static string Resource()
        {
            using (var stream = typeof(Leaf).Assembly.GetManifestResourceStream("Leaf.Payload"))
            using (var reader = new StreamReader(stream)) return reader.ReadToEnd().TrimEnd('\r', '\n');
        }
    }
}
