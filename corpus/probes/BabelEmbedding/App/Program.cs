using System;
using System.Text;

namespace BabelEmbedProbe
{
    public static class Program
    {
        public static int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            Console.WriteLine("EMBED_PROBE " + BabelEmbedLibrary.Library.Combine(6) + " " + BabelEmbedLeaf.Leaf.Transform(-3));
            Console.WriteLine(BabelEmbedLibrary.Library.Resource());
            Console.WriteLine(BabelEmbedLeaf.Leaf.Resource());
            Console.WriteLine(typeof(BabelEmbedLibrary.Library).Assembly.GetName().Name + ":" + typeof(BabelEmbedLibrary.Library).Assembly.GetName().Version);
            Console.WriteLine(typeof(BabelEmbedLeaf.Leaf).Assembly.GetName().Name + ":" + typeof(BabelEmbedLeaf.Leaf).Assembly.GetName().Version);
            return 0;
        }
    }
}
