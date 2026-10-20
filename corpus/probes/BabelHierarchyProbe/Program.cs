using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace BabelHierarchyProbe
{
    public class Storage<T>
    {
        protected T value;
        public static int Calls;
        static Storage() { Calls = 20; }
        protected Storage(T value) { this.value = value; }
    }
    public class Middle<TUnused, TValue> : Storage<TValue>
    {
        protected Middle(TValue value) : base(value) { }
    }
    public class DeepBox<TUnused, TValue> : Middle<TUnused, TValue>
    {
        public DeepBox(TValue value) : base(value) { }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public TValue Exchange(TValue next) { Calls++; var old = value; value = next; return old; }
    }
    public sealed class ChildBox<T> : DeepBox<Guid, T>
    {
        public ChildBox(T value) : base(value) { }
    }
    public sealed class SwappedBox<TValue, TUnused> : Middle<TUnused, TValue>
    {
        public SwappedBox(TValue value) : base(value) { }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public TValue Exchange(TValue next) { Calls++; var old = value; value = next; return old; }
    }
    public sealed class NestedBox<T> : Storage<List<T>>
    {
        public NestedBox(T value) : base(new List<T> { value }) { }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Exchange(T next) { Calls++; var old = value[0]; value = new List<T> { next }; return old; }
    }
    public static class Program
    {
        private static void Check(string label, Func<string> run)
        {
            try { Console.WriteLine(label + ":" + run()); }
            catch (Exception exception) { Console.WriteLine(label + ":exception:" + exception.GetType().Name); }
        }
        public static void Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            Check("deep-int", () => { var box = new DeepBox<Guid, int>(13); return box.Exchange(31) + ":" + box.Exchange(-7); });
            Check("deep-string", () => { var box = new DeepBox<Guid, string>("first"); return box.Exchange("Ω🥬") + ":" + box.Exchange(null); });
            Check("child", () => { var box = new ChildBox<int>(17); return box.Exchange(37) + ":" + Storage<int>.Calls; });
            Check("swapped-int", () => { var box = new SwappedBox<int, Guid>(19); return box.Exchange(41) + ":" + Storage<int>.Calls; });
            Check("swapped-string", () => { var box = new SwappedBox<string, Guid>("before"); return box.Exchange("after") + ":" + Storage<string>.Calls; });
            Check("nested-int", () => { var box = new NestedBox<int>(23); return box.Exchange(43) + ":" + Storage<List<int>>.Calls; });
            Check("nested-string", () => { var box = new NestedBox<string>("old"); return box.Exchange("new") + ":" + Storage<List<string>>.Calls; });
        }
    }
}
