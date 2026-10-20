using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace BabelGenericProbe
{
    public class OpenBox<T>
    {
        private T value;
        public OpenBox(T value) { this.value = value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Exchange(T next) { var old = value; value = next; return old; }
    }
    public sealed class DerivedBox<T> : OpenBox<T>
    {
        public DerivedBox(T value) : base(value) { }
    }
    public sealed class StatefulBox<T>
    {
        public static int Calls;
        private T value;
        static StatefulBox() { Calls = 10; Console.WriteLine("cctor:" + typeof(T).Name); }
        public StatefulBox(T value) { this.value = value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Exchange(T next) { Calls++; var old = value; value = next; return old; }
    }
    public sealed class ClassBox<T> where T : class
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Choose(T left, T right) { return left ?? right; }
    }
    public sealed class StructBox<T> where T : struct
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Choose(T left, T right) { return left.Equals(default(T)) ? right : left; }
    }
    public sealed class NewBox<T> where T : new()
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Create() { return new T(); }
    }
    public sealed class StaticBox<T>
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static T Choose(T left, T right) { return left; }
    }
    public sealed class Item { public override string ToString() { return "item"; } }
    public static class Program
    {
        private static void Check(string label, Func<string> action)
        {
            try { Console.WriteLine(label + ":" + action()); }
            catch (Exception exception) { Console.WriteLine(label + ":exception:" + exception.GetType().Name); }
        }
        public static void Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            Check("open-int", () => { var box = new OpenBox<int>(17); return box.Exchange(41) + ":" + box.Exchange(-9); });
            Check("open-string", () => { var box = new OpenBox<string>("first"); return box.Exchange("Ω🥬") + ":" + box.Exchange(null); });
            Check("derived-int", () => { OpenBox<int> box = new DerivedBox<int>(23); return box.Exchange(51) + ":" + box.Exchange(0); });
            Check("state-int", () => { var box = new StatefulBox<int>(5); return box.Exchange(7) + ":" + StatefulBox<int>.Calls; });
            Check("state-string", () => { var box = new StatefulBox<string>("before"); return box.Exchange("after") + ":" + StatefulBox<string>.Calls; });
            Check("class", () => new ClassBox<string>().Choose(null, "fallback"));
            Check("struct", () => new StructBox<int>().Choose(0, 37).ToString());
            Check("new", () => new NewBox<Item>().Create().ToString());
            Check("static-int", () => StaticBox<int>.Choose(19, -1).ToString());
            Check("static-string", () => StaticBox<string>.Choose("left", "right"));
        }
    }
}
