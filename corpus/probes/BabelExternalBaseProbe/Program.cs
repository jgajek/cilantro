using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace BabelExternalBaseProbe
{
    public class ErrorBox<T> : Exception
    {
        private T value;
        public ErrorBox(T value) : base("external exception base") { this.value = value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Exchange(T next) { var old = value; value = next; return old; }
    }
    public sealed class ErrorChild<T> : ErrorBox<T>
    {
        public ErrorChild(T value) : base(value) { }
    }
    public class ListBox<T> : List<T>
    {
        public ListBox(T value) { Add(value); }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Exchange(T next) { var old = this[0]; this[0] = next; return old; }
    }
    public sealed class ListChild<T> : ListBox<T>
    {
        public ListChild(T value) : base(value) { }
    }
    public sealed class PlainError : Exception
    {
        private int value;
        public PlainError(int value) : base("plain external exception base") { this.value = value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public int Exchange(int next) { var old = value; value = next; return old; }
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
            Check("error-int", () => { var box = new ErrorBox<int>(13); return box.Exchange(31) + ":" + box.Exchange(-7) + ":" + box.Message; });
            Check("error-string", () => { var box = new ErrorBox<string>("first"); return box.Exchange("Ω🥬") + ":" + box.Exchange(null) + ":" + box.Message; });
            Check("error-child", () => { var box = new ErrorChild<int>(17); return box.Exchange(37) + ":" + box.Exchange(47) + ":" + box.Message; });
            Check("list-int", () => { var box = new ListBox<int>(19); return box.Exchange(41) + ":" + box.Exchange(-5) + ":" + box.Count; });
            Check("list-string", () => { var box = new ListBox<string>("before"); return box.Exchange("Ω🥬") + ":" + box.Exchange(null) + ":" + box.Count; });
            Check("list-child", () => { var box = new ListChild<int>(23); return box.Exchange(43) + ":" + box.Exchange(53) + ":" + box.Count; });
            Check("plain-error", () => { var box = new PlainError(29); return box.Exchange(59) + ":" + box.Exchange(61) + ":" + box.Message; });
        }
    }
}
