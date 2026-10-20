using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace BabelMethodProbe
{
    public sealed class Receiver
    {
        public int State;
        public Receiver(int state) { State = state; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public int Instance(int value)
        {
            try { State += value; if (value < 0) throw new ArgumentException(); return State * 3; }
            catch (ArgumentException) { return -State; }
            finally { State++; }
        }
    }

    public struct Counter
    {
        public int State;
        [MethodImpl(MethodImplOptions.NoInlining)]
        public int Step(int value) { State += value; return State * 7; }
    }

    public sealed class Box<T>
    {
        private T value;
        public Box(T value) { this.value = value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public T Exchange(T next) { var old = value; value = next; return old; }
    }

    public static class Program
    {
        private static int calls;
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static T Identity<T>(T value) { calls++; return value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int RefValue(ref int value, out int doubled) { value += 7; doubled = value * 2; return value ^ doubled; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static string RefReference(ref string value, out object copy) { copy = value; value += "!"; return value; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void RefThrow(ref int value) { value++; throw new ArgumentException("expected"); }

        public static void Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            var receiver = new Receiver(11);
            foreach (var value in new[] { -2, 0, 3, 19 }) Console.WriteLine("instance:" + receiver.Instance(value) + ":" + receiver.State);
            var counter = new Counter { State = 5 };
            foreach (var value in new[] { -2, 0, 3, 19 }) Console.WriteLine("struct:" + counter.Step(value) + ":" + counter.State);
            Console.WriteLine("generic:" + Identity(23) + ":" + Identity("Ω🥬") + ":" + calls);
            var ints = new Box<int>(17); var strings = new Box<string>("first");
            Console.WriteLine("owner:" + ints.Exchange(41) + ":" + ints.Exchange(-9) + ":" + strings.Exchange("second") + ":" + strings.Exchange(null));
            var number = 4; int doubled;
            Console.WriteLine("ref:" + RefValue(ref number, out doubled) + ":" + number + ":" + doubled);
            var text = "original"; object copy;
            Console.WriteLine("reference:" + RefReference(ref text, out copy) + ":" + text + ":" + copy);
            try { RefThrow(ref number); } catch (ArgumentException) { Console.WriteLine("throw:" + number); }
        }
    }
}
