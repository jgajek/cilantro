using System;
using System.Reflection;
using System.Text;
using System.Collections.Generic;

namespace BabelMethodCaller
{
    internal static class Program
    {
        private delegate int Values(ref int value, out int doubled);
        private delegate string References(ref string value, out object copy);
        private delegate void Throws(ref int value);
        private enum Small : sbyte { First = -128, Second = 127 }
        private struct Payload { public long Number; public object Tag; }
        public static void Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            if (args.Length > 1 && args[1] == "generic") { Generic(Assembly.LoadFrom(args[0])); return; }
            var type = Assembly.LoadFrom(args[0]).GetType("BabelMethodProbe.Program", true);
            var values = (Values)Delegate.CreateDelegate(typeof(Values), type.GetMethod("RefValue"));
            var references = (References)Delegate.CreateDelegate(typeof(References), type.GetMethod("RefReference"));
            var throws = (Throws)Delegate.CreateDelegate(typeof(Throws), type.GetMethod("RefThrow"));
            var value = 4; int doubled;
            Console.WriteLine("normal:" + values(ref value, out doubled) + ":" + value + ":" + doubled);
            value = 4;
            Console.WriteLine("alias:" + values(ref value, out value) + ":" + value);
            var text = "original"; object copy;
            Console.WriteLine("reference:" + references(ref text, out copy) + ":" + text + ":" + copy);
            value = 11;
            try { throws(ref value); } catch (ArgumentException) { Console.WriteLine("throw:" + value); }
        }

        private static void Generic(Assembly assembly)
        {
            var box = assembly.GetType("BabelMethodProbe.Box`1", true);
            Probe(box, "int", -17, int.MaxValue);
            Probe(box, "long", long.MinValue, long.MaxValue);
            Probe(box, "byte", (byte)0, byte.MaxValue);
            Probe(box, "bool", false, true);
            Probe(box, "char", '\uD800', '\uFFFF');
            Probe(box, "decimal", decimal.MinValue, decimal.MaxValue);
            Probe(box, "guid", Guid.Empty, new Guid("11223344-5566-7788-99aa-bbccddeeff00"));
            Probe(box, "enum", Small.First, Small.Second);
            Probe(box, "struct", new Payload { Number = long.MinValue, Tag = new object() }, new Payload { Number = long.MaxValue, Tag = new object() });
            Probe<int?>(box, "nullable", null, 41);
            Probe<string>(box, "string", null, "second");
            Probe<object>(box, "object", new object(), new object());
            Probe(box, "array", new[] { 1, 2 }, new[] { 3, 4 });
            Probe(box, "list", new List<int> { 1 }, new List<int> { 2 });
            Probe(box, "nested", new Dictionary<string, List<int[]>>(), new Dictionary<string, List<int[]>>());
        }

        private static void Probe<T>(Type definition, string name, T first, T second)
        {
            try
            {
                var closed = definition.MakeGenericType(typeof(T));
                var instance = Activator.CreateInstance(closed, new object[] { first });
                var exchange = closed.GetMethod("Exchange");
                var a = exchange.Invoke(instance, new object[] { second });
                var b = exchange.Invoke(instance, new object[] { first });
                var c = exchange.Invoke(instance, new object[] { second });
                var equal = EqualityComparer<T>.Default;
                var ok = equal.Equals((T)a, first) && equal.Equals((T)b, second) && equal.Equals((T)c, first);
                if (!typeof(T).IsValueType) ok &= ReferenceEquals(a, first) && ReferenceEquals(b, second) && ReferenceEquals(c, first);
                Console.WriteLine(name + ":" + (ok ? "ok" : "wrong"));
            }
            catch (TargetInvocationException exception) { Console.WriteLine(name + ":exception:" + exception.InnerException.GetType().Name); }
        }
    }
}
