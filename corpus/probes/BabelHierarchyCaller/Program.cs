using System;
using System.Reflection;
using System.Text;

public enum Choice { First, Second, Third }
public struct Item { public int Id; }
public sealed class Tag { public int Id; }
public static class Program
{
    private static object Value(Type type, int number)
    {
        if (type == typeof(string)) return new string((char)('a' + number), number + 1);
        if (type == typeof(object)) return new object();
        if (type == typeof(Tag)) return new Tag { Id = number };
        if (type == typeof(Item)) return new Item { Id = number };
        if (type == typeof(Choice)) return (Choice)number;
        if (type == typeof(Guid)) return new Guid(number, 0, 0, new byte[8]);
        if (type == typeof(int?)) return number == 0 ? null : (object)number;
        return Convert.ChangeType(number + 1, type);
    }
    private static bool Same(Type type, object actual, object expected) => type.IsValueType ? Equals(actual, expected) : ReferenceEquals(actual, expected);
    public static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        var assembly = Assembly.LoadFile(System.IO.Path.GetFullPath(args[0]));
        var profile = args[1];
        var cases = new[] { typeof(int), typeof(long), typeof(short), typeof(byte), typeof(decimal), typeof(double), typeof(Guid), typeof(Choice), typeof(Item), typeof(int?), typeof(string), typeof(object), typeof(Tag) };
        var count = 0;
        foreach (var type in cases)
        {
            var a = Value(type, 0); var b = Value(type, 1); var c = Value(type, 2);
            var names = profile == "deep" ? new[] { "DeepBox`2", "ChildBox`1" } : new[] { profile == "swapped" ? "SwappedBox`2" : "NestedBox`1" };
            foreach (var name in names)
            {
                var definition = assembly.GetType("BabelHierarchyProbe." + name, true);
                var owner = definition.MakeGenericType(name == "DeepBox`2" ? new[] { typeof(Guid), type } : name == "SwappedBox`2" ? new[] { type, typeof(Guid) } : new[] { type });
                var storage = owner;
                while (storage.GetGenericTypeDefinition().Name != "Storage`1") storage = storage.BaseType;
                var calls = storage.GetField("Calls", BindingFlags.Public | BindingFlags.Static);
                var seed = 1000 + 10 * count;
                calls.SetValue(null, seed);
                var first = Activator.CreateInstance(owner, new[] { a });
                var exchange = owner.GetMethod("Exchange");
                var results = new[] { exchange.Invoke(first, new[] { b }), exchange.Invoke(first, new[] { c }), exchange.Invoke(first, new[] { a }) };
                var second = Activator.CreateInstance(owner, new[] { c });
                var fourth = exchange.Invoke(second, new[] { b });
                if (!Same(type, results[0], a) || !Same(type, results[1], b) || !Same(type, results[2], c) || !Same(type, fourth, c) || (int)calls.GetValue(null) != seed + 4)
                { Console.WriteLine(name + ":" + type.FullName + ":wrong"); return 1; }
                Console.WriteLine(name + ":" + type.FullName + ":ok"); count++;
            }
        }
        Console.WriteLine("cases:" + count);
        return 0;
    }
}
