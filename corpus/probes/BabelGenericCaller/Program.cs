using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.IO;

namespace BabelGenericCaller
{
    public enum Choice : long { Zero, Other = 0x123456789 }
    public struct Pair { public int Number; public long Wide; }
    public sealed class Fresh
    {
        public static int Calls;
        public Fresh() { Calls++; }
    }
    public sealed class Throwing
    {
        public static int Calls;
        public Throwing() { Calls++; throw new InvalidOperationException("expected constructor failure"); }
    }
    public sealed class InitializationFailureTag { }
    public static class Program
    {
        private static bool failed;
        private static int stateCase;
        private static readonly System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<FieldInfo, int>> states =
            new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<FieldInfo, int>>();
        private sealed class FailingWriter : StringWriter
        {
            public int Calls;
            public override void WriteLine(string value) { Calls++; throw new InvalidOperationException("expected initializer failure"); }
        }
        private static void CheckState<T>(Assembly target, T first, T second, T third)
        {
            try
            {
                var type = target.GetType("BabelGenericProbe.StatefulBox`1", true).MakeGenericType(typeof(T));
                var receiver = Activator.CreateInstance(type, new object[] { first }); var field = type.GetField("Calls");
                var match = (int)field.GetValue(null) == 10; var seed = 1000 + ++stateCase * 17; field.SetValue(null, seed);
                var method = type.GetMethod("Exchange");
                var a = (T)method.Invoke(receiver, new object[] { second }); var b = (T)method.Invoke(receiver, new object[] { third });
                var c = (T)method.Invoke(receiver, new object[] { default(T) });
                match &= typeof(T).IsValueType ? object.Equals(a, first) && object.Equals(b, second) && object.Equals(c, third) :
                    object.ReferenceEquals(a, first) && object.ReferenceEquals(b, second) && object.ReferenceEquals(c, third);
                match &= (int)field.GetValue(null) == seed + 3;
                var another = Activator.CreateInstance(type, new object[] { third }); match &= (int)field.GetValue(null) == seed + 3;
                method.Invoke(another, new object[] { first }); match &= (int)field.GetValue(null) == seed + 4;
                states.Add(new System.Collections.Generic.KeyValuePair<FieldInfo, int>(field, seed + 4));
                Console.WriteLine(typeof(T).Name + ":" + (match ? "ok" : "wrong")); failed |= !match;
            }
            catch (Exception exception)
            {
                while (exception is TargetInvocationException && exception.InnerException != null) exception = exception.InnerException;
                Console.WriteLine(typeof(T).Name + ":exception:" + exception.GetType().Name); failed = true;
            }
        }
        private static void CheckInitializationFailure(Assembly target)
        {
            var original = Console.Out; var writer = new FailingWriter(); var match = true;
            try
            {
                Console.SetOut(writer);
                var type = target.GetType("BabelGenericProbe.StatefulBox`1", true).MakeGenericType(typeof(InitializationFailureTag));
                for (var attempt = 0; attempt < 2; attempt++)
                {
                    try { Activator.CreateInstance(type, new object[] { null }); match = false; }
                    catch (Exception exception)
                    {
                        while (exception is TargetInvocationException && exception.InnerException != null) exception = exception.InnerException;
                        match &= exception is TypeInitializationException && exception.InnerException is InvalidOperationException &&
                            exception.InnerException.Message == "expected initializer failure";
                    }
                }
                match &= writer.Calls == 1;
            }
            finally { Console.SetOut(original); writer.Dispose(); }
            Console.WriteLine("init-failure:" + (match ? "ok" : "wrong")); failed |= !match;
        }
        private static Type reorderedChild;
        private static Type ReorderedChild(Assembly target)
        {
            if (reorderedChild != null) return reorderedChild;
            var assembly = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("BabelGenericCaller.Children"), AssemblyBuilderAccess.Run);
            var builder = assembly.DefineDynamicModule("Children").DefineType("ReorderedChild`2", TypeAttributes.Public | TypeAttributes.Class);
            var parameters = builder.DefineGenericParameters("TUnused", "TStored");
            var definition = target.GetType("BabelGenericProbe.OpenBox`1", true);
            var parent = definition.MakeGenericType(parameters[1]); builder.SetParent(parent);
            builder.DefineField("Extra", typeof(long), FieldAttributes.Public);
            builder.DefineField("value", typeof(string), FieldAttributes.Public);
            var constructor = builder.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, new Type[] { parameters[1] });
            var il = constructor.GetILGenerator(); il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Call, TypeBuilder.GetConstructor(parent, definition.GetConstructors()[0])); il.Emit(OpCodes.Ret);
            var describe = builder.DefineMethod("ToString", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig, typeof(string), Type.EmptyTypes);
            il = describe.GetILGenerator(); il.Emit(OpCodes.Ldstr, "derived"); il.Emit(OpCodes.Ret);
            builder.DefineMethodOverride(describe, typeof(object).GetMethod("ToString"));
            reorderedChild = builder.CreateType(); return reorderedChild;
        }
        private static void CheckInherited<T>(Assembly target, T first, T second, T third)
        {
            foreach (var kind in new[] { "base", "derived", "reordered" })
            {
                try
                {
                    var type = kind == "reordered" ? ReorderedChild(target).MakeGenericType(typeof(decimal), typeof(T)) :
                        target.GetType(kind == "base" ? "BabelGenericProbe.OpenBox`1" : "BabelGenericProbe.DerivedBox`1", true).MakeGenericType(typeof(T));
                    var receiver = Activator.CreateInstance(type, new object[] { first });
                    if (kind == "reordered") { type.GetField("Extra").SetValue(receiver, 77L); type.GetField("value").SetValue(receiver, "shadow"); }
                    var method = type.GetMethod("Exchange");
                    var before = (T)method.Invoke(receiver, new object[] { second });
                    var middle = (T)method.Invoke(receiver, new object[] { third });
                    var last = (T)method.Invoke(receiver, new object[] { default(T) });
                    var match = typeof(T).IsValueType ? object.Equals(before, first) && object.Equals(middle, second) && object.Equals(last, third) :
                        object.ReferenceEquals(before, first) && object.ReferenceEquals(middle, second) && object.ReferenceEquals(last, third);
                    if (kind == "reordered") match &= (long)type.GetField("Extra").GetValue(receiver) == 77 &&
                        (string)type.GetField("value").GetValue(receiver) == "shadow" && receiver.ToString() == "derived";
                    Console.WriteLine(typeof(T).Name + ":" + kind + ":" + (match ? "ok" : "wrong")); failed |= !match;
                }
                catch (Exception exception)
                {
                    while (exception is TargetInvocationException && exception.InnerException != null) exception = exception.InnerException;
                    Console.WriteLine(typeof(T).Name + ":" + kind + ":exception:" + exception.GetType().Name); failed = true;
                }
            }
        }
        private static void CheckStatic<T>(Assembly target, T left, T right)
        {
            try
            {
                var owner = target.GetType("BabelGenericProbe.StaticBox`1", true).MakeGenericType(typeof(T));
                var method = owner.GetMethod("Choose");
                var first = (T)method.Invoke(null, new object[] { left, right });
                var second = (T)method.Invoke(null, new object[] { right, left });
                var empty = (T)method.Invoke(null, new object[] { default(T), left });
                var match = typeof(T).IsValueType ? object.Equals(first, left) && object.Equals(second, right) && object.Equals(empty, default(T)) :
                    object.ReferenceEquals(first, left) && object.ReferenceEquals(second, right) && object.ReferenceEquals(empty, null);
                Console.WriteLine(typeof(T).Name + ":" + (match ? "ok" : "wrong")); failed |= !match;
            }
            catch (Exception exception)
            {
                while (exception is TargetInvocationException && exception.InnerException != null) exception = exception.InnerException;
                Console.WriteLine(typeof(T).Name + ":exception:" + exception.GetType().Name); failed = true;
            }
        }
        private static void CheckNew<T>(Assembly target) where T : new()
        {
            try
            {
                var owner = target.GetType("BabelGenericProbe.NewBox`1", true).MakeGenericType(typeof(T));
                var receiver = Activator.CreateInstance(owner); var method = owner.GetMethod("Create");
                Fresh.Calls = 0; Throwing.Calls = 0;
                var first = (T)method.Invoke(receiver, null); var second = (T)method.Invoke(receiver, null);
                var match = typeof(T).IsValueType ? object.Equals(first, default(T)) && object.Equals(second, default(T)) :
                    !object.ReferenceEquals(first, second) && Fresh.Calls == 2;
                Console.WriteLine(typeof(T).Name + ":" + (match ? "ok" : "wrong")); failed |= !match;
            }
            catch (Exception exception)
            {
                var chain = exception.GetType().Name;
                while (exception is TargetInvocationException && exception.InnerException != null)
                { exception = exception.InnerException; chain += ">" + exception.GetType().Name; }
                Console.Error.WriteLine(typeof(T).Name + ":chain:" + chain);
                var expected = typeof(T) == typeof(Throwing) && exception is InvalidOperationException && Throwing.Calls == 1;
                Console.WriteLine(typeof(T).Name + ":" + (expected ? "ok" : "exception:" + exception.GetType().Name)); failed |= !expected;
            }
        }
        private static void Check<T>(Assembly target, T left, T right) where T : struct
        {
            try
            {
                var owner = target.GetType("BabelGenericProbe.StructBox`1", true).MakeGenericType(typeof(T));
                var receiver = Activator.CreateInstance(owner);
                var method = owner.GetMethod("Choose");
                var zero = (T)method.Invoke(receiver, new object[] { default(T), right });
                var nonzero = (T)method.Invoke(receiver, new object[] { left, right });
                var expected = left.Equals(default(T)) ? right : left;
                var match = zero.Equals(right) && nonzero.Equals(expected);
                Console.WriteLine(typeof(T).Name + ":" + (match ? "ok" : "wrong"));
                failed |= !match;
            }
            catch (Exception exception)
            {
                while (exception is TargetInvocationException && exception.InnerException != null) exception = exception.InnerException;
                Console.WriteLine(typeof(T).Name + ":exception:" + exception.GetType().Name);
                failed = true;
            }
        }
        public static int Main(string[] arguments)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            var target = Assembly.LoadFrom(arguments[0]);
            if (arguments.Length > 1 && arguments[1] == "state")
            {
                CheckState(target, 17, -3, 43); CheckState(target, 0x123456789L, -7L, 91L); CheckState(target, 1.25m, -9.5m, 3m);
                CheckState(target, new Guid("cba76543-3210-4567-89ab-0123456789ab"), Guid.Empty, new Guid("12345678-89ab-4321-8abc-cba987654321"));
                CheckState(target, Choice.Other, (Choice)7, Choice.Zero); CheckState(target, new Pair { Number = 5 }, new Pair { Wide = -9 }, new Pair());
                CheckState<int?>(target, 23, null, -7); CheckState(target, new string('Ω', 3), new string('a', 4), null);
                CheckState(target, new object(), new object(), null); CheckState(target, new[] { 1, 2 }, new[] { -3 }, null);
                CheckState(target, new System.Collections.Generic.List<int> { 1 }, new System.Collections.Generic.List<int> { -3 }, null);
                CheckState(target, new System.Collections.Generic.List<System.Collections.Generic.List<string>>(), new System.Collections.Generic.List<System.Collections.Generic.List<string>>(), null);
                var isolated = true; foreach (var state in states) isolated &= (int)state.Key.GetValue(null) == state.Value;
                Console.WriteLine("isolation:" + (isolated ? "ok" : "wrong")); failed |= !isolated;
                CheckInitializationFailure(target); return failed ? 1 : 0;
            }
            if (arguments.Length > 1 && arguments[1] == "inherit")
            {
                CheckInherited(target, 17, -3, 43); CheckInherited(target, 0x123456789L, -7L, 91L); CheckInherited(target, 1.25m, -9.5m, 3m);
                CheckInherited(target, new Guid("cba76543-3210-4567-89ab-0123456789ab"), Guid.Empty, new Guid("12345678-89ab-4321-8abc-cba987654321"));
                CheckInherited(target, Choice.Other, (Choice)7, Choice.Zero); CheckInherited(target, new Pair { Number = 5 }, new Pair { Wide = -9 }, new Pair());
                CheckInherited<int?>(target, 23, null, -7); CheckInherited(target, new string('Ω', 3), new string('a', 4), null);
                CheckInherited(target, new object(), new object(), null); CheckInherited(target, new[] { 1, 2 }, new[] { -3 }, null);
                CheckInherited(target, new System.Collections.Generic.List<int> { 1 }, new System.Collections.Generic.List<int> { -3 }, null);
                CheckInherited(target, new System.Collections.Generic.List<System.Collections.Generic.List<string>>(), new System.Collections.Generic.List<System.Collections.Generic.List<string>>(), null);
                return failed ? 1 : 0;
            }
            if (arguments.Length > 1 && arguments[1] == "static")
            {
                CheckStatic(target, 17, -3); CheckStatic(target, 0x123456789L, -7L); CheckStatic(target, 1.25m, -9.5m);
                CheckStatic(target, new Guid("cba76543-3210-4567-89ab-0123456789ab"), Guid.Empty);
                CheckStatic(target, Choice.Other, (Choice)7); CheckStatic(target, new Pair { Number = 5 }, new Pair { Wide = -9 });
                CheckStatic<int?>(target, 23, null); CheckStatic(target, new string('Ω', 3), new string('a', 4));
                CheckStatic(target, new object(), new object()); CheckStatic(target, new[] { 1, 2 }, new[] { -3 });
                CheckStatic(target, new System.Collections.Generic.List<int> { 1 }, new System.Collections.Generic.List<int> { -3 });
                CheckStatic(target, new System.Collections.Generic.List<System.Collections.Generic.List<string>>(), new System.Collections.Generic.List<System.Collections.Generic.List<string>>());
                return failed ? 1 : 0;
            }
            if (arguments.Length > 1 && arguments[1] == "new")
            {
                CheckNew<int>(target); CheckNew<long>(target); CheckNew<decimal>(target); CheckNew<Guid>(target);
                CheckNew<Choice>(target); CheckNew<Pair>(target); CheckNew<int?>(target); CheckNew<Fresh>(target); CheckNew<Throwing>(target);
                return failed ? 1 : 0;
            }
            Check(target, 17, 43);
            Check(target, 0x123456789L, -3L);
            Check(target, true, true);
            Check(target, 'Ω', 'a');
            Check(target, 17.25m, -9.5m);
            Check(target, new Guid("cba76543-3210-4567-89ab-0123456789ab"), new Guid("12345678-89ab-4321-8abc-cba987654321"));
            Check(target, new DateTime(2024, 2, 29), new DateTime(2030, 1, 1));
            Check(target, Choice.Other, (Choice)7);
            Check(target, new Pair { Number = 5, Wide = 0x123456789 }, new Pair { Number = -3, Wide = -9 });
            return failed ? 1 : 0;
        }
    }
}
