using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureProbe
{
    public static class Program
    {
        public static unsafe int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            Console.WriteLine(SignatureCases.Cases.Plain());
            Console.WriteLine(SignatureCases.Cases.Generic(3));
            Console.WriteLine(SignatureCases.Cases.Generic("argument"));
            Console.WriteLine(SignatureCases.Cases.GenericReturn(13));
            Console.WriteLine(SignatureCases.Cases.GenericReturn("return argument"));
            Console.WriteLine(SignatureCases.Cases.Collection(new List<int>()));
            Console.WriteLine(SignatureCases.Cases.Nested(default(SignatureCases.Box<int>.Value)));
            Console.WriteLine(SignatureCases.Cases.Vector(new int[1]));
            Console.WriteLine(SignatureCases.Cases.Jagged(new int[1][]));
            Console.WriteLine(SignatureCases.Cases.Matrix(new int[1, 1]));
            int value = 5; string output;
            Console.WriteLine(SignatureCases.Cases.References(ref value, out output));
            Console.WriteLine(output); Console.WriteLine(value);
            Console.WriteLine(SignatureCases.Cases.Enumeration(SignatureCases.Mode.One));
            Console.WriteLine(SignatureCases.Cases.Pointer(&value));
#if NET8_0_OR_GREATER
            Console.WriteLine(SignatureCases.Cases.FunctionPointer(&IdentityNumber));
#endif
            SignatureCases.Cases.ReferenceReturn(ref value) = 29;
            Console.WriteLine(value);
            Console.WriteLine(SignatureCases.Cases.ArrayReturn()[0]);
            Console.WriteLine(SignatureCases.Cases.Méthode());
            Console.WriteLine(new SignatureCases.Box<int>().Describe(4));
            Console.WriteLine(new SignatureCases.Box<string>.Inner<int>().Describe("argument", 7));
            new SignatureCases.Constructor();
            return 0;
        }
        private static int IdentityNumber(int value) => value;
    }
}

namespace SignatureCases
{
    public enum Mode { One }
    public static class Cases
    {
        public static string Plain() => "SIG_PLAIN_Ω🥬";
        public static string Generic<T>(T value) => "SIG_GENERIC";
        public static T GenericReturn<T>(T value) { Console.WriteLine("SIG_GENERIC_RETURN"); return value; }
        public static string Collection(List<int> values) => "SIG_COLLECTION";
        public static string Nested(Box<int>.Value value) => "SIG_NESTED";
        public static string Vector(int[] values) => "SIG_VECTOR";
        public static string Jagged(int[][] values) => "SIG_JAGGED";
        public static string Matrix(int[,] values) => "SIG_MATRIX";
        public static string References(ref int value, out string output)
        {
            value++; output = "SIG_OUT"; return "SIG_REF";
        }
        public static string Enumeration(Mode value) => "SIG_ENUM";
        public static unsafe string Pointer(int* value) => "SIG_POINTER";
#if NET8_0_OR_GREATER
        public static unsafe string FunctionPointer(delegate*<int, int> callback) => "SIG_FUNCTION_POINTER";
#endif
        public static ref int ReferenceReturn(ref int value)
        {
            Console.WriteLine("SIG_RETURN_REF"); return ref value;
        }
        public static int[] ArrayReturn()
        {
            Console.WriteLine("SIG_RETURN_ARRAY"); return new[] { 37 };
        }
        public static string Méthode() => "SIG_UNICODE_NAME";
    }
    public class Box<T>
    {
        public struct Value { }
        public string Describe(T value) => "SIG_GENERIC_OWNER";
        public class Inner<U>
        {
            public string Describe(T first, U second) => "SIG_NESTED_GENERIC_OWNER";
        }
    }
    public sealed class Constructor
    {
        static Constructor() { Console.WriteLine("SIG_STATIC_CONSTRUCTOR"); }
        public Constructor() { Console.WriteLine("SIG_CONSTRUCTOR"); }
    }
}
