using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Linq.Expressions;

namespace Cilantro.Core.Analysis;

/// <summary>Tracks a default serializer's object graph through a restricted set of
/// framework operations. The caller must separately establish the default framework
/// type-provider environment. This analysis never rewrites dynamic calls.</summary>
internal static class JsonReceiverFlow
{
    [Flags] private enum Value { None = 0, Unknown = 1, Null = 2, Graph = 4, Enumerator = 8, String = 16, Scalar = 32, Type = 64 }
    internal sealed record Result(bool Closed, IReadOnlyList<Instruction> MemberBinders, IReadOnlyList<string> Refusals);
    internal static Result Analyze(ModuleDef module, MethodDef method, IReadOnlySet<TypeDef> exposed)
    {
        var sources = DefaultJsonSerializerCalls.Find(method);
        if (sources.Count == 0) return new(false, [], ["No closed default serializer instance."]);
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return new(false, [], ["Unknown evaluation stack."]);
        var decoder = new CSharpBinderArguments(method);
        var sites = ClosedDynamicSiteStorage.Find(module, method, exposed);
        var bindings = sites.SelectMany(s => s.Invocations.Select(i => (Instruction: i, Site: s, Descriptor: decoder.Read(s.Binder))))
            .Where(p => p.Descriptor is not null).ToDictionary(p => p.Instruction);
        var values = new Dictionary<Instruction, Value>();
        var locals = method.Body.Variables.ToDictionary(l => l, l => method.Body.InitLocals ?
            Primitive(l.Type) is { } p && p != Value.Unknown ? p : Value.Null : Value.Unknown);
        Value Inputs(Instruction instruction, int slot) => flow.Inputs.TryGetValue(instruction, out var args) && slot < args.Length
            ? args[slot].Aggregate(Value.None, (v, p) => v | (p is null ? Value.Unknown : values.GetValueOrDefault(p))) : Value.Unknown;
        bool Plain(Value value) => value != Value.None && (value & (Value.Unknown | Value.Enumerator)) == 0;
        bool Graph(Value value) => value != Value.None && (value & ~(Value.Graph | Value.Null)) == 0;
        bool Text(Value value) => value != Value.None && (value & ~(Value.String | Value.Null)) == 0;
        bool Core(ITypeDefOrRef type, string name) => type is TypeRef && type.FullName == name && type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
        bool Dictionary(ITypeDefOrRef type) => type.ToTypeSig() is GenericInstSig { GenericArguments.Count: 2 } g &&
            Core(g.GenericType.TypeDefOrRef, "System.Collections.Generic.Dictionary`2") &&
            new SigComparer().Equals(g.GenericArguments[0], module.CorLibTypes.String) && new SigComparer().Equals(g.GenericArguments[1], module.CorLibTypes.Object);
        bool ContainerType(TypeSig type) => new SigComparer().Equals(type, module.CorLibTypes.Object) ||
            type is SZArraySig array && new SigComparer().Equals(array.Next, module.CorLibTypes.Object) ||
            Dictionary(type.ToTypeDefOrRef()) || Core(type.ToTypeDefOrRef(), "System.Collections.IEnumerable");
        Value Dynamic(Instruction instruction)
        {
            if (!bindings.TryGetValue(instruction, out var binding)) return Value.Unknown;
            var d = binding.Descriptor!; var count = flow.Inputs[instruction].Length - 2;
            var args = Enumerable.Range(0, count).Select(n => Inputs(instruction, n + 2)).ToArray();
            if (args.Any(v => v == Value.None)) return Value.None;
            if (args.Any(v => !Plain(v))) return Value.Unknown;
            // These flags select ordinary positional, dynamic or statically typed
            // arguments. Named/ref/out/static-type arguments require other proofs.
            if (d.Arguments.Any(a => a.Name is not null || (a.Flags & ~3) != 0)) return Value.Unknown;
            if (d.Kind != "Convert" && d.Arguments.Count != count) return Value.Unknown;
            if (d.Kind == "Convert" && count == 1 && d.ConversionType is { } target)
            {
                if (d.Flags == 16 && Core(target, "System.String")) return Value.String;
                if (d.Flags == 0 && ContainerType(target.ToTypeSig()) && Graph(args[0])) return Value.Graph | Value.Null;
            }
            if (d.Kind == "GetIndex" && d.Flags == 0 && count == 2 && Graph(args[0]) && Text(args[1])) return Value.Graph | Value.Null;
            if (d.Kind == "InvokeMember" && d.Flags == 0 && d.Arguments[0].Flags == 0 && Graph(args[0]))
            {
                if (d.Name == "GetType" && count == 1) return Value.Type;
                if (d.Name == "ContainsKey" && count == 2 && Text(args[1])) return Value.Scalar;
            }
            if (d.Kind == "UnaryOperation" && d.Flags == 0 && count == 1 &&
                d.Operation is (int)ExpressionType.IsTrue or (int)ExpressionType.IsFalse or (int)ExpressionType.Not) return Value.Scalar;
            if (d.Kind == "BinaryOperation" && count == 2 &&
                (d.Flags == 0 && d.Operation is (int)ExpressionType.Equal or (int)ExpressionType.NotEqual ||
                 d.Flags == 8 && d.Operation is (int)ExpressionType.And or (int)ExpressionType.Or)) return Value.Scalar;
            return Value.Unknown;
        }
        Value Call(Instruction instruction, IMethod call)
        {
            if (sources.Contains(instruction)) return Value.Graph | Value.Null;
            if (bindings.ContainsKey(instruction)) return Dynamic(instruction);
            var first = Inputs(instruction, 0);
            if (call.MethodSig?.HasThis == true && Graph(first))
            {
                if (Core(call.DeclaringType, "System.Object") && call.Name == "GetType" && call.MethodSig.Params.Count == 0) return Value.Type;
                if (Dictionary(call.DeclaringType) && call.MethodSig.Params.Count == 1 && Text(Inputs(instruction, 1)))
                {
                    if (call.Name == "get_Item") return Value.Graph | Value.Null;
                    if (call.Name == "ContainsKey") return Value.Scalar;
                }
                if (Core(call.DeclaringType, "System.Collections.IEnumerable") && call.Name == "GetEnumerator" && call.MethodSig.Params.Count == 0) return Value.Enumerator;
            }
            if (first != Value.None && (first & ~(Value.Enumerator | Value.Null)) == 0 && call.MethodSig?.Params.Count == 0)
            {
                if (Core(call.DeclaringType, "System.Collections.IEnumerator") && call.Name == "get_Current") return Value.Graph | Value.Null;
                if (Core(call.DeclaringType, "System.Collections.IEnumerator") && call.Name == "MoveNext") return Value.Scalar;
                if (Core(call.DeclaringType, "System.IDisposable") && call.Name == "Dispose") return Value.Scalar;
            }
            if (call.Name == "GetTypeFromHandle" && Core(call.DeclaringType, "System.Type")) return Value.Type;
            if (Enumerable.Range(0, flow.Inputs[instruction].Length).Any(n => (Inputs(instruction, n) & (Value.Graph | Value.Enumerator)) != 0)) return Value.Unknown;
            if (first == Value.None) return Value.None;
            return Primitive(call.MethodSig?.RetType);
        }
        Value Evaluate(Instruction instruction)
        {
            if (instruction.IsLdloc()) return locals[instruction.GetLocal(method.Body.Variables)!];
            if (instruction.IsLdarg()) return Primitive(instruction.GetParameter(method.Parameters)?.Type);
            if (instruction.IsLdcI4() || instruction.OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or Code.Ldlen or Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un) return Value.Scalar;
            if (instruction.OpCode.Code == Code.Ldstr) return Value.String;
            if (instruction.OpCode.Code == Code.Ldnull) return Value.Null;
            if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call) return Call(instruction, call);
            if (instruction.OpCode.Code == Code.Ldelem_Ref) return Graph(Inputs(instruction, 0)) ? Value.Graph | Value.Null : Value.Unknown;
            if (instruction.OpCode.Code is Code.Castclass or Code.Isinst or Code.Unbox_Any && instruction.Operand is ITypeDefOrRef cast)
            {
                var input = Inputs(instruction, 0);
                if (input == Value.None) return Value.None;
                if (ContainerType(cast.ToTypeSig()) && Graph(input)) return Value.Graph | Value.Null;
                if ((Core(cast, "System.IDisposable") || Core(cast, "System.Collections.IEnumerator")) && (input & ~(Value.Enumerator | Value.Null)) == 0) return Value.Enumerator | Value.Null;
                return Primitive(cast.ToTypeSig());
            }
            return Value.Unknown;
        }
        // Union all writes, including back edges and exception paths. None means
        // not discovered yet; Unknown is permanent and can never be proved away.
        bool changed; var rounds = 0;
        do
        {
            changed = false;
            foreach (var instruction in flow.Inputs.Keys)
            {
                if (instruction.IsStloc())
                {
                    var local = instruction.GetLocal(method.Body.Variables)!; var value = locals[local] | Inputs(instruction, 0);
                    if (value != locals[local]) { locals[local] = value; changed = true; }
                }
                else
                {
                    var value = values.GetValueOrDefault(instruction) | Evaluate(instruction);
                    if (value != values.GetValueOrDefault(instruction)) { values[instruction] = value; changed = true; }
                }
            }
            if (++rounds > 256) return new(false, [], ["JSON flow did not converge within budget."]);
        } while (changed);
        var refusals = new List<string>();
        foreach (var (instruction, args) in flow.Inputs)
        {
            if (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S &&
                (locals[instruction.GetLocal(method.Body.Variables)!] & (Value.Graph | Value.Enumerator)) != 0)
            { refusals.Add("Graph local address: " + instruction); continue; }
            if (!Enumerable.Range(0, args.Length).Any(n => (Inputs(instruction, n) & (Value.Graph | Value.Enumerator)) != 0)) continue;
            if (instruction.IsStloc() || instruction.OpCode.Code is Code.Dup or Code.Pop or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or Code.Ceq or Code.Ldlen) continue;
            if (instruction.OpCode.Code is Code.Castclass or Code.Isinst or Code.Unbox_Any or Code.Ldelem_Ref && (values[instruction] & Value.Unknown) == 0) continue;
            if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod called &&
                (bindings.ContainsKey(instruction) ? Dynamic(instruction) : Call(instruction, called)) is var output &&
                output != Value.None && (output & Value.Unknown) == 0 &&
                (bindings.ContainsKey(instruction) || Core(called.DeclaringType, "System.Object") || Dictionary(called.DeclaringType) ||
                 Core(called.DeclaringType, "System.Collections.IEnumerable") || Core(called.DeclaringType, "System.Collections.IEnumerator") || Core(called.DeclaringType, "System.IDisposable"))) continue;
            refusals.Add("Unproved graph consumer: " + instruction);
        }
        var members = bindings.Where(p => p.Value.Descriptor!.Kind == "InvokeMember" &&
            p.Value.Descriptor.Name == "GetType" && Dynamic(p.Key) == Value.Type).Select(p => p.Value.Site.Binder).Distinct().ToArray();
        return new(refusals.Count == 0 && members.Length != 0, members, refusals);
    }
    private static Value Primitive(TypeSig? type) => type?.ElementType switch
    {
        ElementType.String => Value.String,
        ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or
        ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.R4 or ElementType.R8 or ElementType.I or ElementType.U => Value.Scalar,
        _ => Value.Unknown
    };
}
