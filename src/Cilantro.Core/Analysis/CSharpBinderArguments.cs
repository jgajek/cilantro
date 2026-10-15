using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Reads exact framework binder construction. A decoded descriptor is not
/// evidence that its operation is pure or that its receiver has a closed type.</summary>
internal sealed class CSharpBinderArguments
{
    internal sealed record Argument(int Flags, string? Name);
    internal sealed record Descriptor(string Kind, int Flags, string? Name, int? Operation,
        ITypeDefOrRef? ConversionType, ITypeDefOrRef Context, IReadOnlyList<Argument> Arguments);
    private readonly MethodDef method;
    private readonly EvaluationStackOrigins.Result flow;
    private readonly ControlFlowGraph graph;
    private readonly ILookup<Instruction, (Instruction Consumer, int Slot)> consumers;
    internal CSharpBinderArguments(MethodDef method)
    {
        this.method = method;
        flow = EvaluationStackOrigins.Analyze(method);
        graph = ControlFlowGraph.Build(method);
        consumers = flow.Inputs.SelectMany(pair => pair.Value.SelectMany((set, slot) => set.OfType<Instruction>()
            .Select(producer => (producer, use: (Consumer: pair.Key, Slot: slot))))).ToLookup(p => p.producer, p => p.use);
    }
    private Instruction? One(Instruction instruction, int slot) => flow.Inputs.TryGetValue(instruction, out var values) &&
        slot < values.Length && values[slot].Count == 1 ? values[slot].Single() : null;
    private static int? Integer(Instruction? instruction) => instruction?.IsLdcI4() == true ? instruction.GetLdcI4Value() : null;
    private bool Core(TypeSig signature, string name) => signature.ToTypeDefOrRef() is TypeRef type && type.FullName == name &&
        type.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
    private static bool Framework(ITypeDefOrRef? type, string name, string assemblyName, string token) =>
        type is TypeRef { ResolutionScope: AssemblyRef assembly } && type.FullName == name && assembly.Name == assemblyName &&
        assembly.FullName.EndsWith(", PublicKeyToken=" + token, StringComparison.OrdinalIgnoreCase);
    private static bool CSharp(TypeSig signature, string name) => Framework(signature.ToTypeDefOrRef(),
        "Microsoft.CSharp.RuntimeBinder." + name, "Microsoft.CSharp", "b03f5f7f11d50a3a");
    private bool Sequence(TypeSig signature, Func<TypeSig, bool> element) => signature is GenericInstSig { GenericArguments.Count: 1 } generic &&
        Core(generic.GenericType, "System.Collections.Generic.IEnumerable`1") && element(generic.GenericArguments[0]);
    private static bool Ordinary(IMethod call) => call is not MethodSpec && call.MethodSig is
        { HasThis: false, ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } sig &&
        (sig.CallingConvention & CallingConvention.Mask) == CallingConvention.Default;
    private ITypeDefOrRef? TypeValue(Instruction? instruction)
    {
        if (instruction?.OpCode.Code != Code.Call || instruction.Operand is not IMethod call || !Ordinary(call) ||
            call.Name != "GetTypeFromHandle" || !Core(call.DeclaringType.ToTypeSig(), "System.Type") ||
            call.MethodSig.Params.Count != 1 || !Core(call.MethodSig.Params[0], "System.RuntimeTypeHandle") ||
            !Core(call.MethodSig.RetType, "System.Type") || One(instruction, 0) is not { OpCode.Code: Code.Ldtoken, Operand: ITypeDefOrRef type }) return null;
        return type;
    }
    internal Descriptor? Read(Instruction binder)
    {
        if (!flow.Valid || binder.OpCode.Code != Code.Call || binder.Operand is not IMethod call || !Ordinary(call) ||
            !CSharp(call.DeclaringType.ToTypeSig(), "Binder") ||
            !Framework(call.MethodSig.RetType.ToTypeDefOrRef(), "System.Runtime.CompilerServices.CallSiteBinder", "System.Core", "b77a5c561934e089")) return null;
        var p = call.MethodSig.Params; var kind = call.Name.String;
        if (p.Count == 0 || !CSharp(p[0], "CSharpBinderFlags") || Integer(One(binder, 0)) is not { } flags) return null;
        if (kind == "Convert")
        {
            if (p.Count != 3 || !Core(p[1], "System.Type") || !Core(p[2], "System.Type") ||
                TypeValue(One(binder, 1)) is not { } conversion || TypeValue(One(binder, 2)) is not { } context) return null;
            return new(kind, flags, null, null, conversion, context, []);
        }
        var contextSlot = kind == "GetIndex" ? 1 : kind == "InvokeMember" ? 3 : 2;
        var argumentSlot = contextSlot + 1;
        if (p.Count != argumentSlot + 1 || !Core(p[contextSlot], "System.Type") ||
            !Sequence(p[argumentSlot], t => CSharp(t, "CSharpArgumentInfo")) ||
            TypeValue(One(binder, contextSlot)) is not { } owner) return null;
        string? name = null; int? operation = null;
        if (kind == "InvokeMember")
        {
            if (!Core(p[1], "System.String") || !Sequence(p[2], t => Core(t, "System.Type")) ||
                One(binder, 1) is not { OpCode.Code: Code.Ldstr, Operand: string literal } || One(binder, 2)?.OpCode.Code != Code.Ldnull) return null;
            name = literal;
        }
        else if (kind is "BinaryOperation" or "UnaryOperation")
        {
            if (!Framework(p[1].ToTypeDefOrRef(), "System.Linq.Expressions.ExpressionType", "System.Core", "b77a5c561934e089") ||
                Integer(One(binder, 1)) is not { } op) return null;
            operation = op;
        }
        else if (kind != "GetIndex") return null;
        var args = Arguments(binder, argumentSlot);
        if (args is null || kind == "UnaryOperation" && args.Length != 1 || kind == "BinaryOperation" && args.Length != 2) return null;
        return new(kind, flags, name, operation, null, owner, args);
    }
    private Argument[]? Arguments(Instruction binder, int slot)
    {
        var array = One(binder, slot);
        if (array?.OpCode.Code != Code.Newarr || array.Operand is not ITypeDefOrRef element || !CSharp(element.ToTypeSig(), "CSharpArgumentInfo") ||
            Integer(One(array, 0)) is not { } count || count is < 1 or > 32) return null;
        var block = graph.BlockOf(binder);
        if (graph.BlockOf(array) != block) return null;
        var positions = block.Instructions.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        var args = new Argument?[count];
        foreach (var use in consumers[array])
        {
            if (use.Consumer == binder && use.Slot == slot) continue;
            if (use.Slot == 0 && use.Consumer.OpCode.Code == Code.Dup && graph.BlockOf(use.Consumer) == block &&
                positions[use.Consumer] > positions[array] && positions[use.Consumer] < positions[binder]) continue;
            var store = use.Consumer;
            if (use.Slot != 0 || store.OpCode.Code != Code.Stelem_Ref || graph.BlockOf(store) != block ||
                positions[store] <= positions[array] || positions[store] >= positions[binder] ||
                Integer(One(store, 1)) is not { } index || index < 0 || index >= count || args[index] is not null) return null;
            var make = One(store, 2);
            if (make?.OpCode.Code != Code.Call || make.Operand is not IMethod create || !Ordinary(create) ||
                create.Name != "Create" || !CSharp(create.DeclaringType.ToTypeSig(), "CSharpArgumentInfo") ||
                !CSharp(create.MethodSig.RetType, "CSharpArgumentInfo") || create.MethodSig.Params.Count != 2 ||
                !CSharp(create.MethodSig.Params[0], "CSharpArgumentInfoFlags") || !Core(create.MethodSig.Params[1], "System.String") ||
                Integer(One(make, 0)) is not { } flags || graph.BlockOf(make) != block ||
                consumers[make].Any(c => c.Consumer != store || c.Slot != 2)) return null;
            var name = One(make, 1);
            if (name?.OpCode.Code is not (Code.Ldnull or Code.Ldstr)) return null;
            args[index] = new(flags, name.Operand as string);
        }
        return args.All(a => a is not null) ? args.Select(a => a!).ToArray() : null;
    }
}
