using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Exact source-stub argument transport and unchanged arbitrary receiver state.</summary>
internal sealed class BabelGenericStub
{
    private readonly MethodDef stub;
    private readonly HashSet<Instruction> boxes;
    private readonly Dictionary<string, StaticValue> fields = [];
    private StaticValue receiver;
    private string receiverType = "";
    private BabelGenericStub(MethodDef stub, HashSet<Instruction> boxes) { this.stub = stub; this.boxes = boxes; }

    internal static BabelGenericStub? Match(MethodDef method, Func<IMethod, bool> dispatcher)
    {
        var owner = method.DeclaringType;
        if (!method.HasBody || method.HasGenericParameters || !owner.HasGenericParameters || owner.IsValueType ||
            owner.GenericParameters.Count > 8 || owner.GenericParameters.Any(parameter =>
                (parameter.Flags & ~GenericParamAttributes.SpecialConstraintMask) != GenericParamAttributes.NonVariant) ||
            method.MethodSig.Params.Count > 32 || method.Parameters.Any(parameter => parameter.Type.IsByRef || parameter.Type.IsPointer) ||
            method.ReturnType.IsByRef || method.ReturnType.IsPointer || method.Body.ExceptionHandlers.Count != 0 || !method.Body.InitLocals ||
            method.Body.Variables.Count != 1 || method.Body.Variables[0].Type.FullName != "System.Object[]") return null;
        var ownerType = new GenericInstSig((ClassOrValueTypeSig)owner.ToTypeSig(), owner.GenericParameters.Select(parameter => (TypeSig)new GenericVar(parameter.Number, owner)).ToArray());
        if (!GenericOwnerHierarchy.TryRead(ownerType, out _)) return null;
        var il = method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray(); var at = 0;
        var boxes = new HashSet<Instruction>();
        bool IsCode(Code code) => at < il.Length && il[at++].OpCode.Code == code;
        bool Integer(int value) => at < il.Length && il[at].IsLdcI4() && il[at++].GetLdcI4Value() == value;
        bool Argument(int index) => at < il.Length && il[at].IsLdarg() && il[at++].GetParameter(method.Parameters)?.Index == index;
        bool Local(bool store) => at < il.Length && (store ? il[at].IsStloc() : il[at].IsLdloc()) && il[at++].GetLocal(method.Body.Variables)?.Index == 0;
        bool Api(Code code, string name) => at < il.Length && il[at].OpCode.Code == code && il[at].Operand is IMethod called &&
            called.FullName == name && called.ResolveMethodDef()?.Module != method.Module && ++at > 0;
        bool Conversion(Code code, TypeSig type)
        {
            if (at >= il.Length || il[at].OpCode.Code != code || il[at].Operand is not ITypeDefOrRef converted || !new SigComparer().Equals(converted.ToTypeSig(), type)) return false;
            if (code == dnlib.DotNet.Emit.Code.Box) boxes.Add(il[at]); at++; return true;
        }
        bool OwnerToken()
        {
            if (at >= il.Length || il[at].OpCode.Code != dnlib.DotNet.Emit.Code.Ldtoken ||
                il[at++].Operand is not TypeSpec { TypeSig: GenericInstSig instance } ||
                instance.GenericType is not ClassSig || instance.GenericType.TypeDefOrRef.ResolveTypeDef() != owner || instance.GenericArguments.Count != owner.GenericParameters.Count)
                return false;
            return instance.GenericArguments.Select((argument, index) => argument is GenericVar variable && variable.Number == index).All(valid => valid);
        }
        var hasArguments = method.MethodSig.Params.Count != 0;
        if (hasArguments && (!Integer(method.MethodSig.Params.Count) || !IsCode(dnlib.DotNet.Emit.Code.Newarr) ||
            il[at - 1].Operand is not ITypeDefOrRef arrayElement || arrayElement.FullName != "System.Object")) return null;
        foreach (var parameter in method.Parameters.Where(parameter => !parameter.IsHiddenThisParameter))
        {
            if (!IsCode(dnlib.DotNet.Emit.Code.Dup) || !Integer(parameter.Index - (method.IsStatic ? 0 : 1)) || !Argument(parameter.Index)) return null;
            if (parameter.Type.IsValueType || parameter.Type is GenericSig)
            { if (!Conversion(dnlib.DotNet.Emit.Code.Box, parameter.Type)) return null; }
            else if (at < il.Length && il[at].OpCode.Code == dnlib.DotNet.Emit.Code.Box && !Conversion(dnlib.DotNet.Emit.Code.Box, parameter.Type)) return null;
            if (!IsCode(dnlib.DotNet.Emit.Code.Stelem_Ref)) return null;
        }
        if (hasArguments && !Local(true)) return null;
        if (at >= il.Length || !il[at++].IsLdcI4() ||
            !Api(dnlib.DotNet.Emit.Code.Call, "System.Reflection.MethodBase System.Reflection.MethodBase::GetCurrentMethod()") ||
            !Api(dnlib.DotNet.Emit.Code.Callvirt, "System.RuntimeMethodHandle System.Reflection.MethodBase::get_MethodHandle()")) return null;
        if (method.IsStatic)
        {
            if (!OwnerToken() || !Api(dnlib.DotNet.Emit.Code.Call, "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)")) return null;
        }
        else if (!Argument(0) || !Api(dnlib.DotNet.Emit.Code.Call, "System.Type System.Object::GetType()")) return null;
        if (!Api(dnlib.DotNet.Emit.Code.Callvirt, "System.RuntimeTypeHandle System.Type::get_TypeHandle()") ||
            !Api(dnlib.DotNet.Emit.Code.Call, "System.Reflection.MethodBase System.Reflection.MethodBase::GetMethodFromHandle(System.RuntimeMethodHandle,System.RuntimeTypeHandle)") ||
            !(method.IsStatic ? IsCode(dnlib.DotNet.Emit.Code.Ldnull) : Argument(0)) || !(hasArguments ? Local(false) : IsCode(dnlib.DotNet.Emit.Code.Ldnull)) ||
            at >= il.Length || il[at].OpCode.Code != dnlib.DotNet.Emit.Code.Call ||
            il[at++].Operand is not IMethod calledDispatcher || !dispatcher(calledDispatcher)) return null;
        if (method.ReturnType.ElementType == ElementType.Void) { if (!IsCode(dnlib.DotNet.Emit.Code.Pop)) return null; }
        else if (method.ReturnType.ElementType != ElementType.Object && !Conversion(method.ReturnType.IsValueType || method.ReturnType is GenericSig
            ? dnlib.DotNet.Emit.Code.Unbox_Any : dnlib.DotNet.Emit.Code.Castclass, method.ReturnType)) return null;
        return IsCode(dnlib.DotNet.Emit.Code.Ret) && at == il.Length ? new(method, boxes) : null;
    }

    internal StaticValue Prepare(StaticMachine machine, ParametricTypeIntrinsic types)
    {
        var heap = machine.State.Heap;
        types.CertifyStub(stub);
        if (!GenericOwnerHierarchy.TryRead(types.Owner, out var hierarchy, out var externalBase)) throw new InvalidOperationException("Unreviewed generic owner hierarchy.");
        foreach (var layer in hierarchy) machine.State.PreserveApplicationTypeState(layer.Definition, stub);
        machine.State.PreserveExternalApplicationState = externalBase is not null;
        machine.UnknownBoxTransport = (method, instruction, _, value) => method == stub && boxes.Contains(instruction) && value.Kind == StaticValueKind.Unknown;
        if (stub.IsStatic) return StaticValue.Null;
        var allocated = stub.DeclaringType.IsSealed ? heap.TryAllocateOpaqueObject(types.Owner.FullName, out receiver) : heap.TryAllocateSubtypeObject(types.Owner, out receiver);
        if (!allocated) throw new InvalidOperationException("Cannot model the generic receiver.");
        types.BindReceiver(receiver);
        foreach (var field in hierarchy.SelectMany(layer => layer.Definition.Fields).Where(field => !field.IsStatic))
        {
            var unknown = machine.State.Provenance.Origin(StaticValue.Unknown, ProvenanceKind.InstanceField, "Arbitrary generic receiver", field.FullName);
            heap.TryWriteField(receiver, field, unknown);
        }
        if (!heap.TryGetInstanceSnapshot(receiver, out receiverType, out var assigned, out _)) throw new InvalidOperationException("Cannot snapshot the generic receiver.");
        foreach (var pair in assigned) fields.Add(pair.Key, pair.Value);
        return receiver;
    }

    internal bool Unchanged(StaticHeap heap) => stub.IsStatic || heap.TryGetInstanceSnapshot(receiver, out var type, out var assigned, out var model) &&
        heap.HasUnknownRuntimeType(receiver) == !stub.DeclaringType.IsSealed && type == receiverType && model.Count == 0 && assigned.Count == fields.Count && fields.All(pair => assigned.TryGetValue(pair.Key, out var value) &&
            value == pair.Value && value.ProvenanceId == pair.Value.ProvenanceId);
}
