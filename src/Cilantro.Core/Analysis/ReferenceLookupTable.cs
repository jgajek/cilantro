using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Identifies a private enum lookup table by its closed initialization and read-only consumers.</summary>
internal static class ReferenceLookupTable
{
    private const string Consumer = "System.Boolean Newtonsoft.Json.Linq.JToken::ValidateToken(Newtonsoft.Json.Linq.JToken,Newtonsoft.Json.Linq.JTokenType[],System.Boolean)";

    internal static string? Identify(IField reference, IReadOnlyDictionary<string,string> aliases)
    {
        var field = reference.ResolveFieldDef();
        if (field is not { IsPrivate:true, IsStatic:true, IsInitOnly:true } ||
            field.FieldType is not SZArraySig { Next:ValueTypeSig element } ||
            element.TypeDefOrRef.ResolveTypeDef() is not { IsEnum:true } definition ||
            definition.Module != field.Module || definition.GetEnumUnderlyingType()?.ElementType != ElementType.I4) return null;
        var owner = field.DeclaringType;
        var initializer = owner.FindStaticConstructor();
        if (initializer is not { HasBody:true } || initializer.Body.HasExceptionHandlers) return null;
        var il = initializer.Body.Instructions;
        var stores = il.Where(i => i.OpCode.Code == Code.Stsfld && i.Operand is IField f && f.ResolveFieldDef() == field).ToArray();
        if (stores.Length != 1) return null;
        var at = il.IndexOf(stores[0]);
        if (at < 5 || !il[at-5].IsLdcI4() || il[at-5].GetLdcI4Value() is <1 or >128 ||
            il[at-4].OpCode.Code != Code.Newarr || il[at-4].Operand is not ITypeDefOrRef allocated || !new SigComparer().Equals(allocated,element.TypeDefOrRef) ||
            il[at-3].OpCode.Code != Code.Dup || il[at-2].OpCode.Code != Code.Ldtoken ||
            il[at-2].Operand is not IField dataReference || dataReference.ResolveFieldDef() is not { IsStatic:true, HasFieldRVA:true, InitialValue: {} data } dataField ||
            dataField.Module != field.Module || data.Length != il[at-5].GetLdcI4Value()*4 || il[at-1].OpCode.Code != Code.Call ||
            il[at-1].Operand is not IMethod initialize || initialize.FullName != "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)" ||
            !CoreLibraryIdentity.Matches(field.Module,initialize.DeclaringType,"System.Runtime.CompilerServices.RuntimeHelpers")) return null;
        // The initializer must reach this assignment along a single unconditional path.
        var visited = new HashSet<Instruction>();
        var cursor = 0;
        while(cursor >= 0 && cursor < il.Count && visited.Add(il[cursor])) {
            var instruction=il[cursor];
            if(instruction.OpCode.Code==Code.Ret)break;
            if(instruction.OpCode.FlowControl==FlowControl.Branch && instruction.OpCode.Code is Code.Br or Code.Br_S && instruction.Operand is Instruction target)cursor=il.IndexOf(target);
            else if(instruction.OpCode.FlowControl is FlowControl.Cond_Branch or FlowControl.Branch or FlowControl.Throw or FlowControl.Return)return null;
            else cursor++;
        }
        if(cursor<0 || cursor>=il.Count || il[cursor].OpCode.Code!=Code.Ret || !visited.Contains(stores[0]))return null;
        var middle=il.Skip(at-4).Take(5).ToHashSet();
        if(il.Any(i=>i.Operand is Instruction target && middle.Contains(target) || i.Operand is IList<Instruction> targets && targets.Any(middle.Contains)))return null;
        foreach(var method in field.Module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody)) {
            var body=method.Body.Instructions;
            for(var n=0;n<body.Count;n++) {
                if(body[n].Operand is not IField used)continue;
                if(used.ResolveFieldDef()==dataField && (body[n].OpCode.Code!=Code.Ldtoken || n+1>=body.Count ||
                    body[n+1].OpCode.Code!=Code.Call || body[n+1].Operand is not IMethod init || init.FullName!=initialize.FullName ||
                    !CoreLibraryIdentity.Matches(field.Module,init.DeclaringType,"System.Runtime.CompilerServices.RuntimeHelpers")))return null;
                if(used.ResolveFieldDef()!=field)continue;
                if(method==initializer && body[n]==stores[0])continue;
                if(body[n].OpCode.Code!=Code.Ldsfld || n+2>=body.Count || !body[n+1].IsLdcI4() || body[n+1].GetLdcI4Value() is <0 or >1 ||
                    body[n+2].OpCode.Code!=Code.Call || body[n+2].Operand is not IMethod call || !ReferenceParameterContracts.IsLookupConsumer(call,Consumer,aliases))return null;
                if(body.Any(i=>i.Operand==body[n+1] || i.Operand==body[n+2] || i.Operand is IList<Instruction> targets && (targets.Contains(body[n+1])||targets.Contains(body[n+2]))))return null;
            }
        }
        return field.FieldType.FullName+":"+Convert.ToHexString(data);
    }
}
