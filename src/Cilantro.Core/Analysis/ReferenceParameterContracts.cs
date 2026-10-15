using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Reference-body contracts for restoring erased library parameter types; never a substitute for caller checks.</summary>
internal static class ReferenceParameterContracts
{
    internal sealed record Node(string Key, int? Local, string? LocalType, int? Target, bool Inverted, bool Terminal);
    internal sealed record Contract(string Owner, string Signature, string ReturnType, string ReturnScope, string[] Parameters, string[] ParameterScopes, Node[] Body);
    private static readonly Lazy<Contract[]> Known = new(() => {
        using var stream = typeof(ReferenceParameterContracts).Assembly.GetManifestResourceStream("Cilantro.Core.ReferenceParameterContracts.json")
            ?? throw new InvalidOperationException("Reference parameter contracts missing.");
        return JsonSerializer.Deserialize<Contract[]>(stream) ?? [];
    });

    internal static IReadOnlySet<MethodDef> Find(ModuleDef module)
    {
        var found = new Dictionary<MethodDef,Contract>();
        var aliases = new Dictionary<string,string>(StringComparer.Ordinal);
        var types = module.GetTypes().ToLookup(t=>t.FullName,StringComparer.Ordinal);
        bool changed;
        do {
            changed = false;
            foreach (var contract in Known.Value.Where(c=>!found.ContainsValue(c))) {
                var matches = types[contract.Owner].SelectMany(t=>t.Methods).Where(m=>!found.ContainsKey(m) && Match(m,contract,aliases)).ToArray();
                if (matches.Length != 1 || aliases.ContainsKey(matches[0].FullName)) continue;
                found.Add(matches[0],contract); aliases.Add(matches[0].FullName,contract.Signature); changed = true;
            }
        } while(changed);
        return found.Keys.ToHashSet();
    }

    internal static bool IsLookupConsumer(IMethod called, string signature, IReadOnlyDictionary<string,string> aliases)
    {
        if (aliases.TryGetValue(called.FullName, out var certified)) return certified == signature;
        var contract = Known.Value.SingleOrDefault(c => c.Signature == signature);
        return contract is not null && !contract.Body.Any(n => n.Key.StartsWith("Ldsfld:", StringComparison.Ordinal)) &&
            called.ResolveMethodDef() is {} method && Match(method, contract, aliases);
    }
    internal static Contract Create(MethodDef reference) => new(reference.DeclaringType.FullName,reference.FullName,
        reference.ReturnType.FullName,Scope(reference.Module,reference.ReturnType.ToTypeDefOrRef()),reference.MethodSig.Params.Select(p=>p.FullName).ToArray(),reference.MethodSig.Params.Select(p=>Scope(reference.Module,p.ToTypeDefOrRef())).ToArray(),
        reference.Body.Instructions.Select(i=>Describe(reference,i,new Dictionary<string,string>())).ToArray());

    internal static bool Match(MethodDef method, Contract contract, IReadOnlyDictionary<string,string> aliases)
    {
        if (!method.HasBody || !method.IsStatic || method.IsConstructor || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            method.Body.HasExceptionHandlers || method.ReturnType.FullName != contract.ReturnType || Scope(method.Module,method.ReturnType.ToTypeDefOrRef()) != contract.ReturnScope ||
            method.MethodSig is not {HasThis:false,ExplicitThis:false,GenParamCount:0,ParamsAfterSentinel:null} || (method.MethodSig.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
            method.MethodSig.Params.Count != contract.Parameters.Length || method.Body.Instructions.Count > 2048 || contract.Body.Length > 512 ||
            method.MethodSig.Params.Where((p,n)=>p.ElementType != ElementType.Object && (p.FullName != contract.Parameters[n] || Scope(method.Module,p.ToTypeDefOrRef()) != contract.ParameterScopes[n])).Any()) return false;
        var il = method.Body.Instructions;
        var left = il.Select(i=>Describe(method,i,aliases)).ToArray(); var right = contract.Body;
        var pending = new Queue<(int,int)>(); pending.Enqueue((0,0)); var seen = new HashSet<(int,int)>();
        var locals = new Dictionary<int,int>(); var reverse = new Dictionary<int,int>();
        int Skip(Node[] nodes,int at,bool candidate) {
            var visited = new HashSet<int>();
            while(at>=0 && at<nodes.Length && visited.Add(at)) {
                if(nodes[at].Key=="Nop:"){at++;continue;}
                if(nodes[at].Key=="Br" && nodes[at].Target is {} target){at=target;continue;}
                if(candidate && il[at].OpCode.Code==Code.Castclass && at>0 && il[at-1].IsLdarg() &&
                    il[at-1].GetParameter(method.Parameters) is {} arg && arg.Index<contract.Parameters.Length &&
                    il[at].Operand is ITypeDefOrRef cast && cast.FullName==contract.Parameters[arg.Index] && Scope(method.Module,cast)==contract.ParameterScopes[arg.Index] &&
                    !il.Any(i=>i.Operand==il[at] || i.Operand is IList<Instruction> targets && targets.Contains(il[at]))) {at++;continue;}
                return at;
            }
            return -1;
        }
        while(pending.TryDequeue(out var pair)) {
            var x=Skip(left,pair.Item1,true);var y=Skip(right,pair.Item2,false);
            if(x<0||y<0)return false;if(!seen.Add((x,y)))continue;if(seen.Count>10000)return false;
            var a=left[x];var b=right[y];
            if(a.Key!=b.Key || a.Terminal!=b.Terminal || a.LocalType!=b.LocalType || a.Key=="unsupported")return false;
            if(a.Local is {} local && b.Local is {} other) {
                if(locals.TryGetValue(local,out var prior)&&prior!=other || reverse.TryGetValue(other,out prior)&&prior!=local)return false;
                locals[local]=other;reverse[other]=local;
            } else if(a.Local is not null || b.Local is not null)return false;
            if(a.Target is {} targetA && b.Target is {} targetB) {
                pending.Enqueue((a.Inverted?x+1:targetA,b.Inverted?y+1:targetB));
                pending.Enqueue((a.Inverted?targetA:x+1,b.Inverted?targetB:y+1));
            } else if(a.Target is not null || b.Target is not null)return false;
            else if(!a.Terminal)pending.Enqueue((x+1,y+1));
        }
        return true;
    }

    private static Node Describe(MethodDef method,Instruction instruction,IReadOnlyDictionary<string,string> aliases)
    {
        var code=instruction.OpCode.Code.ToString();if(code.EndsWith("_S",StringComparison.Ordinal))code=code[..^2];
        var inverted=code=="Brfalse" || code=="Bge" && IntegralComparison(method,instruction);
        if(code=="Brfalse")code="Brtrue";if(code=="Bge"&&inverted)code="Blt";
        string key;
        Local? local=null;
        if(instruction.IsLdarg())key="arg:"+instruction.GetParameter(method.Parameters).Index;
        else if(instruction.OpCode.Code is Code.Starg or Code.Starg_S)key="starg:"+instruction.GetParameter(method.Parameters).Index;
        else if(instruction.IsLdcI4())key="int:"+instruction.GetLdcI4Value();
        else if(instruction.IsLdloc()||instruction.IsStloc()||instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) {
            local=instruction.GetLocal(method.Body.Variables);key=instruction.IsLdloc()?"load":instruction.IsStloc()?"store":"address";
        } else if(instruction.Operand is Instruction)key=code;
        else if(instruction.Operand is IList<Instruction>)key="unsupported";
        else if(instruction.Operand is IMethod called)key=code+":"+aliases.GetValueOrDefault(called.FullName,called.FullName)+"|"+Scope(method.Module,called.DeclaringType);
        else if(instruction.Operand is IField field)key=code+":"+(ReferenceLookupTable.Identify(field,aliases) is {} table ? "lookup:"+table : field.FullName)+"|"+Scope(method.Module,field.DeclaringType);
        else if(instruction.Operand is ITypeDefOrRef type)key=code+":"+type.FullName+"|"+Scope(method.Module,type);
        else key=code+":"+(instruction.Operand?.ToString()??"");
        return new(key,local?.Index,local is null?null:local.Type.FullName+"|"+Scope(method.Module,local.Type.ToTypeDefOrRef()),
            instruction.Operand is Instruction target?method.Body.Instructions.IndexOf(target):null,inverted,
            instruction.OpCode.FlowControl is FlowControl.Return or FlowControl.Throw);
    }
    private static string Scope(ModuleDef module,ITypeDefOrRef? type) => type is null?"none":
        type is TypeSpec {TypeSig:GenericInstSig generic}?"generic:"+Scope(module,generic.GenericType.TypeDefOrRef)+"<"+string.Join(",",generic.GenericArguments.Select(a=>Scope(module,a.ToTypeDefOrRef())))+">":
        type is TypeSpec {TypeSig:SZArraySig array}?"array:"+Scope(module,array.Next.ToTypeDefOrRef()):
        (type.ResolveTypeDef()?.Module==module || type is TypeRef reference && reference.DefinitionAssembly?.FullName==module.Assembly?.FullName && module.GetTypes().Count(t=>t.FullName==reference.FullName)==1)?"local":(CoreLibraryIdentity.Matches(module,type,type.FullName) || type is TypeRef {FullName:"System.String"} && type.DefinitionAssembly?.FullName == "System.Runtime, Version=4.0.20.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")?"core":type.DefinitionAssembly?.FullName??"unknown";
    private static bool IntegralComparison(MethodDef method,Instruction branch)
    {
        var il=method.Body.Instructions;var at=il.IndexOf(branch);
        if(at<3 || !il[at-3].IsLdloc() || il[at-3].GetLocal(method.Body.Variables)?.Type.ElementType!=ElementType.I4 ||
            !il[at-2].IsLdloc() || il[at-1].OpCode.Code!=Code.Callvirt || il[at-1].Operand is not IMethod call ||
            call.MethodSig is not {HasThis:true,Params.Count:0,RetType.ElementType:ElementType.I4})return false;
        var middle=new HashSet<Instruction>{il[at-2],il[at-1],branch};
        return !il.Any(i=>i.Operand is Instruction target&&middle.Contains(target)||i.Operand is IList<Instruction> targets&&targets.Any(middle.Contains));
    }
}
