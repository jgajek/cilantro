using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Scopes a private static non-accessor's type handles to closed property enumeration.</summary>
internal sealed class PropertyOnlyTypeHandles(ModuleDef module)
{
    private readonly Dictionary<TypeDef, bool> cache = [];
    private readonly ILookup<TypeDef, (MethodDef Method, Instruction Token)> handles = module.GetTypes()
        .SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions
            .Where(i => i.OpCode.Code == Code.Ldtoken && i.Operand is ITypeDefOrRef)
            .Select(i => (Method: m, Token: i, Owner: ((ITypeDefOrRef)i.Operand).ScopeType.ResolveTypeDef())))
        .Where(use => use.Owner?.Module == module).ToLookup(use => use.Owner, use => (use.Method, use.Token));
    internal bool IsClosed(MethodDef candidate)
    {
        if (!candidate.IsPrivate || !candidate.IsStatic || candidate.IsConstructor || candidate.IsVirtual ||
            candidate.DeclaringType.Properties.Any(p => p.GetMethods.Contains(candidate) || p.SetMethods.Contains(candidate) || p.OtherMethods.Contains(candidate))) return false;
        var owner = candidate.DeclaringType;
        if (cache.TryGetValue(owner, out var known)) return known;
        var found = 0;
        foreach (var (method, token) in handles[owner])
        {
            found++;
            var il = method.Body.Instructions;
            var at = il.IndexOf(token);
            if (TypeIdentityHandleUse.IsClosed(method, at) || ComponentTypeMetadataHandleUse.IsClosed(method, token) || InvariantTypeFormattingUse.IsClosed(method, token) || RuntimeTypeRelationshipUse.IsClosed(method, token)) continue;
            var start = at++;
            void Skip() { while (at < il.Count && il[at].OpCode.Code == Code.Nop) at++; }
            bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(module, type, name);
            Skip();
            if (at >= il.Count || il[at].OpCode.Code != Code.Call || il[at].Operand is not IMethod convert ||
                !Core(convert.DeclaringType, "System.Type") || convert.Name != "GetTypeFromHandle" ||
                convert.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 0, Params.Count: 1, ParamsAfterSentinel: null } conversion ||
                (conversion.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
                !Core(conversion.RetType.ToTypeDefOrRef(), "System.Type") || !Core(conversion.Params[0].ToTypeDefOrRef(), "System.RuntimeTypeHandle")) return cache[owner] = false;
            at++; Skip();
            if (at < il.Count && il[at].OpCode.Code == Code.Castclass && il[at].Operand is ITypeDefOrRef cast && Core(cast, "System.Type")) { at++; Skip(); }
            if (at >= il.Count || il[at].OpCode.Code is not (Code.Call or Code.Callvirt) || il[at].Operand is not IMethod lookup ||
                !Core(lookup.DeclaringType, "System.Type") || lookup.Name != "GetProperties" ||
                lookup.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 0, ParamsAfterSentinel: null } signature ||
                (signature.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
                signature.RetType is not SZArraySig array || !Core(array.Next.ToTypeDefOrRef(), "System.Reflection.PropertyInfo")) return cache[owner] = false;
            var interior = il.Skip(start + 1).Take(at - start).ToHashSet();
            if (il.Any(i => i.Operand is Instruction branch && interior.Contains(branch) || i.Operand is IList<Instruction> branches && branches.Any(interior.Contains)) ||
                method.Body.ExceptionHandlers.Any(h => new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }.OfType<Instruction>().Any(interior.Contains)) ||
                !ClosedPropertyContainers.Analyze(method, il[at]).Closed) return cache[owner] = false;
        }
        return cache[owner] = found != 0;
    }
}
