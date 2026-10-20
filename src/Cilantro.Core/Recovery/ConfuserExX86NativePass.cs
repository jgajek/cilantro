using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Converts a closed set of ConfuserEx x86 constant expression stubs to managed IL.</summary>
public sealed class ConfuserExX86NativePass : DeobfuscationPass
{
    public override string Name => "confuserex-x86-native";
    public override IReadOnlyCollection<string> Dependencies => ["confuserex-detection"];

    internal static bool TryPlan(ArtifactContext context,
        out IReadOnlyDictionary<MethodDef, CilBody> bodies)
    {
        bodies = new Dictionary<MethodDef, CilBody>();
        var module = context.Module;
        var header = module.Metadata.ImageCor20Header;
        if (module.NativeEntryPoint != 0 || header.HasNativeHeader || module.IsILOnly ||
            !module.CustomAttributes.Any(attribute => attribute.TypeFullName == "ConfusedByAttribute"))
            return false;
        var natives = module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => (method.ImplAttributes & MethodImplAttributes.CodeTypeMask) ==
                MethodImplAttributes.Native).ToArray();
        if (natives.Length == 0) return false;
        var plan = new Dictionary<MethodDef, CilBody>();
        foreach (var native in natives)
        {
            if (!ConfuserExNativeExpression.TryTranslate(native, context.OriginalBytes,
                    out var body) || body is null)
                return false;
            plan.Add(native, body);
        }
        bodies = plan;
        return true;
    }

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyDictionary<MethodDef, CilBody>>(
                "confuserex.x86.nativePlan", out var plan) || plan is null)
            return (PassStatus.Success, 0, ["No convertible ConfuserEx x86 native stubs."]);
        var oldFlags = context.Module.IsILOnly;
        var oldAttributes = plan.Keys.ToDictionary(method => method, method => method.ImplAttributes);
        // Encrypted anti-tamper bodies can contain unresolved call operands until the
        // subsequent anti-tamper pass restores them. Only reject new diagnostics here.
        var baseline = AssemblyVerifier.Verify(context.Module,
            context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context)).Diagnostics;
        using var batch = new BodyMutationBatch(plan.Keys);
        foreach (var pair in plan)
        {
            pair.Key.Body = pair.Value;
            pair.Key.ImplAttributes = (pair.Key.ImplAttributes &
                    ~(MethodImplAttributes.CodeTypeMask | MethodImplAttributes.ManagedMask)) |
                MethodImplAttributes.IL;
        }
        context.Module.IsILOnly = true;
        var verified = AssemblyVerifier.Verify(context.Module,
            context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        var introduced = verified.Diagnostics.Except(baseline).ToArray();
        if (introduced.Length != 0)
        {
            context.Module.IsILOnly = oldFlags;
            foreach (var pair in oldAttributes) pair.Key.ImplAttributes = pair.Value;
            return (PassStatus.Unsupported, 0,
                [$"ConfuserEx x86 translation failed verification: {string.Join("; ", introduced.Take(3))}"]);
        }
        batch.Commit();
        foreach (var method in plan.Keys)
            context.AddChange(new ChangeRecord(Name, "translate-x86-expression", method.MDToken.ToString(),
                "Rebuilt a closed ConfuserEx x86 integer expression as equivalent CIL."));
        return (PassStatus.Success, plan.Count,
            [$"Translated all {plan.Count} ConfuserEx x86 expression stub(s) to CIL."]);
    }
}
