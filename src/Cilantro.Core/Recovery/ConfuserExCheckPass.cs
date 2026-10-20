using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Removes closed ConfuserEx anti-debug and anti-dump startup calls.</summary>
public sealed class ConfuserExCheckPass : DeobfuscationPass
{
    public override string Name => "confuserex-checks";
    public override IReadOnlyCollection<string> Dependencies => ["method-inlining"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts?.IsConfuserExProtected != true)
            return (PassStatus.Success, 0, ["Not ConfuserEx-protected."]);
        var cctor = context.Module.GlobalType.FindStaticConstructor();
        if (cctor?.HasBody != true)
            return (PassStatus.Success, 0, ["No module initializer contains ConfuserEx checks."]);

        var targets = cctor.Body.Instructions
            .Where(instruction => instruction.OpCode.Code == Code.Call &&
                (instruction.Operand as IMethod)?.ResolveMethodDef() is { } called &&
                called.DeclaringType == context.Module.GlobalType &&
                called.HasBody)
            .Select(instruction => (Instruction: instruction,
                Method: ((IMethod)instruction.Operand).ResolveMethodDef()!))
            .Where(pair => Kind(pair.Method) is not null)
            .ToArray();
        if (targets.Length == 0)
            return (PassStatus.Success, 0, ["No closed anti-debug or anti-dump initializer matched."]);
        foreach (var target in targets)
        {
            var callers = context.Module.GetTypes().SelectMany(type => type.Methods)
                .Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions
                    .Where(instruction => instruction.OpCode.Code == Code.Call &&
                        (instruction.Operand as IMethod)?.ResolveMethodDef() == target.Method)
                    .Select(_ => method)).ToArray();
            if (callers.Length != 1 || callers[0] != cctor)
                return (PassStatus.Unsupported, 0,
                    [$"Check initializer {target.Method.MDToken} has another caller."]);
        }

        using var batch = new BodyMutationBatch();
        batch.Capture(cctor);
        foreach (var target in targets)
        {
            target.Instruction.OpCode = OpCodes.Nop;
            target.Instruction.Operand = null;
        }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
                context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            return (PassStatus.Unsupported, 0, ["Check removal failed structural verification."]);
        batch.Commit();
        foreach (var target in targets)
            context.AddChange(new ChangeRecord(Name, "neutralize-confuserex-check",
                target.Method.FullName, $"Removed the {Kind(target.Method)} startup call."));
        if (targets.Any(target => Kind(target.Method) == "anti-debug"))
            context.AddEvidence(new Evidence("capability", "anti-debug",
                "Recognized the ConfuserEx managed debugger worker after proxy recovery.", 0.95));
        context.SetFact("checks.neutralized", targets.Length);
        return (PassStatus.Success, targets.Length,
            [$"Neutralized {targets.Length} closed anti-debug/image-protection startup call(s)."]);
    }

    private static string? Kind(MethodDef method)
    {
        bool Calls(string type, string name) => method.Body.Instructions.Any(instruction =>
            instruction.Operand is IMethod called &&
            called.DeclaringType?.FullName == type && called.Name == name);
        if (Calls("System.Threading.Thread", "Start") &&
            Calls("System.Environment", "FailFast"))
            return "anti-debug";
        // Antinet mode runs debugger/profiler probes synchronously. Its injected
        // initializer calls several global helpers and fails fast directly, with
        // no worker thread to identify it by.
        if (Calls("System.Environment", "FailFast") &&
            method.Body.Instructions.Count(instruction =>
                instruction.OpCode.Code == Code.Call &&
                (instruction.Operand as IMethod)?.ResolveMethodDef() is { } helper &&
                helper.DeclaringType == method.DeclaringType && helper != method) >= 2)
            return "anti-debug";
        if (Calls("System.Runtime.InteropServices.Marshal", "GetHINSTANCE") &&
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.ResolveMethodDef()?.ImplMap?.Name == "VirtualProtect"))
            return "image-protection";
        return null;
    }
}
