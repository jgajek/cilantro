using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Redirects calls that pass through proven pass-through forwarders to their real targets.
/// </summary>
/// <remarks>
/// Reactor multiplies indirection by wrapping a call in a static forwarder that loads its arguments
/// in order and calls a single target. Such a forwarder is a pure alias: substituting the target at
/// each call site is stack-neutral by construction, because the forwarder's argument list and return
/// value match the target's exactly. This generalizes constant-predicate folding from
/// constant-returning helpers to constant-behaving ones.
///
/// The transform is a single operand rewrite at each site and never removes the forwarder, so the
/// public-API and structural identity gates hold unchanged. It is deliberately narrow: only static
/// forwarders whose body is an in-order argument load followed by one call and a return qualify.
/// Argument-shuffling forwarders would require materializing the reordering through locals and are
/// left out of this conservative pass rather than approximated. Every rewrite is staged and rolled
/// back unless verification passes.
/// </remarks>
public sealed class MethodInliningPass : DeobfuscationPass
{
    public override string Name => "method-inlining";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var forwarders = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Select(method => (Method: method, Target: TryGetForwardedTarget(method)))
            .Where(item => item.Target is not null)
            .ToDictionary(item => item.Method, item => item.Target!);
        if (forwarders.Count == 0)
            return (PassStatus.Success, 0, ["No pass-through forwarder was detected."]);

        var changes = 0;
        using var transaction = new InstructionMutationTransaction();
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods)
                     .Where(item => item.HasBody))
        {
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.FlowControl != FlowControl.Call ||
                    instruction.OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    instruction.Operand is not IMethod called ||
                    called.ResolveMethodDef() is not { } definition ||
                    !forwarders.TryGetValue(definition, out var forward) ||
                    // Leave the forwarder's own body alone; only external callers are redirected.
                    method == definition)
                {
                    continue;
                }

                transaction.Capture(instruction);
                instruction.OpCode = forward.InnerOpCode;
                instruction.Operand = forward.Target;
                changes++;
                context.AddChange(new ChangeRecord(
                    Name,
                    "inline-forwarder",
                    $"{method.MDToken} IL_{instruction.Offset:X4}",
                    $"Redirected forwarder {definition.MDToken} to {forward.Target.MDToken}."));
            }
        }
        if (changes == 0)
            return (PassStatus.Success, 0, ["No reachable forwarder call site required redirection."]);

        var verification = AssemblyVerifier.Verify(
            context.Module, context.OriginalIdentity, context.OriginalStructure);
        if (!verification.Passed)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
                ["Forwarder inlining failed verification and was rolled back."]);
        }
        transaction.Commit();
        context.SetFact("inlining.redirected", changes);
        return (PassStatus.Success, changes,
            [$"Redirected {changes} forwarder call site(s) to their proven targets."]);
    }

    /// <summary>
    /// Returns the single target a static forwarder passes straight through to, or null.
    /// </summary>
    private static ForwardTarget? TryGetForwardedTarget(MethodDef method)
    {
        if (!method.HasBody ||
            !method.IsStatic ||
            method.HasGenericParameters ||
            method.Body.ExceptionHandlers.Count != 0)
        {
            return null;
        }
        var parameterCount = method.MethodSig?.Params.Count ?? 0;
        var body = method.Body.Instructions
            .Where(instruction => instruction.OpCode != OpCodes.Nop)
            .ToArray();
        // Exactly: load every parameter in order, one call, return.
        if (body.Length != parameterCount + 2)
            return null;
        for (var index = 0; index < parameterCount; index++)
        {
            if (!IsLoadOfArgument(body[index], index))
                return null;
        }
        var call = body[parameterCount];
        if (call.OpCode.Code is not (Code.Call or Code.Callvirt) ||
            call.Operand is not IMethod target ||
            target.ResolveMethodDef() is not { } definition ||
            definition == method ||
            body[^1].OpCode.Code != Code.Ret)
        {
            return null;
        }
        // The target must consume exactly the forwarded arguments and return what the forwarder
        // returns, otherwise substitution would not be stack-neutral.
        var targetArgs = (target.MethodSig?.Params.Count ?? 0) +
            (target.MethodSig?.HasThis == true ? 1 : 0);
        if (targetArgs != parameterCount)
            return null;
        if (!ReturnTypesMatch(method, target))
            return null;
        return new ForwardTarget(target, call.OpCode);
    }

    private static bool IsLoadOfArgument(Instruction instruction, int index) =>
        instruction.OpCode.Code switch
        {
            Code.Ldarg_0 => index == 0,
            Code.Ldarg_1 => index == 1,
            Code.Ldarg_2 => index == 2,
            Code.Ldarg_3 => index == 3,
            Code.Ldarg or Code.Ldarg_S when instruction.Operand is Parameter parameter =>
                parameter.Index == index,
            _ => false
        };

    private static bool ReturnTypesMatch(MethodDef forwarder, IMethod target)
    {
        var forwarderReturn = forwarder.MethodSig?.RetType;
        var targetReturn = target.MethodSig?.RetType;
        if (forwarderReturn is null || targetReturn is null)
            return false;
        return string.Equals(
            forwarderReturn.FullName, targetReturn.FullName, StringComparison.Ordinal);
    }

    private sealed record ForwardTarget(IMethod Target, OpCode InnerOpCode);
}
