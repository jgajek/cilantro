using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Redirects calls that pass through proven pass-through forwarders to their real targets.
/// </summary>
/// <remarks>
/// Reactor multiplies indirection by wrapping a call in a static forwarder that loads its arguments
/// in order and calls a single target. Such a forwarder is a pure alias: substituting the target at
/// each call site is stack-neutral by construction, because the forwarder takes the target's
/// arguments in the target's order and hands back what the target returned. This generalizes
/// constant-predicate folding from constant-returning helpers to constant-behaving ones.
///
/// The signatures need not be written the same way, and on Reactor's output they usually are not.
/// Its favourite disguise declares everything it can as <c>System.Object</c> — a helper typed
/// <c>object f(object)</c> whose body calls <c>FileVersionInfo.get_FileVersion</c> — so the types a
/// reader sees say nothing about the call underneath. What licenses substitution is that the body
/// converts nothing: it loads each argument and calls, with no cast, box, or conversion between, so
/// the values the target receives are the caller's own either way and the call performed is
/// identical down to the null check. The declared types are then only a question of what the IL
/// admits, and the pass keeps that side safe by allowing the forwarder's own types to differ only
/// where the difference is a widening to <c>object</c>. Stripping the disguise moves the output
/// towards the types the program was written in rather than away from them.
///
/// Admitting targets outside the assembly is what brings the laundering wrappers in, since they
/// call the framework directly, and it widens what the pass then attributes to the protector. The
/// signatures cannot settle authorship on their own: Reactor declares the real type wherever it has
/// no choice, so its wrapper over <c>TimeSpan.FromSeconds</c> is typed exactly like one a programmer
/// would write, and an exact agreement records only that no slot could be laundered. What the pass
/// can say is narrower and is what the attribution rests on — a forwarder it reports was reachable
/// until this pass redirected the last call to it, so the pass made it dead and owns the
/// consequence, and every call it used to serve now performs the same call. A private one-line
/// helper of the program's own caught by that net loses its name and nothing else. The corpus gate
/// is what holds the line in the other direction, by requiring no preserved name and no per-type
/// method count to go missing against a known-clean build.
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
        CollapseChains(forwarders);

        var changes = 0;
        var bypassed = new HashSet<MethodDef>();
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
                // The whole chain is skipped, not just its first link.
                bypassed.UnionWith(forward.Chain);
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
        // A forwarder exists to be called; every call it had now goes straight to the target.
        RecoveryOrphans.Declare(context, bypassed);
        context.SetFact("inlining.redirected", changes);
        return (PassStatus.Success, changes,
        [
            $"Redirected {changes} forwarder call site(s) to their proven targets.",
            $"{bypassed.Count} forwarder(s) were left with nothing to forward."
        ]);
    }

    /// <summary>
    /// Rewrites each forwarder's target to the end of its chain, so one redirection at a call site
    /// skips the whole run of them.
    /// </summary>
    /// <remarks>
    /// Reactor nests forwarders, and redirecting a site to the next link only moves the indirection
    /// by one. Following the chain first is what makes a single rewrite remove all of it.
    ///
    /// The last link's opcode is the one that survives, because it is the call the program actually
    /// performs. Substitution stays stack-neutral along the way: every link in a chain takes the
    /// same arguments in the same order, or it would not have qualified as a forwarder. A chain that
    /// loops back on itself is left at its first link, since it has no end to resolve to.
    ///
    /// Each extension is re-checked against the head of the chain rather than against the link it
    /// grew from. Every link is licensed against its own immediate target, and the licence permits
    /// the return type to widen, so a chain could in principle accumulate steps that are each
    /// allowed while the head and the end are not compatible at all. Asking the question again for
    /// the pair that will actually be substituted costs nothing and removes the need to reason about
    /// whether the relation composes.
    /// </remarks>
    private static void CollapseChains(Dictionary<MethodDef, ForwardTarget> forwarders)
    {
        foreach (var (forwarder, immediate) in forwarders.ToArray())
        {
            var chain = new List<MethodDef> { forwarder };
            var seen = new HashSet<MethodDef> { forwarder };
            var final = immediate;
            while (final.Target.ResolveMethodDef() is { } next &&
                   seen.Add(next) &&
                   forwarders.TryGetValue(next, out var onward) &&
                   ArgumentsPassStraightThrough(forwarder, onward.Target) &&
                   ReturnTypeSurvives(forwarder, onward.Target))
            {
                chain.Add(next);
                final = onward;
            }
            forwarders[forwarder] = final with { Chain = chain };
        }
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
        // A target outside this assembly cannot resolve to a MethodDef and cannot be this method
        // either, so failing to resolve it is not a reason to decline: Reactor's laundering wrappers
        // are precisely the ones that call straight into the framework.
        if (call.OpCode.Code is not (Code.Call or Code.Callvirt) ||
            call.Operand is not IMethod target ||
            target.ResolveMethodDef() == method ||
            body[^1].OpCode.Code != Code.Ret)
        {
            return null;
        }
        if (!ArgumentsPassStraightThrough(method, target) || !ReturnTypeSurvives(method, target))
            return null;
        return new ForwardTarget(target, call.OpCode, []);
    }

    /// <summary>
    /// Whether the target consumes exactly the values the forwarder was handed, slot for slot.
    /// </summary>
    /// <remarks>
    /// The body loads its arguments and calls, converting nothing, so each value reaches the target
    /// exactly as the caller pushed it and the two signatures are descriptions of the same stack.
    /// They may disagree about how to name a slot — Reactor writes <c>object</c> where the target
    /// says <c>string</c> — and that disagreement is already present in the shipped body, so
    /// repeating it at the call site is not a new liberty. What must not differ is how a slot is
    /// represented, since an object reference and a value are not interchangeable on the stack and
    /// substituting one signature for the other would misread the value rather than retype it.
    /// </remarks>
    private static bool ArgumentsPassStraightThrough(MethodDef forwarder, IMethod target)
    {
        var forwarded = forwarder.MethodSig!.Params;
        var expected = new List<TypeSig?>();
        if (target.MethodSig?.HasThis == true)
            expected.Add(target.DeclaringType?.ToTypeSig());
        foreach (var parameter in target.MethodSig?.Params ?? (IList<TypeSig>)[])
            expected.Add(parameter);
        if (forwarded.Count != expected.Count)
            return false;
        for (var index = 0; index < forwarded.Count; index++)
        {
            if (!SlotsAgree(forwarded[index], expected[index]))
                return false;
        }
        return true;
    }

    private static bool SlotsAgree(TypeSig? forwarded, TypeSig? expected) =>
        forwarded is not null && expected is not null &&
        (string.Equals(forwarded.FullName, expected.FullName, StringComparison.Ordinal) ||
            (IsObjectReference(forwarded) && IsObjectReference(expected)));

    /// <summary>
    /// Whether what the target returns still satisfies everyone who was consuming the forwarder.
    /// </summary>
    /// <remarks>
    /// The forwarder's callers were written against its declared return type, so the substituted
    /// call has to leave the stack holding something they accept. An identical type does, and so
    /// does a reference where the forwarder promised <c>object</c>, which is the case Reactor's
    /// laundering creates and the one worth recovering. The opposite direction is refused: handing
    /// back an <c>object</c> where a caller was told to expect a <c>string</c> would push the
    /// obfuscator's type confusion outwards into code that did not have it.
    /// </remarks>
    private static bool ReturnTypeSurvives(MethodDef forwarder, IMethod target)
    {
        var promised = forwarder.MethodSig?.RetType;
        var actual = target.MethodSig?.RetType;
        if (promised is null || actual is null)
            return false;
        return string.Equals(promised.FullName, actual.FullName, StringComparison.Ordinal) ||
            (promised.ElementType == ElementType.Object && IsObjectReference(actual));
    }

    /// <summary>
    /// Whether a signature slot holds an object reference, judged from the encoding alone.
    /// </summary>
    /// <remarks>
    /// A signature spells a class one way and a value type another, so the element type settles it
    /// without resolving anything. Generic instantiations and type parameters are left out because
    /// their encoding does not say which they are, and guessing is not worth the two extra shapes.
    /// </remarks>
    private static bool IsObjectReference(TypeSig type) => type.ElementType is
        ElementType.Class or ElementType.String or ElementType.Object or
        ElementType.SZArray or ElementType.Array;

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

    /// <param name="Chain">The forwarders a call site skips by going straight to the target.</param>
    private sealed record ForwardTarget(
        IMethod Target, OpCode InnerOpCode, IReadOnlyList<MethodDef> Chain);
}
