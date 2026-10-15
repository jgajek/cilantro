using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using Cilantro.Core.Interpretation;

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
/// A forwarder over a constructor is the same alias written with <c>newobj</c>: ConfuserEx's mild
/// reference proxies are mostly this shape, since a call it wants to hide is as often a construction
/// as a call. The substitution is stack-neutral for the same reason — <c>newobj</c> consumes the
/// constructor's arguments and leaves the new object where the forwarder left its return value — but
/// the two signatures line up differently, because <c>newobj</c> is handed no instance and the value
/// it produces is the type being constructed rather than the void the constructor declares.
///
/// The initial pass rewrites only calls whose initializer trigger can be skipped. The recheck after
/// loader elision can preserve a remaining trigger with RuntimeHelpers.RunClassConstructor, at the
/// original call site after argument evaluation. It also removes calls to helpers the loader pass
/// emptied, subject to the same initialization checks. Neither pass removes declarations, so the
/// public-API and structural identity gates hold unchanged. It is deliberately narrow: only static
/// forwarders whose body is an in-order argument load followed by one call and a return qualify.
/// Argument-shuffling forwarders would require materializing the reordering through locals and are
/// left out of this conservative pass rather than approximated. Every rewrite is staged and rolled
/// back unless verification passes.
/// </remarks>
public class MethodInliningPass : DeobfuscationPass
{
    public override string Name => "method-inlining";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];
    protected virtual bool PreserveInitializerCalls => false;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var forwarders = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Select(method => (Method: method, Target:
                PreserveInitializerCalls && method.IsStatic && !method.IsStaticConstructor &&
                !method.HasGenericParameters && method.MethodSig?.Params.Count == 0 &&
                RecoveryOrphans.Of(context).Contains(method.MDToken.Raw) &&
                EmptyMethodBodies.DoesNothing(method)
                    ? new ForwardTarget(method, OpCodes.Nop, [])
                    : TryGetForwardedTarget(method)))
            .Where(item => item.Target is not null)
            .ToDictionary(item => item.Method, item => item.Target!);
        if (forwarders.Count == 0)
            return (PassStatus.Success, 0, ["No pass-through forwarder was detected."]);
        CollapseChains(forwarders);

        var changes = 0;
        var bypassed = new HashSet<MethodDef>();
        using var transaction = new BodyMutationBatch();
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods)
                     .Where(item => item.HasBody))
        {
            foreach (var instruction in method.Body.Instructions.ToArray())
            {
                if (instruction.OpCode.FlowControl != FlowControl.Call ||
                    instruction.OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    instruction.Operand is not IMethod called ||
                    called.ResolveMethodDef() is not { } definition ||
                    !forwarders.TryGetValue(definition, out var forward) ||
                    // Leave the forwarder's own body alone; only external callers are redirected.
                    method == definition ||
                    !CanAccessTarget(method, forward.Chain[^1], forward.Target))
                {
                    continue;
                }

                // The forwarded operand is written in the wrapper's generic scope.
                // Preserve the target declaration's signature, but instantiate its owner
                // and method arguments in the original caller's scope before moving it.
                var target = BindTarget(forward.Target, GenericScope.For(called, null), context.Module);

                var initialize = forward.Chain.Where(link => !CanSkipInitializer(link, method)).ToArray();
                // Only materialize the original call's own initialization trigger. Intermediate
                // owners may not be nameable here, and open generic owners need a closed token.
                if (initialize.Length != 0 && (!PreserveInitializerCalls ||
                    initialize.Any(link => link.DeclaringType != definition.DeclaringType) ||
                    HasGenericOwner(definition.DeclaringType) || definition.DeclaringType.IsBeforeFieldInit))
                    continue;
                var index = method.Body.Instructions.IndexOf(instruction);
                if ((initialize.Length != 0 || forward.InnerOpCode == OpCodes.Nop) && index > 0 &&
                    method.Body.Instructions[index - 1].OpCode.OpCodeType == OpCodeType.Prefix)
                    continue;
                transaction.Capture(method);
                instruction.OpCode = forward.InnerOpCode;
                instruction.Operand = forward.InnerOpCode == OpCodes.Nop ? null : target;
                if (initialize.Length != 0)
                {
                    // Keep the original instruction as the branch/EH entry. Arguments have
                    // already been evaluated, exactly as before the wrapper's static call.
                    var call = new Instruction(instruction.OpCode, instruction.Operand);
                    instruction.OpCode = OpCodes.Ldtoken;
                    instruction.Operand = definition.DeclaringType;
                    var helpers = new TypeRefUser(context.Module, "System.Runtime.CompilerServices",
                        "RuntimeHelpers", context.Module.CorLibTypes.AssemblyRef);
                    var handle = new ValueTypeSig(new TypeRefUser(context.Module, "System",
                        "RuntimeTypeHandle", context.Module.CorLibTypes.AssemblyRef));
                    var ensure = new MemberRefUser(context.Module, "RunClassConstructor",
                        MethodSig.CreateStatic(context.Module.CorLibTypes.Void, handle), helpers);
                    method.Body.Instructions.Insert(index + 1, OpCodes.Call.ToInstruction(ensure));
                    method.Body.Instructions.Insert(index + 2, call);
                    method.Body.KeepOldMaxStack = false;
                    method.Body.SimplifyBranches();
                }
                changes++;
                // The whole chain is skipped, not just its first link.
                bypassed.UnionWith(forward.Chain);
                transaction.RecordChange(context, new ChangeRecord(
                    Name,
                    "inline-forwarder",
                    $"{method.MDToken} IL_{instruction.Offset:X4}",
                    forward.InnerOpCode == OpCodes.Nop
                        ? $"Removed a call to loader-emptied helper {definition.MDToken}, preserving required initialization."
                        : $"Redirected forwarder {definition.MDToken} to {forward.Target.MDToken}."));
            }
        }
        if (changes == 0)
            return (PassStatus.Success, 0, ["No reachable forwarder call site required redirection."]);

        var verification = AssemblyVerifier.Verify(
            context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
                ["Forwarder inlining failed verification and was rolled back."]);
        }
        transaction.Commit();
        // A forwarder exists to be called; every call it had now goes straight to the target.
        RecoveryOrphans.Declare(context, bypassed);
        context.TryGetFact<int>("inlining.redirected", out var previous);
        context.SetFact("inlining.redirected", previous + changes);
        return (PassStatus.Success, changes,
        [
            $"Rewrote {changes} forwarder call site(s), preserving required type initialization.",
            $"{bypassed.Count} forwarder(s) were left with nothing to forward."
        ]);
    }

    private static bool HasGenericOwner(TypeDef type) =>
        type.HasGenericParameters || type.DeclaringType is { } parent && HasGenericOwner(parent);

    private static IMethod BindTarget(IMethod target, GenericScope? scope, ModuleDef module)
    {
        if (scope is null) return target;
        if (target is MethodSpec specification)
            return new MethodSpecUser((IMethodDefOrRef)BindTarget(specification.Method, scope, module),
                new GenericInstMethodSig(specification.GenericInstMethodSig.GenericArguments
                    .Select(argument => scope.Bind(argument)!).ToArray()));
        if (target.DeclaringType is TypeSpec owner)
            return new MemberRefUser(module, target.Name, target.MethodSig,
                new TypeSpecUser(scope.Bind(owner.TypeSig)!));
        return target;
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
        // Keep the immediate edges unchanged while walking. Reading an already-collapsed entry
        // would lose intermediate owners, including the access context of the final call.
        var immediateTargets = new Dictionary<MethodDef, ForwardTarget>(forwarders);
        foreach (var (forwarder, immediate) in immediateTargets)
        {
            var chain = new List<MethodDef> { forwarder };
            var seen = new HashSet<MethodDef> { forwarder };
            var final = immediate;
            while (final.Target.ResolveMethodDef() is { } next &&
                   seen.Add(next) &&
                   immediateTargets.TryGetValue(next, out var onward) &&
                   !HasGenericOwner(next.DeclaringType) &&
                   CanSkipInitializer(next, forwarder) &&
                   ArgumentsPassStraightThrough(forwarder, onward.Target, onward.InnerOpCode) &&
                   ReturnTypeSurvives(forwarder, onward.Target, onward.InnerOpCode))
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
            method.IsStaticConstructor ||
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
        if (call.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj) ||
            call.Operand is not IMethod target ||
            target.ResolveMethodDef() == method ||
            body[^1].OpCode.Code != Code.Ret)
        {
            return null;
        }
        if (!ArgumentsPassStraightThrough(method, target, call.OpCode) ||
            !ReturnTypeSurvives(method, target, call.OpCode))
        {
            return null;
        }
        return new ForwardTarget(target, call.OpCode, []);
    }

    private static bool CanSkipInitializer(MethodDef forwarder, MethodDef caller) =>
        // A static caller in the same type already has the wrapper's initialization semantics.
        // An instance method can be entered on an uninitialized object, so it gets no exemption.
        (caller.IsStatic && forwarder.DeclaringType == caller.DeclaringType) ||
        !forwarder.DeclaringType.Methods.Any(initializer =>
            initializer.IsStaticConstructor && !EmptyTypeInitializers.DoesNothing(initializer));

    /// <summary>Moving a call must not give its new owner less access than the wrapper had.</summary>
    private static bool CanAccessTarget(MethodDef caller, MethodDef forwarder, IMethod target)
    {
        // Within the same type the access context is unchanged, even for an unresolved reference.
        if (caller.DeclaringType == forwarder.DeclaringType)
            return true;
        if (target.ResolveMethodDef() is not { } definition)
            return false;
        if (caller.DeclaringType == definition.DeclaringType)
            return true;

        var sameModule = caller.Module == definition.Module;
        if (!definition.IsPublic &&
            !(sameModule && (definition.IsAssembly || definition.IsFamilyOrAssembly)))
        {
            // Family access also constrains the receiver. Leave those calls wrapped unless the
            // assembly access above suffices; neither inheritance nor friendship is guessed here.
            return false;
        }
        for (var type = definition.DeclaringType; type is not null; type = type.DeclaringType)
        {
            if (!type.IsNested)
                return type.IsPublic || sameModule;
            if (!type.IsNestedPublic &&
                !(sameModule && (type.IsNestedAssembly || type.IsNestedFamilyOrAssembly)))
            {
                return false;
            }
        }
        return false;
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
    private static bool ArgumentsPassStraightThrough(MethodDef forwarder, IMethod target, OpCode inner)
    {
        var forwarded = forwarder.MethodSig!.Params;
        var expected = new List<TypeSig?>();
        // A constructor declares an instance it is never handed here: newobj makes the object it
        // then initializes, so the forwarder's parameters line up with the constructor's alone.
        if (target.MethodSig?.HasThis == true && inner.Code != Code.Newobj)
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
    private static bool ReturnTypeSurvives(MethodDef forwarder, IMethod target, OpCode inner)
    {
        var promised = forwarder.MethodSig?.RetType;
        // What newobj leaves on the stack is the constructed object, not the void its constructor
        // declares, so that is what the forwarder's callers have to be able to accept.
        var actual = inner.Code == Code.Newobj
            ? target.DeclaringType?.ToTypeSig()
            : target.MethodSig?.RetType;
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

/// <summary>Reconsiders wrappers after loader elision, preserving required initialization explicitly.</summary>
public sealed class MethodInliningRecheckPass : MethodInliningPass
{
    protected override bool PreserveInitializerCalls => true;
    public override string Name => "method-inlining-recheck";
    public override IReadOnlyCollection<string> Dependencies => ["method-inlining", "loader-call-elision"];
}
