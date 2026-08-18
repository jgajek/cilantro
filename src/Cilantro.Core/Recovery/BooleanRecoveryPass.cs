using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Strings;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Recovers Reactor's encrypted booleans by statically evaluating the real resolver.
/// </summary>
/// <remarks>
/// Reactor's boolean protection mirrors its string protection: a single static
/// <c>bool(int32)</c> resolver reads a resource-backed table and returns the plaintext value for a
/// per-site offset. Rather than reimplement the codec, this pass proves each call site's offset
/// with the shared slicer and then interprets the actual resolver body under the bounded machine,
/// seeded exactly as method-body recovery seeds it, to obtain the concrete boolean. Evaluating the
/// genuine decoder is what makes the result correct by construction rather than a guess.
///
/// Determinism is required: each offset is evaluated on two independently seeded machines and the
/// two results must agree, otherwise the site stays unproven and the whole rewrite is abandoned.
/// The rewrite is all-or-nothing and atomic, replacing each proven call with <c>ldc.i4.0</c> or
/// <c>ldc.i4.1</c> under a body transaction that rolls back unless verification passes.
/// </remarks>
public sealed class BooleanRecoveryPass : DeobfuscationPass
{
    public override string Name => "boolean-recovery";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var resolvers = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(IsBooleanResolver)
            .ToArray();
        if (resolvers.Length == 0)
            return (PassStatus.Success, 0, ["No protected boolean resolver was detected."]);
        if (resolvers.Length != 1)
        {
            return (PassStatus.Partial, 0,
                [$"Detected {resolvers.Length} ambiguous boolean resolvers; no call site was modified."]);
        }
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete)
        {
            return (PassStatus.Partial, 0,
            [
                "Boolean recovery was deferred because method-body recovery is not complete.",
                "No boolean call site was modified."
            ]);
        }

        var resolver = resolvers[0];
        var integerFields = LoadIntegerFields(context);
        var callSites = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions
                .Select((instruction, index) => (Method: method, Instruction: instruction, Index: index)))
            .Where(item => item.Instruction.OpCode.Code is Code.Call or Code.Callvirt &&
                item.Instruction.Operand is IMethod called &&
                called.ResolveMethodDef() == resolver)
            .ToArray();
        if (callSites.Length == 0)
            return (PassStatus.Success, 0, ["No reachable boolean resolver call sites were found."]);

        var offsets = new List<(MethodDef Method, Instruction Call, int Offset)>();
        foreach (var site in callSites)
        {
            if (!StringOffsetSlicer.TryEvaluate(
                    site.Method, site.Index, integerFields, out var offset, out var sliceDiagnostic))
            {
                return (PassStatus.Partial, 0,
                [
                    $"Could not prove boolean resolver argument at {site.Method.MDToken} " +
                    $"IL_{site.Instruction.Offset:X4}: {sliceDiagnostic}.",
                    "No boolean call site was modified."
                ]);
            }
            offsets.Add((site.Method, site.Instruction, offset));
        }

        var distinctOffsets = offsets.Select(item => item.Offset).Distinct().ToArray();
        var evaluated = new Dictionary<int, bool>();
        foreach (var offset in distinctOffsets)
        {
            if (!TryEvaluateResolver(context, resolver, offset, out var first, out var evalDiagnostic) ||
                !TryEvaluateResolver(context, resolver, offset, out var second, out _) ||
                first != second)
            {
                return (PassStatus.Partial, 0,
                [
                    $"Could not deterministically evaluate the boolean resolver at offset {offset}: " +
                    $"{evalDiagnostic}.",
                    "No boolean call site was modified."
                ]);
            }
            evaluated[offset] = first;
        }

        var transactions = offsets.Select(item => item.Method)
            .Distinct()
            .ToDictionary(method => method, method => new BodyMutationTransaction(method));
        try
        {
            foreach (var site in offsets)
            {
                var instructions = site.Method.Body.Instructions;
                var callIndex = instructions.IndexOf(site.Call);
                if (callIndex < 0)
                    throw new InvalidOperationException("A boolean resolver call moved during rewrite.");
                instructions.Insert(callIndex, Instruction.Create(OpCodes.Pop));
                site.Call.OpCode = evaluated[site.Offset] ? OpCodes.Ldc_I4_1 : OpCodes.Ldc_I4_0;
                site.Call.Operand = null;
            }
            var remaining = context.Module.GetTypes()
                .SelectMany(type => type.Methods)
                .Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions)
                .Count(instruction => instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() == resolver);
            if (remaining != 0)
                throw new InvalidOperationException(
                    $"{remaining} boolean resolver reference(s) remained after rewrite.");
            var verification = AssemblyVerifier.Verify(
                context.Module, context.OriginalIdentity, context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            foreach (var transaction in transactions.Values)
                transaction.Commit();
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException)
        {
            foreach (var transaction in transactions.Values)
                transaction.Rollback();
            return (PassStatus.Failed, 0,
                [$"Atomic boolean rewrite was rolled back: {exception.Message}"]);
        }
        finally
        {
            foreach (var transaction in transactions.Values)
                transaction.Dispose();
        }

        foreach (var site in offsets)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "restore-boolean",
                $"{site.Method.MDToken} IL_{site.Call.Offset:X4}",
                evaluated[site.Offset] ? "true" : "false"));
        }
        context.SetFact("booleans.callSites", offsets.Count);
        context.SetFact("booleans.replacedSites", offsets.Count);
        // Every call the resolver existed to answer is now the constant it would have returned,
        // which leaves the table it consulted with nothing to answer from.
        RecoveryOrphans.DeclareSubtree(context, [resolver]);
        return (PassStatus.Success, offsets.Count,
            [$"Atomically restored all {offsets.Count} proven boolean site(s)."]);
    }

    private static bool IsBooleanResolver(MethodDef method) =>
        method.HasBody &&
        method.IsStatic &&
        method.ReturnType.ElementType == ElementType.Boolean &&
        method.MethodSig?.Params.Count == 1 &&
        method.MethodSig.Params[0].ElementType == ElementType.I4 &&
        (method.Body.Instructions.Any(instruction =>
            instruction.Operand is IMethod called && called.Name == "GetManifestResourceStream") ||
         method.Body.Instructions.Any(instruction =>
            instruction.OpCode.Code == Code.Ldsfld &&
            instruction.Operand is IField field &&
            field.FieldSig?.Type.ElementType is ElementType.SZArray or ElementType.Object));

    private static IReadOnlyDictionary<uint, int> LoadIntegerFields(ArtifactContext context) =>
        context.TryGetFact<CapturedStringTable>("strings.table", out var table) && table is not null
            ? table.IntegerFields
            : new Dictionary<uint, int>();

    /// <summary>
    /// Seeds a bounded machine like method-body recovery and invokes the resolver at one offset.
    /// </summary>
    private static bool TryEvaluateResolver(
        ArtifactContext context,
        MethodDef resolver,
        int offset,
        out bool value,
        out string diagnostic)
    {
        value = false;
        if (!BootstrapMachine.TryRunInitializers(context, 2_000_000, out var machine, out diagnostic) ||
            machine is null)
        {
            return false;
        }

        var result = machine.Execute(resolver, [StaticValue.FromInt32(offset)]);
        if (!result.Succeeded || result.Value.Kind != StaticValueKind.Int32)
        {
            diagnostic = result.Diagnostic ?? result.Status.ToString();
            return false;
        }
        value = result.Value.AsInt32() != 0;
        return true;
    }
}
