using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Cilantro.Core.Verification;

namespace Cilantro.Core;

public sealed record VerificationResult(bool Passed, IReadOnlyList<string> Diagnostics);

public static class AssemblyVerifier
{
    public static VerificationResult Verify(
        ModuleDef module,
        ArtifactIdentitySnapshot? originalIdentity = null,
        ArtifactStructuralSnapshot? originalStructure = null,
        RewriteAllowance? allowance = null)
    {
        var diagnostics = new List<string>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            var instructionSet = instructions.ToHashSet();
            var invalidBoundaries = false;
            foreach (var instruction in instructions)
            {
                if (instruction.Operand is Instruction target && !instructionSet.Contains(target))
                {
                    diagnostics.Add($"{method.MDToken}: branch target is outside the method.");
                    invalidBoundaries = true;
                }
                else if (instruction.Operand is IList<Instruction> targets &&
                         targets.Any(target => !instructionSet.Contains(target)))
                {
                    diagnostics.Add($"{method.MDToken}: switch target is outside the method.");
                    invalidBoundaries = true;
                }
            }

            foreach (var handler in method.Body.ExceptionHandlers)
            {
                VerifyBoundary(handler.TryStart, "try start");
                VerifyBoundary(handler.TryEnd, "try end", allowEndOfMethod: true);
                VerifyBoundary(handler.HandlerStart, "handler start");
                VerifyBoundary(handler.HandlerEnd, "handler end", allowEndOfMethod: true);
                if (handler.FilterStart is not null)
                    VerifyBoundary(handler.FilterStart, "filter start");
            }

            // Reachability assumes all targets belong to the body. Preserve the diagnostic
            // above instead of throwing while trying to walk an already-invalid graph.
            if (invalidBoundaries)
                continue;
            var reachable = CfgDeadCodePass.ComputeReachable(method);
            var invalidReachableCalls = reachable.Count(instruction =>
                instruction.OpCode.FlowControl == FlowControl.Call && instruction.Operand is null);
            if (invalidReachableCalls != 0)
            {
                diagnostics.Add($"{method.MDToken}: {invalidReachableCalls} reachable calls have invalid operands.");
            }

            void VerifyBoundary(
                Instruction? boundary,
                string kind,
                bool allowEndOfMethod = false)
            {
                if (boundary is null && allowEndOfMethod)
                    return;
                if (boundary is not null && instructionSet.Contains(boundary))
                    return;
                diagnostics.Add($"{method.MDToken}: {kind} is outside the method.");
                invalidBoundaries = true;
            }
        }

        if (originalIdentity is not null)
        {
            var effective = allowance ?? RewriteAllowance.None;
            var current = ArtifactIdentitySnapshot.Capture(module);
            if (current.EntryPointToken != originalIdentity.EntryPointToken)
                diagnostics.Add("Entry point token changed during rewriting.");
            if (current.StrongNameSigned != originalIdentity.StrongNameSigned)
                diagnostics.Add("Strong-name signed state changed during rewriting.");
            if (!ApiMatches(originalIdentity.PublicApi, current.PublicApi, effective))
                diagnostics.Add("Public API changed during rewriting.");
            if (!SetMatches(
                    originalIdentity.ResourceNames, current.ResourceNames,
                    effective.AddedResourceSet, effective.RemovedResourceSet))
                diagnostics.Add("Embedded resource set changed during rewriting.");
        }

        if (originalStructure is not null)
        {
            var effective = allowance ?? RewriteAllowance.None;
            var current = ArtifactStructuralSnapshot.Capture(module);
            var removedMethods = effective.RemovedMethodTokenSet;
            var resourceDelta = effective.AddedResourceSet.Count - effective.RemovedResourceSet.Count;
            var typeDelta = effective.AddedTypeCount - effective.RemovedTypeCount;
            if (current.TypeCount != originalStructure.TypeCount + typeDelta)
                diagnostics.Add("Type count changed during rewriting.");
            if (current.MethodCount !=
                originalStructure.MethodCount - removedMethods.Count + effective.AddedMethodCount)
            {
                diagnostics.Add("Method count changed during rewriting.");
            }
            if (current.FieldCount != originalStructure.FieldCount - effective.RemovedFieldCount)
                diagnostics.Add("Field count changed during rewriting.");
            if (current.ResourceCount != originalStructure.ResourceCount + resourceDelta)
                diagnostics.Add("Resource count changed during rewriting.");
            if (!MethodTokensMatch(
                    originalStructure.MethodRvas.Keys, current.MethodRvas.Keys, removedMethods))
            {
                diagnostics.Add("Method token set changed during rewriting.");
            }
        }

        return new VerificationResult(diagnostics.Count == 0, diagnostics);
    }

    /// <summary>
    /// Confirms the methods that had a row are exactly the original set less what was declared
    /// removed.
    /// </summary>
    /// <remarks>
    /// Methods the run added are absent from both sides and are checked by their number instead.
    /// A method built here has no row until the writer gives it one, so it has no token to be
    /// compared by — every one of them reads as the zero row of the method table, which is why
    /// naming them was only ever possible while there was one.
    /// </remarks>
    private static bool MethodTokensMatch(
        IEnumerable<uint> original,
        IEnumerable<uint> current,
        IReadOnlySet<uint> removed)
    {
        var expected = new HashSet<uint>(original);
        expected.ExceptWith(removed);
        return expected.SetEquals(current);
    }

    /// <summary>
    /// Confirms the current set equals the original plus declared additions minus declared removals.
    /// </summary>
    private static bool SetMatches(
        IReadOnlyList<string> original,
        IReadOnlyList<string> current,
        IReadOnlySet<string> added,
        IReadOnlySet<string> removed)
    {
        var expected = new HashSet<string>(original, StringComparer.Ordinal);
        foreach (var name in removed)
            expected.Remove(name);
        foreach (var name in added)
            expected.Add(name);
        return expected.SetEquals(current);
    }

    /// <summary>
    /// Confirms the public API changed only by the declared removals, additions, and renames.
    /// </summary>
    private static bool ApiMatches(
        IReadOnlyList<string> original,
        IReadOnlyList<string> current,
        RewriteAllowance allowance)
    {
        if (allowance.RemovedPublicApiSet.Count == 0 &&
            allowance.AddedPublicApiSet.Count == 0 &&
            allowance.RenamedPublicApiMap.Count == 0)
        {
            return current.SequenceEqual(original, StringComparer.Ordinal);
        }

        var expected = new HashSet<string>(original, StringComparer.Ordinal);
        foreach (var removed in allowance.RemovedPublicApiSet)
            expected.Remove(removed);
        foreach (var rename in allowance.RenamedPublicApiMap)
        {
            if (expected.Remove(rename.Key))
                expected.Add(rename.Value);
        }
        foreach (var added in allowance.AddedPublicApiSet)
            expected.Add(added);
        return expected.SetEquals(current);
    }

    public static VerificationResult VerifyFile(
        string path,
        ArtifactIdentitySnapshot? originalIdentity = null,
        ArtifactStructuralSnapshot? originalStructure = null,
        RewriteAllowance? allowance = null)
    {
        try
        {
            using var module = ModuleDefMD.Load(path);
            return Verify(module, originalIdentity, originalStructure, allowance);
        }
        catch (Exception ex)
        {
            return new VerificationResult(false, [$"Reload failed: {ex.Message}"]);
        }
    }

    /// <summary>
    /// Confirms the file on disk is the module that was in memory, and that it still reloads with
    /// sound method bodies.
    /// </summary>
    /// <remarks>
    /// This deliberately compares against the transformed module rather than the original. The
    /// in-memory gate has already established that the module differs from the original only by
    /// what the passes declared; establishing that the file matches that module carries the
    /// conclusion through to disk, and it is the only form the check can take once deletions have
    /// made the writer renumber tokens.
    /// </remarks>
    public static VerificationResult VerifyRoundTrip(string path, ModuleShape expected)
    {
        try
        {
            using var module = ModuleDefMD.Load(path);
            var diagnostics = new List<string>(Verify(module).Diagnostics);
            diagnostics.AddRange(expected.DifferencesFrom(ModuleShape.Capture(module)));
            return new VerificationResult(diagnostics.Count == 0, diagnostics);
        }
        catch (Exception ex)
        {
            return new VerificationResult(false, [$"Reload failed: {ex.Message}"]);
        }
    }
}
