using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Drops Reactor's resource-resolve hook once the module carries the resources it served.
/// </summary>
/// <remarks>
/// The hook answers <see cref="AppDomain.ResourceResolve"/> by returning a satellite assembly it
/// decrypts from an embedded bundle. Once resource restoration has lifted that satellite's streams
/// onto the module, the hook cannot be reached: the runtime raises <c>ResourceResolve</c> only after
/// its own lookup fails, and the names it would have been asked for are exactly the ones now
/// present. So the subscription is not merely unused, it is unreachable, and removing it changes
/// nothing a program can observe.
///
/// The edit is the subscription itself rather than the loader entry point that performs it. Reactor
/// injects a call to that entry point at the head of every type initializer in the module, so
/// eliding it would mean reasoning about a method that runs everywhere; the five instructions that
/// build the delegate and add it to the event are self-contained, stack-neutral, and provable where
/// they stand. Taking them out leaves the handler with no reference, which is what lets attribution
/// account for the decryptor, cipher, and reader behind it and cleanup take the whole apparatus.
///
/// Every precondition is a way the hook could still matter. If any bundle went unrecovered, or a
/// resource still looks like an unextracted assembly payload, then something is being served that
/// the module does not have, and the pass declines.
/// </remarks>
public sealed class ResourceHookElisionPass : DeobfuscationPass
{
    public override string Name => "resource-hook-elision";
    public override IReadOnlyCollection<string> Dependencies => ["resource-restoration"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlySet<string>>("resources.addedResources", out var restored) ||
            restored is null || restored.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No resource was reattached, so the resolve hook still serves the only copy."]);
        }
        if (!context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var roles) ||
            roles is null)
        {
            return (PassStatus.Success, 0, ["No resource-role analysis is available."]);
        }
        if (roles.Any(role => role.Role == ResourceRole.ManagedPayload))
        {
            return (PassStatus.Unsupported, 0,
            [
                "A resource is still attributed as an unextracted managed payload.",
                "The resolve hook may serve it, so the subscription was left in place."
            ]);
        }

        var subscriptions = Subscriptions(context.Module);
        if (subscriptions.Length == 0)
            return (PassStatus.Success, 0, ["No resource-resolve subscription was found to elide."]);

        var handlers = subscriptions.Select(item => item.Handler).Distinct().ToArray();
        var transactions = subscriptions
            .Select(item => item.Method)
            .Distinct()
            .ToDictionary(method => method, method => new BodyMutationTransaction(method));
        try
        {
            foreach (var subscription in subscriptions)
            {
                foreach (var instruction in subscription.Sequence)
                {
                    instruction.OpCode = OpCodes.Nop;
                    instruction.Operand = null;
                }
            }
            // Restoration has already reattached resources by this point, so the gate has to be
            // told what the earlier pass declared or it reads that addition as this pass's damage.
            var verification = AssemblyVerifier.Verify(
                context.Module,
                context.OriginalIdentity,
                context.OriginalStructure,
                ReactorPipeline.BuildRewriteAllowance(context));
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
                [$"Resource-hook elision was rolled back: {exception.Message}"]);
        }
        finally
        {
            foreach (var transaction in transactions.Values)
                transaction.Dispose();
        }

        foreach (var subscription in subscriptions)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "elide-resource-hook",
                $"{subscription.Method.MDToken} IL_{subscription.Sequence[0].Offset:X4}",
                $"Removed the ResourceResolve subscription of {subscription.Handler.Name}."));
        }
        context.AddEvidence(new Evidence(
            "resource-hook-elided",
            $"Dropped {subscriptions.Length} resource-resolve subscription(s) made redundant by " +
            $"{restored.Count} reattached resource(s).",
            string.Join("; ", handlers.Select(handler => handler.FullName)),
            0.95));
        // The handler is the only reason the bundle's decryptor, cipher, and reader are in the
        // module, and the accessors on the handler's own type exist to serve it. Naming more than
        // strictly lost its caller is safe here because attribution never removes anything on its
        // own; whatever the module still reaches, reachability keeps.
        RecoveryOrphans.DeclareSubtree(context, handlers);
        RecoveryOrphans.DeclareSubtree(context, handlers
            .SelectMany(handler => Nest(handler.DeclaringType))
            .SelectMany(type => type.Methods));
        context.SetFact("resources.elidedHooks", subscriptions.Length);
        return (PassStatus.Success, subscriptions.Length,
        [
            $"Elided {subscriptions.Length} resource-resolve subscription(s) that the " +
            $"{restored.Count} reattached resource(s) made unreachable."
        ]);
    }

    private sealed record Subscription(
        MethodDef Method,
        MethodDef Handler,
        IReadOnlyList<Instruction> Sequence);

    /// <summary>
    /// Finds every literal <c>AppDomain.CurrentDomain.ResourceResolve += handler</c> in the module.
    /// </summary>
    /// <remarks>
    /// The whole five-instruction sequence is matched, not just the event add, because the proof
    /// that removing it is safe is a stack argument: the sequence pushes the domain, the delegate
    /// target, and the function pointer, folds the last two into a handler, and consumes both. It is
    /// therefore stack-neutral and can be replaced in place with no-operations, which also leaves
    /// every branch target in the body pointing where it did.
    /// </remarks>
    private static Subscription[] Subscriptions(ModuleDef module) =>
        [.. module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions
                .Select((instruction, index) => (Method: method, Instruction: instruction, Index: index)))
            .Select(site => Match(site.Method, site.Index))
            .Where(subscription => subscription is not null)
            .Cast<Subscription>()];

    private static Subscription? Match(MethodDef method, int index)
    {
        var instructions = method.Body.Instructions;
        if (index < 4 ||
            instructions[index].OpCode.Code != Code.Callvirt ||
            instructions[index].Operand is not IMethod add ||
            add.Name != "add_ResourceResolve" ||
            add.DeclaringType?.FullName != "System.AppDomain")
        {
            return null;
        }

        var sequence = new[]
        {
            instructions[index - 4], instructions[index - 3], instructions[index - 2],
            instructions[index - 1], instructions[index]
        };
        if (sequence[0].OpCode.Code != Code.Call ||
            sequence[0].Operand is not IMethod currentDomain ||
            currentDomain.Name != "get_CurrentDomain" ||
            currentDomain.DeclaringType?.FullName != "System.AppDomain" ||
            sequence[1].OpCode.Code != Code.Ldnull ||
            sequence[2].OpCode.Code != Code.Ldftn ||
            sequence[2].Operand is not IMethod target ||
            sequence[3].OpCode.Code != Code.Newobj ||
            sequence[3].Operand is not IMethod handlerConstructor ||
            handlerConstructor.DeclaringType?.FullName != "System.ResolveEventHandler")
        {
            return null;
        }

        return target.ResolveMethodDef() is { } handler &&
            handler.Module == method.Module &&
            ResourceRoleAnalyzer.IsResourceResolveHandler(handler)
                ? new Subscription(method, handler, sequence)
                : null;
    }

    private static IEnumerable<TypeDef> Nest(TypeDef? type)
    {
        if (type is null)
            yield break;
        var outermost = type;
        while (outermost.DeclaringType is { } declaring)
            outermost = declaring;
        var pending = new Queue<TypeDef>([outermost]);
        while (pending.Count != 0)
        {
            var current = pending.Dequeue();
            yield return current;
            foreach (var nested in current.NestedTypes)
                pending.Enqueue(nested);
        }
    }
}
