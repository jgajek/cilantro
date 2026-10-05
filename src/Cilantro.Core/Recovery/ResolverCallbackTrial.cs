using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cilantro.Core.Recovery;

/// <summary>Exercises finite resolver requests; it never raises a host CLR event or loads a payload.</summary>
internal static class ResolverCallbackTrial
{
    internal static bool Exercise(StaticMachine machine, ModuleDef module, StaticWorkBudget budget,
        uint? engineToken, IReadOnlyList<StaticValue> retained, Dictionary<object, int> metadata,
        out List<(string Name, StaticValue Value)> observed, out string diagnostic)
    {
        observed = [];
        diagnostic = "";
        var heap = machine.State.Heap;
        if (!machine.State.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain) ||
            !machine.State.TryGetOrAllocateRuntimeSingleton("System.Reflection.Assembly", out var home))
            return Fail("resolver fixture allocation failed", out diagnostic);
        heap.TrySetModelValue(home, LoaderFrameworkIntrinsic.HomeModuleMark, true);
        if (!AppDomainAssemblyInventory.BeginClosedFixture(machine.State, home))
            return Fail("closed assembly-inventory fixture could not be initialized", out diagnostic);
        var engine = (engineToken is { } token ? module.ResolveToken(token) as IMethod : null)?.ResolveMethodDef()?.DeclaringType;
        bool VmOwned(TypeDef? type) => engine is not null && type is not null && (type == engine || VmOwned(type.DeclaringType));
        var fields = module.GetTypes().SelectMany(type => type.Fields).Where(field => field.IsStatic).OrderBy(field => field.FullName, StringComparer.Ordinal).ToArray();
        var requests = 0;
        var invocations = 0;
        foreach (var kind in new[] { "AssemblyResolve", "ResourceResolve" })
        {
            var names = (kind == "AssemblyResolve"
                    ? module.GetAssemblyRefs().Select(reference => reference.FullName).Append(module.Assembly?.FullName ?? module.Name.String)
                    : module.Resources.Select(resource => resource.Name.String))
                .Append("Cilantro.MissingResolverFixture").Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (names.Length > 64) return Fail($"{kind} has {names.Length} fixture names; limit is 64", out diagnostic);
            foreach (var name in names)
            foreach (var requester in new[] { StaticValue.Null, home })
            {
                if (!heap.TryAllocateObject("System.ResolveEventArgs", out var args) ||
                    !heap.TryAllocateString(name, out var requested))
                    return Fail("resolver event arguments could not be allocated", out diagnostic);
                heap.TrySetModelValue(args, "Name", requested);
                heap.TrySetModelValue(args, "RequestingAssembly", requester);
                heap.TryGetModelValue(domain, "Event:" + kind, out List<StaticValue>? handlers);
                var answer = IntrinsicResult.Completed(StaticValue.Null);
                // Match CLR resolution ordering; mutations affect the next request.
                foreach (var handler in handlers?.ToArray() ?? [])
                {
                    if (++invocations > 512) return Fail("resolver callback invocation limit exceeded", out diagnostic);
                    answer = machine.InvokeCallback(handler, [domain, args], budget);
                    if (answer.Status is not (StaticExecutionStatus.Completed or StaticExecutionStatus.Threw))
                        return Fail($"{kind} request '{name}' stopped: {answer.Status}: {answer.Diagnostic}", out diagnostic);
                    if (answer.Status == StaticExecutionStatus.Threw || answer.Value.Kind != StaticValueKind.Null) break;
                }
                var label = $"resolver request {requests++} ({kind}, {name}, requester={(requester.Kind == StaticValueKind.Null ? "null" : "home")})";
                observed.Add((label + " arguments", args));
                observed.Add((label + " outcome", StaticValue.FromInt32((int)answer.Status)));
                observed.Add((label + " result/exception", answer.Value));
                // Record each response before a later handler can overwrite its effects.
                // Final snapshots also retain all returned objects to check cross-request aliases.
                var snapshot = new RebuiltMethodTrial.Snapshot(heap, metadata);
                var values = retained.Concat(observed.Select(root => root.Value))
                    .Concat(fields.Where(field => !VmOwned(field.DeclaringType)).Select(machine.State.ReadStaticField))
                    .Select(snapshot.Read).ToList();
                values.Add(snapshot.ReadNetworkSettings(machine.State));
                values.Add(snapshot.ReadDomainState(machine.State));
                if (values.Any(value => value is null)) return Fail("resolver response snapshot failed: " + snapshot.Failure, out diagnostic);
                if (snapshot.MetadataHandles.Any(handle => handle switch {
                    IMethod method => VmOwned(method.ResolveMethodDef()?.DeclaringType),
                    IField field => VmOwned(field.ResolveFieldDef()?.DeclaringType),
                    ITypeDefOrRef type => VmOwned(type.ResolveTypeDef()), _ => false }))
                    return Fail("resolver response exposes VM metadata", out diagnostic);
                var vm = new RebuiltMethodTrial.Snapshot(heap, metadata);
                if (fields.Where(field => VmOwned(field.DeclaringType)).Select(field => vm.Read(machine.State.ReadStaticField(field))).Any(value => value is null))
                    return Fail("resolver VM-state snapshot failed: " + vm.Failure, out diagnostic);
                if (vm.SharesCapturedObjectsWith(snapshot)) return Fail("resolver response may share VM state", out diagnostic);
                var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(values))));
                if (!heap.TryAllocateString(digest, out var captured)) return Fail("resolver response digest allocation failed", out diagnostic);
                observed.Add((label + " immediate application snapshot", captured));
            }
        }
        diagnostic = $"Resolver fixtures exercised {requests} ordered requests and {invocations} callbacks using declared assembly/resource names and a missing name, with null/home requesters and a closed inventory of the home assembly plus observed loads; other names, callers and preloaded assemblies remain untested.";
        return true;
    }

    private static bool Fail(string reason, out string diagnostic) { diagnostic = reason; return false; }
}
