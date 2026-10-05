using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>Assembly objects observed in a bounded machine, never assemblies of the host process.</summary>
internal static class AppDomainAssemblyInventory
{
    private const string Loads = "ObservedAssemblyLoads";
    private const string Complete = "ClosedAssemblyInventoryFixture";

    internal static bool RecordLoad(StaticMachineState state, StaticValue assembly)
    {
        if (!state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain)) return false;
        if (!state.Heap.TryGetModelValue(domain, Loads, out List<StaticValue>? values) || values is null)
        {
            values = [];
            if (!state.Heap.TrySetModelValue(domain, Loads, values)) return false;
        }
        values.Add(assembly);
        return true;
    }

    // This is an explicit test world. A list of observed loads alone cannot establish
    // the complete inventory of an actual application domain.
    internal static bool BeginClosedFixture(StaticMachineState state, StaticValue home)
    {
        if (!state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain)) return false;
        if (!state.Heap.TryGetModelValue(domain, Loads, out List<StaticValue>? values) || values is null)
        {
            values = [];
            if (!state.Heap.TrySetModelValue(domain, Loads, values)) return false;
        }
        if (!values.Contains(home)) values.Insert(0, home);
        return state.Heap.TrySetModelValue(domain, Complete, true);
    }

    internal static IntrinsicResult Read(StaticMachineState state, StaticValue domain)
    {
        if (!state.Heap.TryGetModelValue(domain, Complete, out bool complete) || !complete ||
            !state.Heap.TryGetModelValue(domain, Loads, out List<StaticValue>? values) || values is null)
            return IntrinsicResult.Unknown("AppDomain.GetAssemblies requires a complete declared assembly inventory; observed loads alone are insufficient.");
        if (state.ModuleMetadata is not { } module)
            return IntrinsicResult.Unknown("Assembly inventory requires module metadata for its array element type.");
        if (!state.Heap.TryAllocateArray(module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly").ToTypeSig(), values.Count, out var array))
            return IntrinsicResult.Unknown("Assembly inventory array allocation failed.");
        for (var index = 0; index < values.Count; index++)
            if (!state.Heap.TryWriteArray(array, index, values[index]))
                return IntrinsicResult.Unknown("Assembly inventory array element could not be stored.");
        return IntrinsicResult.Completed(array);
    }
}
