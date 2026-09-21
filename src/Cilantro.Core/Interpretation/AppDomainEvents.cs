using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>Ordered subscriptions of supported, single-target managed delegates.</summary>
internal static class AppDomainEvents
{
    internal static IntrinsicResult Update(StaticHeap heap, StaticValue domain, string name,
        StaticValue handler, bool add)
    {
        var key = $"Event:{name}";
        heap.TryGetModelValue(domain, key, out List<StaticValue>? previous);
        var next = previous is null ? new List<StaticValue>() : new List<StaticValue>(previous);
        if (handler.Kind != StaticValueKind.Null)
        {
            if (!heap.TryGetModelValue(handler, StaticMachine.DelegateMethodKey, out IMethod? method) ||
                method is null ||
                !heap.TryGetModelValue(handler, StaticMachine.DelegateTargetKey, out StaticValue target) ||
                target.Kind == StaticValueKind.Unknown)
                return IntrinsicResult.Invalid("Application-domain event handler is not a modeled managed delegate.");
            if (add)
            {
                if (next.Count >= 4096)
                    return IntrinsicResult.Invalid("Application-domain event subscription limit exceeded.");
                next.Add(handler);
            }
            else
            {
                // CLR delegate equality uses delegate type, method, target, and binding form.
                for (var i = next.Count - 1; i >= 0; i--)
                {
                    var candidate = next[i];
                    if (!heap.TryGetModelValue(candidate, StaticMachine.DelegateMethodKey, out IMethod? other) ||
                        !heap.TryGetModelValue(candidate, StaticMachine.DelegateTargetKey, out StaticValue receiver) ||
                        !heap.TryGetRuntimeTypeName(candidate, out var candidateType) ||
                        !heap.TryGetRuntimeTypeName(handler, out var handlerType))
                        return IntrinsicResult.Invalid("Application-domain event delegate equality is unavailable.");
                    heap.TryGetModelValue(candidate, StaticMachine.DelegateOpenKey, out bool candidateOpen);
                    heap.TryGetModelValue(handler, StaticMachine.DelegateOpenKey, out bool handlerOpen);
                    if (candidateType == handlerType && target == receiver && candidateOpen == handlerOpen &&
                        new SigComparer().Equals(method, other))
                    {
                        next.RemoveAt(i);
                        break;
                    }
                }
            }
        }
        return heap.TrySetModelValue(domain, key, next)
            ? IntrinsicResult.Completed()
            : IntrinsicResult.Invalid("Application-domain event receiver is not modeled.");
    }
}
