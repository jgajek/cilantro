using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>
/// Runs an <c>async</c> method by driving its state machine to the end without ever waiting.
/// </summary>
/// <remarks>
/// <para>
/// An async method is a compiler-written state machine plus a builder that owns it: the method body
/// makes the machine, hands it to the builder to start, and returns the builder's task. Everything
/// the program actually wrote is in <c>MoveNext</c>, which is a method in the module like any other,
/// so it is interpreted rather than modeled. What is modeled is the four pieces around it — the
/// builder, the task, the awaiter, and what the awaiter says about whether the thing it waits for has
/// finished.
/// </para>
/// <para>
/// It says yes, always. Nothing here runs on another thread, so anything a task stands for has
/// already happened by the time the task exists: a request was refused or it was answered, a file was
/// read or it was not. An awaiter that reports finished sends <c>MoveNext</c> straight into the
/// continuation on the same call, which is exactly what the runtime does for a task that completed
/// before it was awaited — the compiler wrote that path and the program takes it. So the interpretation
/// runs the whole method, the ordering it would have had between threads is the one ordering it can
/// have, and a program whose behaviour depends on something else finishing first stops where it reads
/// a result that was never produced rather than proceeding on a made-up one.
/// </para>
/// <para>
/// This matters for recovery because a loader written today is usually async all the way down: the
/// method that fetches or decrypts the next stage is <c>async Task&lt;byte[]&gt;</c>, and refusing to
/// start one means refusing everything behind it, including the parts that never needed a thread.
/// </para>
/// </remarks>
public sealed class AsyncIntrinsic : IStaticIntrinsic
{
    private const string Result = "TaskResult";
    private const string Failure = "TaskException";
    private const string Produced = "TaskCompleted";

    private const string BuilderPrefix = "System.Runtime.CompilerServices.AsyncTaskMethodBuilder";
    private const string AwaiterPrefix = "System.Runtime.CompilerServices.TaskAwaiter";
    private const string ConfiguredPrefix = "System.Runtime.CompilerServices.ConfiguredTaskAwaitable";

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName is { } declaring &&
        (declaring is "System.Threading.Tasks.Task" or
            "System.Runtime.CompilerServices.AsyncVoidMethodBuilder" or
            "System.Runtime.CompilerServices.IAsyncStateMachine" ||
            declaring.StartsWith("System.Threading.Tasks.Task`1<", StringComparison.Ordinal) ||
            declaring.StartsWith(BuilderPrefix, StringComparison.Ordinal) ||
            declaring.StartsWith(AwaiterPrefix, StringComparison.Ordinal) ||
            declaring.StartsWith(ConfiguredPrefix, StringComparison.Ordinal));

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var heap = context.State.Heap;
        var name = method.Name.String;
        var declaring = method.DeclaringType?.FullName ?? string.Empty;
        var builder = declaring.StartsWith(BuilderPrefix, StringComparison.Ordinal) ||
            declaring == "System.Runtime.CompilerServices.AsyncVoidMethodBuilder";

        // A builder and a state machine are both structs, so a call on one arrives as a reference to
        // the slot holding it rather than as the thing itself.
        var self = arguments.Count > 0 ? Held(heap, arguments[0]) : StaticValue.Unknown;

        if (builder)
        {
            switch (name)
            {
                case "Create" when arguments.Count == 0:
                    return heap.TryAllocateObject(declaring, out var made)
                        ? IntrinsicResult.Completed(made)
                        : IntrinsicResult.Invalid("Could not allocate an async builder.");
                case "Start" when arguments.Count == 2:
                    return Advance(context, method, arguments[1], 0);
                case "AwaitOnCompleted" or "AwaitUnsafeOnCompleted" when arguments.Count == 3:
                    // The continuation is what runs once the awaited thing is done, and it is done,
                    // so this is where the rest of the method runs.
                    return Advance(context, method, arguments[2], 1);
                case "SetStateMachine":
                    return IntrinsicResult.Completed();
                case "SetResult":
                    heap.TrySetModelValue(self, Produced, true);
                    if (arguments.Count == 2)
                        heap.TrySetModelValue(self, Result, arguments[1]);
                    return IntrinsicResult.Completed();
                case "SetException" when arguments.Count == 2:
                    heap.TrySetModelValue(self, Produced, true);
                    heap.TrySetModelValue(self, Failure, arguments[1]);
                    return IntrinsicResult.Completed();
                case "get_Task" when arguments.Count == 1:
                    return Handed(heap, self, declaring);
                case "get_ObjectIdForDebugger":
                    return IntrinsicResult.Completed(self);
                default:
                    return IntrinsicResult.Invalid($"Unsupported async builder operation {name}.");
            }
        }

        switch (name)
        {
            // What a task is awaited through stands for the task itself: there is one thing here to
            // ask about, and asking it through an awaiter or through a configured awaitable is the
            // same question about the same task.
            case "GetAwaiter" or "ConfigureAwait" when arguments.Count >= 1:
                return IntrinsicResult.Completed(self);
            case "get_IsCompleted" when arguments.Count == 1:
                return IntrinsicResult.Completed(StaticValue.FromInt32(1));
            case "get_IsFaulted" when arguments.Count == 1:
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    heap.TryGetModelValue<StaticValue>(self, Failure, out _) ? 1 : 0));
            case "get_IsCanceled" when arguments.Count == 1:
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            case "get_Status" when arguments.Count == 1:
                // RanToCompletion and Faulted, as TaskStatus spells them.
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    heap.TryGetModelValue<StaticValue>(self, Failure, out _) ? 7 : 5));
            case "GetResult" or "get_Result" or "Wait" when arguments.Count >= 1:
            {
                if (heap.TryGetModelValue<StaticValue>(self, Failure, out var thrown))
                {
                    var kind = heap.TryGetRuntimeTypeName(thrown, out var threw)
                        ? threw
                        : "an exception";
                    return new IntrinsicResult(
                        StaticExecutionStatus.Unsupported,
                        StaticValue.Unknown,
                        $"the awaited method ended in {kind}, and what the program does with that " +
                        "is on a path this does not follow");
                }
                if (name == "Wait")
                    return IntrinsicResult.Completed();
                if (heap.TryGetModelValue<StaticValue>(self, Result, out var produced))
                    return IntrinsicResult.Completed(produced);
                // A task that finished without a value is what an async method returning no value
                // leaves behind, and reading a value from it is reading something that was never
                // there.
                return heap.TryGetModelValue<bool>(self, Produced, out var completed) && completed
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid(
                        "The awaited task is not one this machine produced, so what it finished " +
                        "with is not known.");
            }

            case "FromResult" when arguments.Count == 1:
                return Made(heap, arguments[0]);
            case "get_CompletedTask" when arguments.Count == 0:
                return Made(heap, null);
            // A delay is a wait, and waiting is the one thing that cannot happen here; what it comes
            // to is that the delay is over.
            case "Delay" when arguments.Count >= 1:
                return Made(heap, null);
            case "Run" when arguments.Count >= 1 && context.Invoke is { } invoke:
            {
                var ran = invoke(arguments[0], []);
                if (ran.Status != StaticExecutionStatus.Completed)
                    return ran;
                // An Action produces nothing and a Func produces a value, and which one this was is
                // whether anything came back.
                return ran.Value.IsKnown ? Made(heap, ran.Value) : Made(heap, null);
            }

            case "Yield" when arguments.Count == 0:
                return Made(heap, null);
            case "OnCompleted" or "UnsafeOnCompleted" when arguments.Count == 2 &&
                context.Invoke is { } continues:
            {
                var went = continues(arguments[1], []);
                return went.Status == StaticExecutionStatus.Completed
                    ? IntrinsicResult.Completed()
                    : went;
            }

            case "Dispose" or "SetObserved":
                return IntrinsicResult.Completed();
            default:
                return IntrinsicResult.Invalid($"Unsupported task operation {name}.");
        }
    }

    /// <summary>What a call's receiver is, following a reference to a struct slot.</summary>
    private static StaticValue Held(StaticHeap heap, StaticValue receiver) =>
        receiver.Kind == StaticValueKind.ManagedReference && heap.TryReadManaged(receiver, out var at)
            ? at
            : receiver;

    /// <summary>A finished task, carrying a value when there is one.</summary>
    private static IntrinsicResult Made(StaticHeap heap, StaticValue? carried)
    {
        if (!heap.TryAllocateObject(
                carried is null
                    ? "System.Threading.Tasks.Task"
                    : "System.Threading.Tasks.Task`1<System.Object>",
                out var task))
            return IntrinsicResult.Invalid("Could not allocate a task.");
        heap.TrySetModelValue(task, Produced, true);
        if (carried is { } value)
            heap.TrySetModelValue(task, Result, value);
        return IntrinsicResult.Completed(task);
    }

    /// <summary>
    /// The task a builder hands back, which is the builder seen as what it produced.
    /// </summary>
    /// <remarks>
    /// The task carries the value and the failure the builder was given, and it is allocated wearing
    /// the type the builder's own type says it produces, so that code which checks what it has back
    /// sees a task of the right kind.
    /// </remarks>
    private static IntrinsicResult Handed(StaticHeap heap, StaticValue builder, string declaring)
    {
        var at = declaring.IndexOf('<', StringComparison.Ordinal);
        var produced = at < 0
            ? "System.Threading.Tasks.Task"
            : "System.Threading.Tasks.Task`1" + declaring[at..];
        if (!heap.TryAllocateObject(produced, out var task))
            return IntrinsicResult.Invalid("Could not allocate the async method's task.");
        if (heap.TryGetModelValue<bool>(builder, Produced, out var completed) && completed)
            heap.TrySetModelValue(task, Produced, true);
        if (heap.TryGetModelValue<StaticValue>(builder, Result, out var value))
            heap.TrySetModelValue(task, Result, value);
        if (heap.TryGetModelValue<StaticValue>(builder, Failure, out var thrown))
            heap.TrySetModelValue(task, Failure, thrown);
        return IntrinsicResult.Completed(task);
    }

    /// <summary>
    /// Runs the state machine's next step, which is the whole of the program's own async code.
    /// </summary>
    /// <remarks>
    /// Which type the machine is comes from the call's own generic arguments rather than from the
    /// value, because a state machine is a struct reached through a reference and the reference says
    /// nothing about what it points at.
    /// </remarks>
    private static IntrinsicResult Advance(
        IntrinsicContext context,
        IMethod method,
        StaticValue machine,
        int position)
    {
        if (context.Call is not { } call)
            return IntrinsicResult.Invalid("The async method cannot be started from here.");
        var arguments = (method as MethodSpec)?.GenericInstMethodSig?.GenericArguments;
        var stated = arguments is not null && position < arguments.Count
            ? arguments[position]
            : null;
        var declared = stated?.ToTypeDefOrRef().ResolveTypeDef();
        if (declared is null &&
            context.State.Heap.TryGetRuntimeTypeName(Held(context.State.Heap, machine), out var was))
            declared = context.State.ModuleMetadata?.Find(was, isReflectionName: false);
        // A state machine written as a class is passed as a reference to the local holding it, and
        // what its MoveNext runs on is the object rather than that slot; one written as a struct is
        // reached through the reference itself.
        if (declared is { IsValueType: false })
            machine = Held(context.State.Heap, machine);
        var moves = declared?.FindMethod("MoveNext");
        if (moves?.Body is null)
        {
            return IntrinsicResult.Invalid(
                "The async state machine's MoveNext is not a body this machine can run.");
        }

        var went = call(moves, [machine]);
        return went.Status == StaticExecutionStatus.Completed
            ? IntrinsicResult.Completed()
            : went;
    }
}
