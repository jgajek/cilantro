using System.Collections;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class HashtableKeyTests
{
    [Fact]
    public void KeyViewIsLiveAndEnumerationRetainsOriginalBoxes()
    {
        using var fixture = new Fixture();
        var view = fixture.Call("System.Collections.Hashtable", "get_Keys", fixture.Table).Value;
        Assert.Equal(view, fixture.Call("System.Collections.Hashtable", "get_Keys", fixture.Table).Value);
        Assert.Equal(0, fixture.Call("System.Collections.ICollection", "get_Count", view).Value.AsInt32());
        Assert.True(fixture.Heap.TryAllocateBox("System.Int32", StaticValue.FromInt32(42), out var key));
        fixture.Add(key);
        var oracle = new Hashtable();
        var oracleKeys = oracle.Keys;
        oracle.Add(42, null);
        Assert.Equal(oracleKeys.Count, fixture.Call("System.Collections.ICollection", "get_Count", view).Value.AsInt32());
        Assert.Equal(fixture.Table, fixture.Call("System.Collections.ICollection", "get_SyncRoot", view).Value);
        var enumerator = fixture.Enumerator(view);
        Assert.Equal(1, fixture.Call("System.Collections.IEnumerator", "MoveNext", enumerator).Value.AsInt32());
        Assert.Equal(key, fixture.Call("System.Collections.IEnumerator", "get_Current", enumerator).Value);
        Assert.Equal(0, fixture.Call("System.Collections.IEnumerator", "MoveNext", enumerator).Value.AsInt32());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MutationsInvalidateMoveNextAndResetButRetainCurrent(bool replace)
    {
        using var fixture = new Fixture();
        var key = fixture.Text("key");
        fixture.Add(key);
        var iterator = fixture.Enumerator();
        fixture.Call("System.Collections.IEnumerator", "MoveNext", iterator);
        var oracle = new Hashtable { ["key"] = null };
        var oracleIterator = oracle.Keys.GetEnumerator();
        Assert.True(oracleIterator.MoveNext());
        if (replace)
        {
            fixture.Call("System.Collections.Hashtable", "set_Item", fixture.Table, key, StaticValue.Null);
            oracle["key"] = null;
        }
        else { fixture.Add(fixture.Text("new")); oracle.Add("new", null); }
        Assert.Equal("key", oracleIterator.Current);
        Assert.Equal(key, fixture.Call("System.Collections.IEnumerator", "get_Current", iterator).Value);
        Assert.Throws<InvalidOperationException>(() => oracleIterator.MoveNext());
        Assert.Throws<InvalidOperationException>(() => oracleIterator.Reset());
        fixture.ThrowsInvalidOperation(fixture.Call("System.Collections.IEnumerator", "MoveNext", iterator));
        fixture.ThrowsInvalidOperation(fixture.Call("System.Collections.IEnumerator", "Reset", iterator));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public void CurrentBoundariesAndResetFollowRuntimeBehavior(int count)
    {
        using var fixture = new Fixture();
        for (var i = 0; i < count; i++) fixture.Add(fixture.Text(i.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        var iterator = fixture.Enumerator();
        fixture.ThrowsInvalidOperation(fixture.Call("System.Collections.IEnumerator", "get_Current", iterator));
        var seen = new HashSet<StaticValue>();
        while (fixture.Call("System.Collections.IEnumerator", "MoveNext", iterator).Value.AsInt32() != 0)
            seen.Add(fixture.Call("System.Collections.IEnumerator", "get_Current", iterator).Value);
        Assert.Equal(count, seen.Count);
        Assert.Equal(0, fixture.Call("System.Collections.IEnumerator", "MoveNext", iterator).Value.AsInt32());
        fixture.ThrowsInvalidOperation(fixture.Call("System.Collections.IEnumerator", "get_Current", iterator));
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Call("System.Collections.IEnumerator", "Reset", iterator).Status);
        fixture.ThrowsInvalidOperation(fixture.Call("System.Collections.IEnumerator", "get_Current", iterator));
        Assert.Equal(count > 0 ? 1 : 0, fixture.Call("System.Collections.IEnumerator", "MoveNext", iterator).Value.AsInt32());
    }

    [Fact]
    public void EnumerationRespectsAllocationLimits()
    {
        using var fixture = new Fixture(new StaticMachineLimits(MaximumArrayLength: 1));
        fixture.Add(fixture.Text("a")); fixture.Add(fixture.Text("b"));
        var view = fixture.Call("System.Collections.Hashtable", "get_Keys", fixture.Table).Value;
        Assert.Equal(StaticExecutionStatus.AllocationLimitExceeded,
            fixture.Call("System.Collections.IEnumerable", "GetEnumerator", view).Status);
    }

    [Fact]
    public void PreexistingUnboxedKeysAreNotGivenInventedBoxIdentities()
    {
        using var fixture = new Fixture();
        Assert.True(fixture.Heap.TryGetModelValue(fixture.Table, "Entries", out Dictionary<StaticValue, StaticValue>? entries));
        entries![StaticValue.FromInt32(42)] = StaticValue.Null;
        var view = fixture.Call("System.Collections.Hashtable", "get_Keys", fixture.Table).Value;
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call("System.Collections.IEnumerable", "GetEnumerator", view).Status);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ModuleDefUser module = new("keys");
        private readonly StaticMachine machine;
        internal StaticHeap Heap => machine.State.Heap;
        internal StaticValue Table { get; }
        internal Fixture(StaticMachineLimits? limits = null)
        {
            machine = new StaticMachine(limits);
            machine.State.RegisterModuleMetadata(module);
            Assert.True(Heap.TryAllocateObject("System.Collections.Hashtable", out var table));
            Table = table;
            Assert.Equal(StaticExecutionStatus.Completed, Call("System.Collections.Hashtable", ".ctor", Table).Status);
        }
        internal StaticValue Text(string text) { Assert.True(Heap.TryAllocateString(text, out var value)); return value; }
        internal void Add(StaticValue key) => Assert.Equal(StaticExecutionStatus.Completed,
            Call("System.Collections.Hashtable", "Add", Table, key, StaticValue.Null).Status);
        internal StaticValue Enumerator(StaticValue? view = null)
        {
            var result = Call("System.Collections.IEnumerable", "GetEnumerator",
                view ?? Call("System.Collections.Hashtable", "get_Keys", Table).Value);
            Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
            return result.Value;
        }
        internal StaticExecutionResult Call(string type, string name, params StaticValue[] arguments)
        {
            var split = type.LastIndexOf('.');
            var method = new MemberRefUser(module, name, MethodSig.CreateInstance(module.CorLibTypes.Object),
                module.CorLibTypes.GetTypeRef(type[..split], type[(split + 1)..]));
            return machine.Invoke(method, arguments);
        }
        internal void ThrowsInvalidOperation(StaticExecutionResult result)
        {
            Assert.Equal(StaticExecutionStatus.Threw, result.Status);
            Assert.True(Heap.TryGetRuntimeTypeName(result.Value, out var name));
            Assert.Equal("System.InvalidOperationException", name);
        }
        public void Dispose() => module.Dispose();
    }
}
