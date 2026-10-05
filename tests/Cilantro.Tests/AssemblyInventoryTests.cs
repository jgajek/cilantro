using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class AssemblyInventoryTests
{
    [Theory]
    [InlineData("Dependency, Version=\"65535.65535.65535.65535\"")]
    [InlineData("Version=65535.65535.65535.65535")]
    public void UnmodeledLegacyWildcardSyntaxDoesNotBorrowCoreClrFailure(string identity)
    {
        using var module = new ModuleDefUser("legacy.dll");
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(module);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.AssemblyName", out var receiver));
        Assert.True(state.Heap.TryAllocateString(identity, out var text));
        var method = new Importer(module).Import(typeof(System.Reflection.AssemblyName).GetConstructor([typeof(string)])!);
        var result = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), method, [receiver, text]);
        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
    }

    [Theory]
    [InlineData("65535.65535.65535.65535", null, null)]
    [InlineData("1.2.65535.65535", "1.2", "1.2.65535.65535")]
    [InlineData("1.65535.3.4", null, null)]
    [InlineData("65535.2.3.4", null, null)]
    [InlineData("65534.65534.65534.65534", "65534.65534.65534.65534", "65534.65534.65534.65534")]
    [InlineData("1.2.3.65535", "1.2.3", "1.2.3.65535")]
    public void FrameworkWildcardVersionsMatchTheSourceBuiltFrameworkOracle(string version, string? displayVersion, string? objectVersion)
    {
        using var module = new ModuleDefUser("legacy.dll");
        new AssemblyDefUser("Home", new Version(9, 8, 7, 6)).Modules.Add(module);
        Assert.Equal("mscorlib", module.CorLibTypes.AssemblyRef.Name.String);
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(module);
        var heap = state.Heap;
        Assert.True(heap.TryAllocateObject("System.Reflection.AssemblyName", out var receiver));
        Assert.True(heap.TryAllocateString($"Dependency, Version={version}, Culture=neutral, PublicKeyToken=null", out var text));
        var importer = new Importer(module);
        var intrinsic = new LoaderFrameworkIntrinsic();
        var context = new IntrinsicContext(state);
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetConstructor([typeof(string)])!), [receiver, text]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var name = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetProperty("FullName")!.GetMethod!), [receiver]);
        Assert.True(heap.TryGetString(name.Value, out var display));
        Assert.Equal("Dependency" + (displayVersion is null ? "" : ", Version=" + displayVersion) + ", Culture=neutral, PublicKeyToken=null", display);
        var actualVersion = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetProperty("Version")!.GetMethod!), [receiver]);
        if (objectVersion is null) Assert.Equal(StaticValue.Null, actualVersion.Value);
        else
        {
            Assert.True(heap.TryGetModelValue(actualVersion.Value, "Components", out int[]? parts));
            Assert.Equal(objectVersion, string.Join('.', parts!));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("mscorlib, Version=65535.65535.65535.65535, Culture=neutral, PublicKeyToken=b77a5c561934e089")]
    [InlineData("Dependency, PublicKeyToken=not-a-token")]
    public void InvalidDisplayNamesThrowTheFrameworkException(string? identity)
    {
        var expected = Record.Exception(() => new System.Reflection.AssemblyName(identity!));
        Assert.NotNull(expected);
        using var module = new ModuleDefUser("test.dll");
        var state = new StaticMachineState(new StaticMachineLimits());
        var heap = state.Heap;
        Assert.True(heap.TryAllocateObject("System.Reflection.AssemblyName", out var receiver));
        var text = StaticValue.Null;
        if (identity is not null) Assert.True(heap.TryAllocateString(identity, out text));
        var method = new Importer(module).Import(typeof(System.Reflection.AssemblyName).GetConstructor([typeof(string)])!);
        var result = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), method, [receiver, text]);
        Assert.Equal(StaticExecutionStatus.Threw, result.Status);
        Assert.True(heap.TryGetRuntimeTypeName(result.Value, out var type));
        Assert.Equal(expected.GetType().FullName, type);
        Assert.True(heap.TryGetModelValue(result.Value, "Message", out string? message));
        Assert.Equal(expected.Message, message);
        if (expected is ArgumentException argument)
        {
            Assert.True(heap.TryGetModelValue(result.Value, "ParamName", out string? parameter));
            Assert.Equal(argument.ParamName, parameter);
        }
    }

    [Fact]
    public void ObservedLoadsDoNotClaimACompleteHostInventory()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.Assembly", out var assembly));
        Assert.True(AppDomainAssemblyInventory.RecordLoad(state, assembly));
        Assert.Equal(StaticExecutionStatus.Unknown, AppDomainAssemblyInventory.Read(state, domain).Status);
    }

    [Fact]
    public void ClosedInventoryKeepsLoadIdentityAndReturnsIndependentArrays()
    {
        using var module = new ModuleDefUser("home.dll");
        new AssemblyDefUser("Home", new Version(1, 0)).Modules.Add(module);
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(module);
        var heap = state.Heap;
        var intrinsic = new LoaderFrameworkIntrinsic();
        var context = new IntrinsicContext(state);
        var importer = new Importer(module);
        IntrinsicResult Call(System.Reflection.MethodInfo method, params StaticValue[] args) => intrinsic.Invoke(context, importer.Import(method), args);
        var home = Call(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly")!).Value;
        Assert.True(AppDomainAssemblyInventory.BeginClosedFixture(state, home));
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        using var payload = new ModuleDefUser("Payload.dll");
        new AssemblyDefUser("Payload", new Version(2, 3, 4, 5)).Modules.Add(payload);
        using var bytes = new MemoryStream();
        payload.Write(bytes);
        Assert.True(heap.TryAllocateByteArray(bytes.ToArray(), out var image));
        Assert.True(heap.TryAllocateByteArray([1, 2, 3], out var symbols));
        var loaded = Call(typeof(System.Reflection.Assembly).GetMethod("Load", [typeof(byte[]), typeof(byte[])])!, image, symbols);
        Assert.Equal(StaticExecutionStatus.Completed, loaded.Status);
        Assert.Single(state.CapturedAssemblyLoads);
        Assert.True(heap.TryGetModelValue(loaded.Value, "LoadedSymbols", out byte[]? captured));
        Assert.Equal(new byte[] { 1, 2, 3 }, captured);
        var listed = AppDomainAssemblyInventory.Read(state, domain);
        Assert.True(heap.TryGetRuntimeTypeName(listed.Value, out var arrayType));
        Assert.Equal("System.Reflection.Assembly[]", arrayType);
        Assert.True(heap.TryGetLength(listed.Value, out var count));
        Assert.Equal(2, count);
        Assert.True(heap.TryReadArray(listed.Value, 0, out var first));
        Assert.True(heap.TryReadArray(listed.Value, 1, out var second));
        Assert.Equal(home, first); Assert.Equal(loaded.Value, second);
        Assert.True(heap.TryWriteArray(listed.Value, 0, StaticValue.Null));
        Assert.True(heap.TryReadArray(AppDomainAssemblyInventory.Read(state, domain).Value, 0, out first));
        Assert.Equal(home, first);
        var getName = typeof(System.Reflection.Assembly).GetMethod("GetName", Type.EmptyTypes)!;
        var nameGetter = typeof(System.Reflection.AssemblyName).GetProperty("Name")!.GetMethod!;
        Assert.True(heap.TryGetString(Call(nameGetter, Call(getName, loaded.Value).Value).Value, out var payloadName));
        Assert.True(heap.TryGetString(Call(nameGetter, Call(getName, home).Value).Value, out var homeName));
        Assert.Equal("Payload", payloadName); Assert.Equal("Home", homeName);
        Assert.True(heap.TryGetString(Call(typeof(System.Reflection.Assembly).GetProperty("Location")!.GetMethod!, loaded.Value).Value, out var location));
        Assert.Equal("", location);
        Assert.NotNull(new RebuiltMethodTrial.Snapshot(heap).ReadDomainState(state));
    }

    [Theory]
    [InlineData("Dependency, Version=2.3.4.5, Culture=fr-FR, PublicKeyToken=0011223344556677", "fr-FR", "0011223344556677")]
    [InlineData("Dependency, Version=2.3.4.5, Culture=neutral, PublicKeyToken=null", "", "")]
    public void ParsedAssemblyIdentityDoesNotBorrowHomeCultureOrToken(string identity, string culture, string token)
    {
        using var module = new ModuleDefUser("test.dll");
        var state = new StaticMachineState(new StaticMachineLimits());
        var heap = state.Heap;
        var intrinsic = new LoaderFrameworkIntrinsic();
        var importer = new Importer(module);
        heap.TryAllocateObject("System.Reflection.AssemblyName", out var receiver);
        heap.TryAllocateString(identity, out var text);
        var created = intrinsic.Invoke(new IntrinsicContext(state), importer.Import(typeof(System.Reflection.AssemblyName).GetConstructor([typeof(string)])!), [receiver, text]);
        Assert.Equal(StaticExecutionStatus.Completed, created.Status);
        var readCulture = intrinsic.Invoke(new IntrinsicContext(state), importer.Import(typeof(System.Reflection.AssemblyName).GetProperty("CultureName")!.GetMethod!), [receiver]);
        Assert.True(heap.TryGetString(readCulture.Value, out var actualCulture));
        Assert.Equal(culture, actualCulture);
        var readToken = intrinsic.Invoke(new IntrinsicContext(state), importer.Import(typeof(System.Reflection.AssemblyName).GetMethod("GetPublicKeyToken")!), [receiver]);
        Assert.Equal(Convert.FromHexString(token), heap.GetBytesSnapshot(readToken.Value));
    }

    [Theory]
    [InlineData("Core.Name", "core.name", true)]
    [InlineData("Core.Name", "Other.Name", false)]
    [InlineData("en-US", "EN-us", true)]
    public void InvariantIdentifierEqualityMatchesFramework(string left, string right, bool expected)
    {
        using var module = new ModuleDefUser("test.dll");
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateString(left, out var a));
        Assert.True(state.Heap.TryAllocateString(right, out var b));
        var method = new Importer(module).Import(typeof(string).GetMethod("Equals", [typeof(string), typeof(string), typeof(StringComparison)])!);
        var result = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), method,
            [a, b, StaticValue.FromInt32((int)StringComparison.InvariantCultureIgnoreCase)]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(expected, result.Value.AsInt32() != 0);
#pragma warning disable CA1309 // The framework's invariant overload is the oracle under test.
        Assert.Equal(string.Equals(left, right, StringComparison.InvariantCultureIgnoreCase), expected);
#pragma warning restore CA1309
    }

    [Theory]
    [InlineData("\u00e6", "ae")]
    [InlineData("a\0b", "ab")]
    public void NonIdentifierCollationRemainsUnknown(string left, string right)
    {
        using var module = new ModuleDefUser("test.dll");
        var state = new StaticMachineState(new StaticMachineLimits());
        state.Heap.TryAllocateString(left, out var a); state.Heap.TryAllocateString(right, out var b);
        var method = new Importer(module).Import(typeof(string).GetMethod("Equals", [typeof(string), typeof(string), typeof(StringComparison)])!);
        var result = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), method,
            [a, b, StaticValue.FromInt32((int)StringComparison.InvariantCultureIgnoreCase)]);
        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
    }
}
