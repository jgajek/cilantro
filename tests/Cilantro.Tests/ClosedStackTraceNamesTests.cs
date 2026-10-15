using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedStackTraceNamesTests
{
    [Theory]
    [InlineData("direct", 1)]
    [InlineData("nullable", 1)]
    [InlineData("foreign", 0)]
    [InlineData("argument-frame", 0)]
    [InlineData("address", 0)]
    [InlineData("alternate-getter-entry", 0)]
    [InlineData("escape", 0)]
    public void OnlyClosedFrameworkReceiversAreAccepted(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var trace = new TypeRefUser(module, "System.Diagnostics", "StackTrace", module.CorLibTypes.AssemblyRef);
            var frame = new TypeRefUser(module, "System.Diagnostics", "StackFrame", module.CorLibTypes.AssemblyRef);
            var exception = new TypeRefUser(module, "System", "Exception", module.CorLibTypes.AssemblyRef);
            var methodBase = new TypeRefUser(module, "System.Reflection", "MethodBase", module.CorLibTypes.AssemblyRef);
            var member = new TypeRefUser(module, "System.Reflection", "MemberInfo", module.CorLibTypes.AssemblyRef);
            if (scenario == "foreign") trace.ResolutionScope = new AssemblyRefUser("Foreign", new Version(1, 0));
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.String, new ClassSig(frame)))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            SyntheticContext.AddType(module, "Logger").Methods.Add(method);
            var traceLocal = new Local(new ClassSig(trace)); var frameLocal = new Local(new ClassSig(frame));
            method.Body.Variables.Add(traceLocal); method.Body.Variables.Add(frameLocal);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldc_I4_1.ToInstruction());
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new ClassSig(exception), module.CorLibTypes.Boolean), trace)));
            il.Add(OpCodes.Stloc.ToInstruction(traceLocal));
            if (scenario == "argument-frame") il.Add(OpCodes.Ldarg_0.ToInstruction());
            else
            {
                il.Add(OpCodes.Ldloc.ToInstruction(traceLocal)); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetFrame", MethodSig.CreateInstance(new ClassSig(frame), module.CorLibTypes.Int32), trace)));
            }
            il.Add(OpCodes.Stloc.ToInstruction(frameLocal));
            if (scenario is "address" or "escape")
            {
                il.Add((scenario == "address" ? OpCodes.Ldloca : OpCodes.Ldloc).ToInstruction(frameLocal));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            var getName = OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Name", MethodSig.CreateInstance(module.CorLibTypes.String), member));
            if (scenario == "alternate-getter-entry")
            {
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(getName));
            }
            il.Add(OpCodes.Ldloc.ToInstruction(frameLocal));
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(new ClassSig(methodBase)), frame)));
            var ret = OpCodes.Ret.ToInstruction();
            if (scenario == "nullable")
            {
                var pop = OpCodes.Pop.ToInstruction();
                il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Brfalse.ToInstruction(pop));
                il.Add(OpCodes.Br.ToInstruction(getName)); il.Add(pop); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(ret));
            }
            il.Add(getName); il.Add(ret);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        Assert.Equal(expected, ClosedStackTraceNames.Find(method).Count);
    }
}
