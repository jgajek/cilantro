using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorLocationFallbackTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("live", true)]
    [InlineData("handle", true)]
    [InlineData("public", true)]
    [InlineData("no-proof", false)]
    [InlineData("other-owner", false)]
    [InlineData("foreign", false)]
    [InlineData("extra-call", false)]
    [InlineData("other-property", false)]
    [InlineData("missing-handler", false)]
    public void RequiresBothOwnerProofAndCompleteFrameworkFingerprint(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var setup = Add(owner, "Setup", MethodSig.CreateStatic(module.CorLibTypes.Void));
            setup.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var other = SyntheticContext.AddType(module, "Other");
            var gate = Add(scenario == "other-owner" ? other : owner, "Gate", MethodSig.CreateStatic(module.CorLibTypes.Void));
            gate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var method = Add(owner, "Location", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object));
            if (scenario == "public") { owner.Attributes = TypeAttributes.Public; method.Attributes = MethodAttributes.Public | MethodAttributes.Static; }
            method.Body.Variables.Add(new Local(module.CorLibTypes.Object));
            var il = method.Body.Instructions;
            TypeSig T(string full)
            {
                if (full == "System.String") return module.CorLibTypes.String;
                if (full == "System.Object") return module.CorLibTypes.Object;
                if (full == "System.Boolean") return module.CorLibTypes.Boolean;
                if (full.EndsWith("[]", StringComparison.Ordinal)) return new SZArraySig(T(full[..^2]));
                var at = full.LastIndexOf('.');
                return new TypeRefUser(module, full[..at], full[(at + 1)..], module.CorLibTypes.AssemblyRef).ToTypeSig();
            }
            void Call(string type, string name, string result, int count, params string[] parameters)
            {
                var declaring = (TypeRef)T(type).ToTypeDefOrRef();
                if (scenario == "foreign" && name == "GetProperty") declaring.ResolutionScope = new AssemblyRefUser("Foreign");
                var signature = name == "Exists" ? MethodSig.CreateStatic(T(result), parameters.Select(T).ToArray()) : MethodSig.CreateInstance(T(result), parameters.Select(T).ToArray());
                for (var n = 0; n < count; n++)
                {
                    if (signature.HasThis) il.Add(OpCodes.Ldarg_0.ToInstruction());
                    foreach (var p in parameters) il.Add(OpCodes.Ldarg_0.ToInstruction());
                    il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, name, signature, declaring)));
                    il.Add(OpCodes.Pop.ToInstruction());
                }
            }
            Call("System.Reflection.Assembly", "get_Location", "System.String", 2);
            Call("System.IO.File", "Exists", "System.Boolean", 3, "System.String");
            Call("System.Reflection.Assembly", "GetName", "System.Reflection.AssemblyName", 2);
            Call("System.Reflection.AssemblyName", "get_CodeBase", "System.String", 2);
            Call("System.Object", "ToString", "System.String", 4);
            Call("System.String", "Replace", "System.String", 2, "System.String", "System.String");
            Call("System.Object", "GetType", "System.Type", 2);
            Call("System.Type", "GetProperty", "System.Reflection.PropertyInfo", 2, "System.String");
            Call("System.Reflection.PropertyInfo", "GetValue", "System.Object", 2, "System.Object", "System.Object[]");
            if (scenario == "extra-call") Call("System.Object", "GetType", "System.Type", 1);
            foreach (var text in new[] { "Location", scenario == "other-property" ? "Resource" : "Location", "file:///", "file:///", "", "", "" })
            { il.Add(OpCodes.Ldstr.ToInstruction(text)); il.Add(OpCodes.Pop.ToInstruction()); }
            for (var n = 0; n < (scenario == "missing-handler" ? 2 : 3); n++)
            {
                var start = OpCodes.Nop.ToInstruction(); var handler = OpCodes.Pop.ToInstruction(); var end = OpCodes.Nop.ToInstruction();
                il.Add(start); il.Add(OpCodes.Leave.ToInstruction(end)); il.Add(handler); il.Add(OpCodes.Leave.ToInstruction(end)); il.Add(end);
                method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end, CatchType = module.CorLibTypes.Object.TypeDefOrRef });
            }
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
            var entry = Add(module.GlobalType, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void));
            entry.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            if (scenario == "live") { entry.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(method)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "handle") { entry.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(method)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        if (scenario != "no-proof") context.SetFact("antitamper.memoryLoadEntryPoint", methods.Single(m => m.Name == "Gate").MDToken.Raw);
        var helpers = ReactorRuntimeFallbacks.Find(context, methods.Single(m => m.Name == "Setup")).ToArray();
        var fallback = methods.Single(m => m.Name == "Location");
        Assert.Equal(expected, helpers.Contains(fallback));
        RecoveryOrphans.Declare(context, helpers);
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(scenario != "valid", context.Module.GetTypes().SelectMany(t => t.Methods).Contains(fallback));
    }

    private static MethodDefUser Add(TypeDef owner, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        owner.Methods.Add(method); return method;
    }
}
