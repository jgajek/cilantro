using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BinderContextReachabilityTests
{
    [Theory]
    [InlineData("context", false)]
    [InlineData("binary", false)]
    [InlineData("target", true)]
    [InlineData("foreign", true)]
    [InlineData("duplicate", true)]
    [InlineData("alternate-entry", true)]
    public void OnlyTheClosedFrameworkContextAvoidsReflectiveExposure(string scenario, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var root = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(root);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var getType = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(),
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), type);
            var assembly = new AssemblyRefUser(scenario == "foreign" ? "Impostor" : "Microsoft.CSharp");
            var binder = new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", "Binder", assembly);
            var flags = new ValueTypeSig(new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", "CSharpBinderFlags", assembly));
            var result = new ClassSig(new TypeRefUser(module, "System.Runtime.CompilerServices", "CallSiteBinder", new AssemblyRefUser("System.Core")));
            var il = root.Body.Instructions;
            il.Add(OpCodes.Ldc_I4_0.ToInstruction());
            if (scenario == "binary") il.Add(OpCodes.Ldc_I4_0.ToInstruction());
            else if (scenario != "target") il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Ldtoken.ToInstruction(owner));
            il.Add(OpCodes.Call.ToInstruction(getType));
            if (scenario == "duplicate") { il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "target") il.Add(OpCodes.Ldnull.ToInstruction());
            IMethod call;
            if (scenario == "binary")
            {
                var info = new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", "CSharpArgumentInfo", assembly);
                il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(info));
                var enumerable = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1")), info.ToTypeSig());
                call = new MemberRefUser(module, "BinaryOperation", MethodSig.CreateStatic(result, flags,
                    new ValueTypeSig(new TypeRefUser(module, "System.Linq.Expressions", "ExpressionType", new AssemblyRefUser("System.Core"))), type.ToTypeSig(), enumerable), binder);
            }
            else call = new MemberRefUser(module, "Convert", MethodSig.CreateStatic(result, flags, type.ToTypeSig(), type.ToTypeSig()), binder);
            var invoke = OpCodes.Call.ToInstruction(call);
            if (scenario == "alternate-entry") il.Add(OpCodes.Br.ToInstruction(invoke));
            il.Add(invoke); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.Types.Single(t => t.Name == "Owner");
        Assert.Equal(exposed, ModuleReachability.Compute(context.Module).IsReflectivelyExposed(owner));
    }
}
