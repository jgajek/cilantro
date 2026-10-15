using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LoadedAssemblyFlowTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("domain", true)]
    [InlineData("null-store", true)]
    [InlineData("finally-loaded", true)]
    [InlineData("finally-own", false)]
    [InlineData("catch-own", false)]
    [InlineData("address", false)]
    [InlineData("uninitialized", false)]
    [InlineData("circular", false)]
    [InlineData("unreachable-writer", false)]
    [InlineData("foreign", false)]
    public void LoadedLocalInvariantSurvivesExceptionsOnlyWhenEveryStoreIsKnown(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("retired", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
            SyntheticContext.AddType(module, "RetiredOwner");
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = scenario != "uninitialized" } };
            owner.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var domain = new TypeRefUser(module, "System", "AppDomain", scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var local = new Local(assembly.ToTypeSig()); run.Body.Variables.Add(local);
            var start = OpCodes.Nop.ToInstruction();
            var handler = OpCodes.Nop.ToInstruction();
            var after = OpCodes.Ldloc.ToInstruction(local);
            AddIL(run, start);
            if (scenario == "circular") AddIL(run, OpCodes.Ldloc.ToInstruction(local));
            else Load();
            AddIL(run, OpCodes.Stloc.ToInstruction(local));
            if (scenario == "null-store") AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Stloc.ToInstruction(local));
            if (scenario == "address") AddIL(run, OpCodes.Ldloca.ToInstruction(local), OpCodes.Pop.ToInstruction());
            AddIL(run, OpCodes.Leave.ToInstruction(after), handler);
            if (scenario == "catch-own") AddIL(run, OpCodes.Pop.ToInstruction());
            if (scenario == "finally-loaded") { Load(); AddIL(run, OpCodes.Stloc.ToInstruction(local)); }
            if (scenario is "finally-own" or "catch-own") Own();
            AddIL(run, scenario == "catch-own" ? OpCodes.Leave.ToInstruction(after) : OpCodes.Endfinally.ToInstruction());
            if (scenario == "unreachable-writer") { Own(); AddIL(run, OpCodes.Br.ToInstruction(after)); }
            AddIL(run, after, OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_FullName", MethodSig.CreateInstance(module.CorLibTypes.String), assembly)),
                OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            run.Body.ExceptionHandlers.Add(new ExceptionHandler(scenario == "catch-own" ? ExceptionHandlerType.Catch : ExceptionHandlerType.Finally)
            { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = after,
                CatchType = scenario == "catch-own" ? module.CorLibTypes.GetTypeRef("System", "Exception") : null });
            void Load()
            {
                if (scenario is "domain" or "foreign") AddIL(run, OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain)));
                AddIL(run, OpCodes.Ldnull.ToInstruction(), scenario is "domain" or "foreign"
                    ? OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Load", MethodSig.CreateInstance(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), domain))
                    : OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load", MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            }
            void Own() => AddIL(run, OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)), OpCodes.Stloc.ToInstruction(local));
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var observe = run.Body.Instructions.Single(i => i.Operand is IMethod m && m.Name == "get_FullName");
        var before = MethodBodySnapshot.Capture(run);
        Assert.Equal(expected, LoadedAssemblyFlow.Find(context.Module).Contains(observe));
        var retired = context.Module.Types.Single(t => t.Name == "RetiredOwner");
        context.SetFact<IReadOnlyList<NumericResourceOwnership>>(NumericResourceOwnership.Fact,
            [new(retired, RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]))]);
        context.Module.Types.Remove(retired);
        context.SetFact("cleanup.removedTypeCount", 1);
        context.SetFact("options.removeRuntime", true);
        // Proven retired protector metadata may be removed even when application reflection remains unknown.
        Assert.Equal(1, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.True(before.StructurallyEquals(run));
    }

    [Theory]
    [InlineData("entry", false, false)]
    [InlineData("entry", true, false)]
    [InlineData("entry", false, true)]
    [InlineData("construct", false, false)]
    [InlineData("construct", true, false)]
    [InlineData("construct", false, true)]
    [InlineData("compare", false, false)]
    [InlineData("compare", true, false)]
    [InlineData("compare", false, true)]
    public void InvocationAndComparisonRequireLoadedOriginAndFrameworkScope(string operation, bool own, bool foreign)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load", MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            if (own) AddIL(run, OpCodes.Pop.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)));
            var scope = foreign ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef;
            if (operation == "construct")
            {
                AddIL(run, OpCodes.Ldstr.ToInstruction("App"), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType", MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)),
                    OpCodes.Call.ToInstruction(new MemberRefUser(module, "CreateInstance", MethodSig.CreateStatic(module.CorLibTypes.Object, type.ToTypeSig()), new TypeRefUser(module, "System", "Activator", scope))));
            }
            else if (operation == "entry") AddIL(run, OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_EntryPoint", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo").ToTypeSig()), new TypeRefUser(module, "System.Reflection", "Assembly", scope))));
            else AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "op_Inequality", MethodSig.CreateStatic(module.CorLibTypes.Boolean, assembly.ToTypeSig(), assembly.ToTypeSig()), new TypeRefUser(module, "System.Reflection", "Assembly", scope))));
            AddIL(run, OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var instruction = run.Body.Instructions[^3];
        Assert.Equal(!own && !foreign, LoadedAssemblyFlow.Find(context.Module).Contains(instruction));
    }

    [Theory]
    [InlineData("closed", 3)]
    [InlineData("split", 3)]
    [InlineData("join-own", 0)]
    [InlineData("join-loaded", 3)]
    [InlineData("recursive", 0)]
    [InlineData("mixed-writer", 0)]
    [InlineData("unknown-caller", 0)]
    [InlineData("field-address", 0)]
    [InlineData("method-handle", 0)]
    [InlineData("named-setter", 0)]
    [InlineData("named-field", 0)]
    [InlineData("type-handle", 0)]
    [InlineData("null-caller", 3)]
    [InlineData("parameter-address", 0)]
    [InlineData("external-setter", 0)]
    [InlineData("foreign", 0)]
    public void FollowsOnlyClosedWritersAndCallers(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("retired", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
            SyntheticContext.AddType(module, "RetiredOwner");
            var owner = SyntheticContext.AddType(module, "Flow");
            if (scenario == "external-setter") owner.Attributes = TypeAttributes.Public;
            var assembly = new TypeRefUser(module, "System.Reflection", "Assembly", scenario == "foreign"
                ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var info = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var methodBase = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase");
            var field = new FieldDefUser("AssemblyValue", new FieldSig(assembly.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            var setter = Add("Set", module.CorLibTypes.Void, assembly.ToTypeSig());
            if (scenario == "external-setter") setter.Attributes = MethodAttributes.Public | MethodAttributes.Static;
            if (scenario == "parameter-address")
            { setter.Body.Instructions.Add(OpCodes.Ldarga.ToInstruction(setter.Parameters[0])); setter.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "recursive") AddIL(setter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(setter));
            AddIL(setter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
            var getter = Add("Get", assembly.ToTypeSig());
            AddIL(getter, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
            var lookup = Add("Lookup", type.ToTypeSig(), assembly.ToTypeSig());
            AddIL(lookup, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldstr.ToInstruction("Payload"), OpCodes.Callvirt.ToInstruction(
                new MemberRefUser(module, "GetType", MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)), OpCodes.Ret.ToInstruction());
            var run = Add("Run", module.CorLibTypes.Void);
            module.EntryPoint = run;
            var il = run.Body.Instructions;
            AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)), OpCodes.Call.ToInstruction(setter));
            if (scenario is "mixed-writer" or "unknown-caller")
            {
                AddIL(run, OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)));
                il.Add(scenario == "mixed-writer" ? OpCodes.Stsfld.ToInstruction(field) : OpCodes.Call.ToInstruction(setter));
            }
            if (scenario == "field-address") AddIL(run, OpCodes.Ldsflda.ToInstruction(field), OpCodes.Pop.ToInstruction());
            if (scenario == "method-handle") AddIL(run, OpCodes.Ldftn.ToInstruction(setter), OpCodes.Pop.ToInstruction());
            if (scenario == "named-setter") AddIL(run, OpCodes.Ldstr.ToInstruction("Set"), OpCodes.Pop.ToInstruction());
            if (scenario == "named-field") AddIL(run, OpCodes.Ldstr.ToInstruction("AssemblyValue"), OpCodes.Pop.ToInstruction());
            if (scenario == "type-handle") AddIL(run, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            if (scenario == "null-caller") AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(setter));
            AddIL(run, OpCodes.Call.ToInstruction(getter));
            if (scenario is "split" or "join-own" or "join-loaded")
            {
                var local = new Local(assembly.ToTypeSig()); run.Body.Variables.Add(local);
                var read = OpCodes.Ldloc.ToInstruction(local);
                AddIL(run, OpCodes.Stloc.ToInstruction(local));
                if (scenario is "join-own" or "join-loaded")
                {
                    AddIL(run, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(read));
                    if (scenario == "join-loaded") AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                        MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
                    else AddIL(run, OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)));
                    AddIL(run, OpCodes.Stloc.ToInstruction(local));
                }
                AddIL(run, OpCodes.Br.ToInstruction(read), read);
            }
            AddIL(run, OpCodes.Call.ToInstruction(lookup), OpCodes.Ldstr.ToInstruction("Start"), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod",
                MethodSig.CreateInstance(info.ToTypeSig(), module.CorLibTypes.String), type)), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(module.CorLibTypes.Object,
                    module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)), methodBase)), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());

            MethodDef Add(string name, TypeSig result, params TypeSig[] parameters)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(result, parameters))
                    { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
                owner.Methods.Add(method); return method;
            }
        });
        Assert.Equal(expected, LoadedAssemblyFlow.Find(context.Module).Count);
        var retired = context.Module.Types.Single(t => t.Name == "RetiredOwner");
        context.SetFact<IReadOnlyList<NumericResourceOwnership>>(NumericResourceOwnership.Fact,
            [new(retired, RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]))]);
        context.Module.Types.Remove(retired);
        context.SetFact("cleanup.removedTypeCount", 1);
        context.SetFact("options.removeRuntime", true);
        var bodies = context.Module.GetTypes().SelectMany(t => t.Methods).ToDictionary(m => m, MethodBodySnapshot.Capture);
        // Flow classification above remains strict; retirement has its independent ownership proof.
        Assert.Equal(1, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.True(bodies.All(p => p.Value.StructurallyEquals(p.Key)));
    }

    [Theory]
    [InlineData("closed", 5)]
    [InlineData("enumerate", 5)]
    [InlineData("escape", 2)]
    [InlineData("mutate", 2)]
    [InlineData("address", 2)]
    public void ReflectionArrayElementsRequireUnescapedUnmodifiedArrays(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var info = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var methodBase = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase");
            var member = module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo");
            var parameter = module.CorLibTypes.GetTypeRef("System.Reflection", "ParameterInfo");
            var array = new Local(new SZArraySig(info.ToTypeSig())); run.Body.Variables.Add(array);
            AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            if (scenario == "enumerate") AddIL(run, OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetTypes",
                MethodSig.CreateInstance(new SZArraySig(type.ToTypeSig())), assembly)), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelem_Ref.ToInstruction());
            else AddIL(run, OpCodes.Ldstr.ToInstruction("App"), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType",
                MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)));
            AddIL(run, OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethods", MethodSig.CreateInstance(array.Type), type)),
                OpCodes.Stloc.ToInstruction(array));
            if (scenario == "escape") AddIL(run, OpCodes.Ldloc.ToInstruction(array), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Mutate",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), new TypeRefUser(module, "External", "Api", new AssemblyRefUser("External")))));
            if (scenario == "mutate") AddIL(run, OpCodes.Ldloc.ToInstruction(array), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Stelem_Ref.ToInstruction());
            if (scenario == "address") AddIL(run, OpCodes.Ldloc.ToInstruction(array), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelema.ToInstruction(info), OpCodes.Pop.ToInstruction());
            AddIL(run, OpCodes.Ldloc.ToInstruction(array), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelem_Ref.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetParameters", MethodSig.CreateInstance(new SZArraySig(parameter.ToTypeSig())), methodBase)),
                OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelem_Ref.ToInstruction(), OpCodes.Castclass.ToInstruction(parameter),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_ParameterType",
                    MethodSig.CreateInstance(type.ToTypeSig()), parameter)), OpCodes.Castclass.ToInstruction(member), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Name",
                    MethodSig.CreateInstance(module.CorLibTypes.String), member)), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, LoadedAssemblyFlow.Find(context.Module).Count);
    }

    [Theory]
    [InlineData(false, 4)]
    [InlineData(true, 1)]
    public void AttributeConstructionRequiresLoadedMemberProvenance(bool ownAssembly, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() }; owner.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var info = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var member = module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo");
            AddIL(run, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            if (ownAssembly) AddIL(run, OpCodes.Pop.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly",
                MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)));
            AddIL(run, OpCodes.Ldstr.ToInstruction("App"), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType",
                MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)), OpCodes.Ldstr.ToInstruction("Entry"),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(info.ToTypeSig(), module.CorLibTypes.String), type)),
                OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetCustomAttributes",
                    MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Object), module.CorLibTypes.Boolean), member)),
                OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelem_Ref.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType",
                    MethodSig.CreateInstance(type.ToTypeSig()), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Castclass.ToInstruction(member),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Name", MethodSig.CreateInstance(module.CorLibTypes.String), member)),
                OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, LoadedAssemblyFlow.Find(context.Module).Count);
    }

    private static void AddIL(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 0)]
    public void AccountsForHiddenReceiverAndRejectsVirtualSetter(bool virtualSetter, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Holder");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var field = new FieldDefUser("Value", new FieldSig(assembly.ToTypeSig()), FieldAttributes.Private); owner.Fields.Add(field);
            var setter = new MethodDefUser("Set", MethodSig.CreateInstance(module.CorLibTypes.Void, assembly.ToTypeSig()))
                { Attributes = MethodAttributes.Public | (virtualSetter ? MethodAttributes.Virtual | MethodAttributes.NewSlot : 0), Body = new CilBody() };
            var getter = new MethodDefUser("Get", MethodSig.CreateInstance(assembly.ToTypeSig()))
                { Attributes = MethodAttributes.Public, Body = new CilBody() };
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, owner.ToTypeSig()))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(setter); owner.Methods.Add(getter); owner.Methods.Add(run);
            AddIL(setter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
            AddIL(getter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
            AddIL(run, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)), OpCodes.Callvirt.ToInstruction(setter),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(getter), OpCodes.Ldstr.ToInstruction("Payload"),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType", MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)),
                OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, LoadedAssemblyFlow.Find(context.Module).Count);
    }

    [Fact]
    public void DoesNotCarryLocalProvenancePastFinally()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } }; owner.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var local = new Local(assembly.ToTypeSig()); run.Body.Variables.Add(local);
            var start = OpCodes.Ldnull.ToInstruction();
            var handler = OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly));
            var after = OpCodes.Ldloc.ToInstruction(local);
            AddIL(run, start, OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)), OpCodes.Stloc.ToInstruction(local),
                OpCodes.Leave.ToInstruction(after), handler, OpCodes.Stloc.ToInstruction(local), OpCodes.Endfinally.ToInstruction(), after,
                OpCodes.Ldstr.ToInstruction("App"), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType",
                    MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            run.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
                { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = after });
        });
        Assert.Empty(LoadedAssemblyFlow.Find(context.Module));
    }
}
