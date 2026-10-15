using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers which methods the reachability walk treats as able to run.
/// </summary>
/// <remarks>
/// The deletions and constant-folding downstream are only as sound as this set, and the failure mode
/// is silent: a method wrongly left out is a method whose code can be deleted or whose writes are
/// ignored. Each root kind is therefore checked on its own, along with the deliberate
/// over-approximation on virtual dispatch, and the edge of the module, where the walk has to stop
/// for the answer to be about the file rather than about the machine reading it.
/// </remarks>
public sealed class ModuleReachabilityTests : IDisposable
{
    [Theory]
    [InlineData("distinct", false)]
    [InlineData("generic-call", false)]
    [InlineData("member-ref", true)]
    [InlineData("same", true)]
    [InlineData("not-sealed", true)]
    [InlineData("foreign-base", true)]
    [InlineData("managed-slot", true)]
    public void SealedRuntimeDelegateSlotsDoNotDispatchAcrossUnrelatedDelegateTypes(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var left = SyntheticContext.AddType(module, "LeftDelegate");
            var right = SyntheticContext.AddType(module, "RightDelegate");
            foreach (var type in new[] { left, right })
            {
                type.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed;
                type.BaseType = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate");
                type.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void),
                    MethodImplAttributes.Runtime, MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot));
            }
            if (scenario == "not-sealed") right.Attributes &= ~TypeAttributes.Sealed;
            if (scenario == "foreign-base") right.BaseType = new TypeRefUser(module, "System", "MulticastDelegate", new AssemblyRefUser("Foreign"));
            if (scenario == "managed-slot") { right.Methods[0].ImplAttributes = MethodImplAttributes.IL; right.Methods[0].Body = new CilBody(); right.Methods[0].Body.Instructions.Add(OpCodes.Ret.ToInstruction()); }
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public;
            var inputType = new FieldDefUser("InputType", new FieldSig(module.Import(typeof(Type)).ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static);
            api.Fields.Add(inputType);
            var run = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            run.Body.Instructions.Clear();
            // Unknown construction forces the conservative instance-analysis fallback.
            run.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(inputType));
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(module.Import(typeof(Activator).GetMethod("CreateInstance", [typeof(Type)])!)));
            run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            IMethod target = scenario == "same" ? right.Methods[0] : left.Methods[0];
            if (scenario == "member-ref") target = new MemberRefUser(module, "Invoke", right.Methods[0].MethodSig, right);
            if (scenario == "generic-call")
            {
                left.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
                target = new MemberRefUser(module, "Invoke", left.Methods[0].MethodSig,
                    new TypeSpecUser(new GenericInstSig(new ClassSig(left), module.CorLibTypes.Object)));
            }
            run.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(target));
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var candidate = context.Module.GetTypes().Single(t => t.Name == "RightDelegate").Methods[0];
        Assert.Equal(expected, ModuleReachability.Compute(context.Module, false).IsReachable(candidate));
        var withInstances = ModuleReachability.ComputeWithInstances(context.Module, false);
        Assert.NotNull(withInstances.InstanceRefusal);
        Assert.Equal(expected, withInstances.IsReachable(candidate));
    }

    [Theory]
    [InlineData("direct", false)]
    [InlineData("duplicate", true)]
    [InlineData("local-impostor", true)]
    [InlineData("wrong-signature", true)]
    public void ClassInitializationKeepsInitializerDependenciesWithoutExposingOrdinaryMembers(string shape, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var hidden = SyntheticContext.AddType(module, "Hidden");
            var dependency = AddMethod(hidden, "InitializeState", MethodAttributes.Private | MethodAttributes.Static);
            var initializer = AddMethod(hidden, ".cctor", MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            initializer.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(dependency));
            AddMethod(hidden, "Unused", MethodAttributes.Private | MethodAttributes.Static);
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public;
            var run = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            IMethod called = module.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("RunClassConstructor")!);
            if (shape == "local-impostor")
            {
                var fake = SyntheticContext.AddType(module, "RuntimeHelpers");
                fake.Namespace = "System.Runtime.CompilerServices";
                called = new MethodDefUser("RunClassConstructor", called.MethodSig, MethodImplAttributes.Runtime, MethodAttributes.Static | MethodAttributes.Public);
                fake.Methods.Add((MethodDef)called);
            }
            if (shape == "wrong-signature") called = new MemberRefUser(module, called.Name,
                MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), called.DeclaringType);
            run.Body.Instructions.Clear();
            run.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(hidden));
            if (shape == "duplicate") run.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(called));
            if (shape is "duplicate" or "wrong-signature") run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().Single(t => t.Name == "Hidden");
        foreach (var reach in new[] { ModuleReachability.Compute(context.Module, false), ModuleReachability.ComputeWithInstances(context.Module, false) })
        {
            Assert.Equal(exposed, reach.IsReflectivelyExposed(target));
            Assert.True(reach.IsReachable(target.Methods.Single(m => m.Name == ".cctor")));
            Assert.True(reach.IsReachable(target.Methods.Single(m => m.Name == "InitializeState")));
        }
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(3, true)]
    [InlineData(4, false)]
    [InlineData(5, false)]
    [InlineData(6, true)]
    public void AssemblyLookupDoesNotExposeTypeMembersButEscapingHandlesDo(int shape, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var target = SyntheticContext.AddType(module, "Hidden");
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public;
            var run = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            var getType = module.Import(typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle))!);
            var getAssembly = module.Import(typeof(Type).GetProperty(nameof(Type.Assembly))!.GetMethod!);
            run.Body.Instructions.Clear();
            run.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(target));
            if (shape == 4) run.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(getType));
            var slot = new Local(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig());
            if (shape is 5 or 6)
            {
                run.Body.Variables.Add(slot);
                run.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(slot));
                run.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(slot));
            }
            if (shape == 4)
            {
                run.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(module.CorLibTypes.GetTypeRef("System", "Type")));
                run.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            }
            if (shape == 2) run.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
            var getter = OpCodes.Callvirt.ToInstruction(getAssembly);
            if (shape != 1) run.Body.Instructions.Add(getter);
            run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (shape == 6)
            {
                run.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(slot));
                run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (shape == 2) run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (shape == 3)
            {
                run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Br.ToInstruction(getter));
            }
        });
        var target = context.Module.GetTypes().Single(t => t.Name == "Hidden");
        Assert.Equal(exposed, ModuleReachability.Compute(context.Module).IsReflectivelyExposed(target));
        Assert.Equal(exposed, ModuleReachability.ComputeWithInstances(context.Module, false).IsReflectivelyExposed(target));
    }

    [Theory]
    [InlineData("direct", false)]
    [InlineData("typeinfo", false)]
    [InlineData("escape", true)]
    [InlineData("branch", true)]
    [InlineData("foreign", true)]
    public void AssemblyWrapperRequiresEntireNonExposingBody(string shape, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var target = SyntheticContext.AddType(module, "Hidden");
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public;
            var wrapper = new MethodDefUser("Lookup", MethodSig.CreateStatic(
                module.Import(typeof(System.Reflection.Assembly)).ToTypeSig(), module.Import(typeof(Type)).ToTypeSig()))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            api.Methods.Add(wrapper);
            wrapper.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (shape == "escape")
            {
                wrapper.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
                wrapper.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(module.Import(typeof(Type).GetMethod("GetMethods", Type.EmptyTypes)!)));
                wrapper.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (shape == "typeinfo")
            {
                wrapper.Body.Instructions.Add(OpCodes.Call.ToInstruction(module.Import(typeof(System.Reflection.IntrospectionExtensions).GetMethod("GetTypeInfo")!)));
                wrapper.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(module.Import(typeof(System.Reflection.TypeInfo))));
            }
            var owner = shape == "typeinfo" ? typeof(System.Reflection.TypeInfo) : typeof(Type);
            IMethod getter = module.Import(owner.GetProperty("Assembly")!.GetMethod!);
            // Reflection may return the inherited Type declaration; use the legal TypeInfo MemberRef explicitly.
            if (shape == "typeinfo") getter = new MemberRefUser(module, "get_Assembly",
                MethodSig.CreateInstance(module.Import(typeof(System.Reflection.Assembly)).ToTypeSig()), module.Import(owner));
            if (shape == "foreign") getter = new MemberRefUser(module, "get_Assembly", getter.MethodSig,
                new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Untrusted")));
            var call = OpCodes.Callvirt.ToInstruction(getter);
            if (shape == "branch") wrapper.Body.Instructions.Add(OpCodes.Br.ToInstruction(call));
            wrapper.Body.Instructions.Add(call);
            wrapper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var run = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            run.Body.Instructions.Clear();
            run.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(target));
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(module.Import(typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle))!)));
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(wrapper));
            run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().Single(t => t.Name == "Hidden");
        Assert.Equal(exposed, ModuleReachability.Compute(context.Module).IsReflectivelyExposed(target));
        Assert.Equal(exposed, ModuleReachability.ComputeWithInstances(context.Module, false).IsReflectivelyExposed(target));
    }

    private readonly string _folder =
        Directory.CreateTempSubdirectory("Cilantro.Reachability").FullName;

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    [Fact]
    public void PublicSurfaceAndWhatItCallsAreReachable()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Api");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var helper = AddMethod(type, "Helper", MethodAttributes.Private | MethodAttributes.Static);
            var entry = AddMethod(type, "Run", MethodAttributes.Public | MethodAttributes.Static);
            entry.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(helper));
        });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.True(reachability.IsReachable(Find(context, "Run")));
        Assert.True(reachability.IsReachable(Find(context, "Helper")));
    }

    [Fact]
    public void PublicMethodOfANonPublicTypeIsNotAnEntryFromOutside()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Internal");
            AddMethod(type, "Orphan", MethodAttributes.Public | MethodAttributes.Static);
        });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.False(reachability.IsReachable(Find(context, "Orphan")));
    }

    [Fact]
    public void TypeInitializersAndFinalizersAreRootsTheRuntimeInvokes()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Hidden");
            AddMethod(
                type,
                ".cctor",
                MethodAttributes.Private | MethodAttributes.Static |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            AddMethod(type, "Finalize", MethodAttributes.Family | MethodAttributes.Virtual, isStatic: false);
        });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.True(reachability.IsReachable(Find(context, ".cctor")));
        Assert.True(reachability.IsReachable(Find(context, "Finalize")));
    }

    [Fact]
    public void CallvirtKeepsEveryOverrideThatCouldSatisfyIt()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public | TypeAttributes.Class;

            var baseType = SyntheticContext.AddType(module, "Shape");
            var declared = AddMethod(
                baseType, "Draw", MethodAttributes.Public | MethodAttributes.Virtual, isStatic: false);

            var derived = SyntheticContext.AddType(module, "Circle");
            derived.BaseType = baseType;
            AddMethod(
                derived, "Draw", MethodAttributes.Public | MethodAttributes.Virtual, isStatic: false);

            var entry = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            entry.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
            entry.Body.Instructions.Insert(1, OpCodes.Callvirt.ToInstruction(declared));
        });

        var reachability = ModuleReachability.Compute(context.Module);

        var overrides = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.Name == "Draw")
            .ToArray();
        Assert.Equal(2, overrides.Length);
        Assert.All(overrides, method => Assert.True(reachability.IsReachable(method)));
    }

    [Fact]
    public void AVirtualMethodOfATypeNothingConstructsCannotBeCalled()
    {
        using var context = SyntheticContext.Build(module => Shapes(module, construct: false));

        var narrowed = ModuleReachability.ComputeWithInstances(
            context.Module, typeInitializersAlwaysRun: true);

        Assert.Null(narrowed.InstanceRefusal);
        // Only the shape of the call reaches this one, Circle deriving from nothing the call names,
        // and a call arrives on an instance that nothing here makes.
        Assert.False(narrowed.IsReachable(OnCircle(context)));
        // Which is the whole of the difference: the wider reading keeps it on the shape alone.
        Assert.True(ModuleReachability.Compute(context.Module).IsReachable(OnCircle(context)));
    }

    [Fact]
    public void AVirtualMethodIsCalledOnceSomethingConstructsItsType()
    {
        using var context = SyntheticContext.Build(module => Shapes(module, construct: true));

        var narrowed = ModuleReachability.ComputeWithInstances(
            context.Module, typeInitializersAlwaysRun: true);

        Assert.Null(narrowed.InstanceRefusal);
        Assert.True(narrowed.IsReachable(OnCircle(context)));
    }

    [Fact]
    public void NoVirtualMethodIsDroppedWhereAnInstanceCanBeMadeWithoutNamingItsType()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = Shapes(module, construct: false);
            var made = new MemberRefUser(
                module,
                "CreateInstance",
                MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.String),
                module.CorLibTypes.GetTypeRef("System", "Activator"));
            var body = api.Methods.Single(method => method.Name == "Run").Body.Instructions;
            body.Insert(0, OpCodes.Ldstr.ToInstruction("whichever type this turns out to name"));
            body.Insert(1, OpCodes.Call.ToInstruction(made));
            body.Insert(2, OpCodes.Pop.ToInstruction());
            api.Methods.Single(method => method.Name == "Run").Body.MaxStack = 8;
        });

        var narrowed = ModuleReachability.ComputeWithInstances(
            context.Module, typeInitializersAlwaysRun: true);

        Assert.NotNull(narrowed.InstanceRefusal);
        Assert.Contains("without naming its type", narrowed.InstanceRefusal, StringComparison.Ordinal);
        // Refused whole rather than narrowly: there is no type the unnamed instance could not be of.
        Assert.True(narrowed.IsReachable(OnCircle(context)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FixedTypeForwardersAreNarrowedButCyclesAreNot(bool cycle)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = Shapes(module, construct: false);
            var run = api.Methods.Single(m => m.Name == "Run");
            var typeSig = module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
            var helper = new MethodDefUser("NamedType", MethodSig.CreateStatic(typeSig))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            api.Methods.Add(helper);
            var forward = new MethodDefUser("Forward", MethodSig.CreateStatic(typeSig))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            api.Methods.Add(forward);
            forward.Body.Instructions.Add(OpCodes.Call.ToInstruction(helper));
            forward.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (cycle) helper.Body.Instructions.Add(OpCodes.Call.ToInstruction(forward));
            else {
                helper.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(api));
                helper.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle",
                    MethodSig.CreateStatic(typeSig, new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
                    module.CorLibTypes.GetTypeRef("System", "Type"))));
            }
            helper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var make = new MemberRefUser(module, "CreateInstance", MethodSig.CreateStatic(module.CorLibTypes.Object, typeSig),
                module.CorLibTypes.GetTypeRef("System", "Activator"));
            run.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(forward));
            run.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(make));
            run.Body.Instructions.Insert(2, OpCodes.Pop.ToInstruction());
        });
        var reach = ModuleReachability.ComputeWithInstances(context.Module, true);
        Assert.Equal(cycle, reach.InstanceRefusal is not null);
        Assert.Equal(cycle, reach.IsReachable(OnCircle(context)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownReflectionCannotBootstrapAnUninstantiatedReceiver(bool construct)
    {
        using var context = SyntheticContext.Build(module =>
        {
            Shapes(module, construct);
            var draw = module.GetTypes().Single(t => t.Name == "Circle").Methods.Single(m => m.Name == "Draw");
            var make = new MemberRefUser(module, "CreateInstance", MethodSig.CreateStatic(module.CorLibTypes.Object,
                module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig()), module.CorLibTypes.GetTypeRef("System", "Activator"));
            // Unknown type supplied through a field, inside the otherwise unreachable method.
            var field = new FieldDefUser("TypeInput", new FieldSig(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig()), FieldAttributes.Static);
            draw.DeclaringType.Fields.Add(field);
            draw.Body.Instructions.Insert(0, OpCodes.Ldsfld.ToInstruction(field));
            draw.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(make));
            draw.Body.Instructions.Insert(2, OpCodes.Pop.ToInstruction());
        });
        var reach = ModuleReachability.ComputeWithInstances(context.Module, false);
        Assert.Equal(construct, reach.InstanceRefusal is not null);
        Assert.Equal(construct, reach.IsReachable(OnCircle(context)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [InlineData(false, true)]
    [InlineData(true, false, true)]
    public void ReflectiveTypeInASingleAssignmentLocalDoesNotRetainUnrelatedVirtuals(bool reassigned, bool alternateEntry = false, bool unknown = false)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = Shapes(module, construct: false);
            var run = api.Methods.Single(m => m.Name == "Run");
            var local = new Local(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig());
            run.Body.Variables.Add(local); run.Body.InitLocals = true;
            var get = new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(local.Type, new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
                module.CorLibTypes.GetTypeRef("System", "Type"));
            var make = new MemberRefUser(module, "CreateInstance", MethodSig.CreateStatic(module.CorLibTypes.Object, local.Type),
                module.CorLibTypes.GetTypeRef("System", "Activator"));
            var prefix = new List<Instruction> { OpCodes.Ldtoken.ToInstruction(api), OpCodes.Call.ToInstruction(get), OpCodes.Stloc.ToInstruction(local) };
            if (reassigned) { prefix.Add(OpCodes.Ldnull.ToInstruction()); prefix.Add(OpCodes.Stloc.ToInstruction(local)); }
            if (unknown)
            {
                var field = new FieldDefUser("TypeInput", new FieldSig(local.Type), FieldAttributes.Public | FieldAttributes.Static);
                api.Fields.Add(field);
                prefix.Add(OpCodes.Ldsfld.ToInstruction(field)); prefix.Add(OpCodes.Stloc.ToInstruction(local));
            }
            prefix.Add(OpCodes.Ldloc.ToInstruction(local)); prefix.Add(OpCodes.Call.ToInstruction(make)); prefix.Add(OpCodes.Pop.ToInstruction());
            if (alternateEntry)
            {
                prefix.Insert(0, OpCodes.Br.ToInstruction(prefix[^2]));
                prefix.Insert(0, OpCodes.Ldnull.ToInstruction());
            }
            for (var i = 0; i < prefix.Count; i++) run.Body.Instructions.Insert(i, prefix[i]);
        });
        var reach = ModuleReachability.ComputeWithInstances(context.Module, true);
        Assert.Equal(alternateEntry || unknown, reach.InstanceRefusal is not null);
        Assert.Equal(alternateEntry || unknown, reach.IsReachable(OnCircle(context)));
    }

    /// <summary>
    /// A virtual call whose shape one type's method matches, that type being constructed or not.
    /// </summary>
    private static TypeDefUser Shapes(ModuleDefUser module, bool construct)
    {
        var api = SyntheticContext.AddType(module, "Api");
        api.Attributes = TypeAttributes.Public | TypeAttributes.Class;

        var baseType = SyntheticContext.AddType(module, "Shape");
        var declared = AddMethod(
            baseType, "Draw", MethodAttributes.Public | MethodAttributes.Virtual, isStatic: false);

        // Deliberately not derived from the type the call names, so nothing but the shape of the
        // call reaches it. This is the interpreter's shape: methods a call could satisfy, on types
        // the call could never be holding.
        var other = SyntheticContext.AddType(module, "Circle");
        AddMethod(other, "Draw", MethodAttributes.Public | MethodAttributes.Virtual, isStatic: false);
        var constructor = AddMethod(
            other, ".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName,
            isStatic: false);

        var entry = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
        var body = entry.Body.Instructions;
        var at = 0;
        if (construct)
        {
            body.Insert(at++, OpCodes.Newobj.ToInstruction(constructor));
            body.Insert(at++, OpCodes.Pop.ToInstruction());
        }
        // It answers with nothing, so nothing is taken off after it.
        body.Insert(at++, OpCodes.Ldnull.ToInstruction());
        body.Insert(at, OpCodes.Callvirt.ToInstruction(declared));
        return api;
    }

    /// <summary>The method only the shape of the call reaches.</summary>
    private static MethodDef OnCircle(Core.ArtifactContext context) => context.Module.GetTypes()
        .Single(type => type.Name == "Circle")
        .Methods.Single(method => method.Name == "Draw");

    [Fact]
    public void LoadingATypeHandleExposesItToReflectionWithoutRunningIt()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var hidden = SyntheticContext.AddType(module, "Hidden");
            AddMethod(hidden, "Never", MethodAttributes.Private | MethodAttributes.Static);

            var entry = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            entry.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(hidden));
            entry.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        });

        var reachability = ModuleReachability.Compute(context.Module);

        var hidden = context.Module.GetTypes().Single(type => type.Name == "Hidden");
        Assert.True(reachability.IsReflectivelyExposed(hidden));
        Assert.False(reachability.IsReachable(Find(context, "Never")));
    }

    /// <summary>
    /// A body outside the module is not read, however resolvable it happens to be here.
    /// </summary>
    /// <remarks>
    /// This is what made the same sample clean up differently on two machines. The walk followed a
    /// call out of the module, and on a machine whose framework was installed it found a body,
    /// stepped into somebody else's IL, and marked this module's methods reachable wherever that
    /// IL called something of a matching shape — so scaffolding that was plainly dead on one desk
    /// was kept on another. The library here stands in for that framework: resolvable, never
    /// supplied, and calling something shaped like a method of the sample it knows nothing about.
    /// </remarks>
    [Fact]
    public void SomebodyElsesBodyIsNotReadEvenWhenItIsThereToRead()
    {
        var library = WriteLibraryCalling("helper", "Draw");
        using var context = Core.ArtifactContext.Load(WriteCallerOf("caller", "helper"), [library]);
        // The point of the test is a body that is there to be stepped into, so say so.
        var reference = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions)
            .Where(instruction => instruction.OpCode == OpCodes.Call)
            .Select(instruction => (IMethod)instruction.Operand)
            .First();
        Assert.True(reference.ResolveMethodDef() is { HasBody: true });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.False(reachability.IsReachable(Find(context, "Draw")));
        Assert.All(
            reachability.ReachableMethods,
            method => Assert.Same(context.Module, method.Module));
    }

    /// <summary>
    /// A library whose one method calls something named <paramref name="calls"/>, matching the
    /// shape of a method the sample declares and nothing in the sample calls.
    /// </summary>
    private string WriteLibraryCalling(string name, string calls)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Library", "Answers", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(type);
        var method = new MethodDefUser(
            "Answer", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Callvirt,
            new MemberRefUser(
                module,
                calls,
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                type)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 41));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    /// <summary>
    /// A sample that calls into the library, and separately declares a virtual method of the shape
    /// the library's body calls, which nothing in the sample reaches.
    /// </summary>
    private string WriteCallerOf(string name, string library)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var reference = new AssemblyRefUser(library, new Version(1, 0, 0, 0));
        module.UpdateRowId(reference);

        var api = new TypeDefUser("Sample", "Api", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(api);
        var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        run.Body.Instructions.Add(Instruction.Create(
            OpCodes.Call,
            new MemberRefUser(
                module,
                "Answer",
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                new TypeRefUser(module, "Library", "Answers", reference))));
        run.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        api.Methods.Add(run);

        // Not visible from outside and nothing here calls it, so the only way it could be reached
        // is by reading the library's body.
        var scaffolding = new TypeDefUser(
            "Sample", "Scaffolding", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(scaffolding);
        scaffolding.Methods.Add(new MethodDefUser(
            "Draw", MethodSig.CreateInstance(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Virtual |
                MethodAttributes.NewSlot,
            Body = new CilBody()
        });
        scaffolding.FindMethod("Draw").Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    private static MethodDefUser AddMethod(
        TypeDef type, string name, MethodAttributes attributes, bool isStatic = true)
    {
        var signature = isStatic
            ? MethodSig.CreateStatic(type.Module.CorLibTypes.Void)
            : MethodSig.CreateInstance(type.Module.CorLibTypes.Void);
        var method = new MethodDefUser(name, signature, MethodImplAttributes.IL, attributes)
        {
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(method);
        return method;
    }

    private static MethodDef Find(Core.ArtifactContext context, string name) =>
        context.Module.GetTypes().SelectMany(type => type.Methods).First(method => method.Name == name);
}
