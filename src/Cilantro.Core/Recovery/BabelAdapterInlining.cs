using Cilantro.Core.Analysis;
using Cilantro.Core.Proxy;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Copies proved, initialization-free adapter casts and temporaries into callers.</summary>
internal static class BabelAdapterInlining
{
    internal static int Run(ArtifactContext context, out string diagnostic)
    {
        diagnostic = "No retired Babel adapter needed cast/local expansion.";
        if (!context.TryGetFact<IReadOnlySet<MethodDef>>(BabelProxyInitializationPass.RetiredWrappersFact, out var retired) || retired is null) return 0;
        var wrappers = retired.Where(method => method.DeclaringType?.Module == context.Module && Supported(method)).ToHashSet();
        if (wrappers.Count == 0) return 0;
        var sites = wrappers.ToDictionary(method => method, _ => new List<(MethodDef Caller, Instruction Site)>());
        foreach (var caller in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
            foreach (var site in caller.Body.Instructions)
                if (site.OpCode.Code == Code.Call && site.Operand is IMethod called && called is not MethodSpec &&
                    called.ResolveMethodDef() is { } target && sites.TryGetValue(target, out var entries)) entries.Add((caller, site));
        using var batch = new BodyMutationBatch();
        var bypassed = new HashSet<MethodDef>(); var changed = new HashSet<MethodDef>(); var count = 0;
        foreach (var wrapper in Order(wrappers))
        {
            if (!Supported(wrapper)) continue;
            var invoke = wrapper.Body.Instructions.Single(instruction => instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj);
            foreach (var (caller, site) in sites[wrapper])
            {
                if (!caller.Body.InitLocals && caller.Body.Variables.Count != 0) continue;
                if (count >= 8192 || site.OpCode.Code != Code.Call || site.Operand is not IMethod called || called.ResolveMethodDef() != wrapper || caller == wrapper ||
                    caller.Body.Instructions.Count > 65_536 || caller.Body.Variables.Count + wrapper.Parameters.Count + wrapper.Body.Variables.Count > 4096) continue;
                var index = caller.Body.Instructions.IndexOf(site);
                if (index > 0 && caller.Body.Instructions[index - 1].OpCode.OpCodeType == OpCodeType.Prefix) continue;
                if (!BabelProxyRecoveryPass.CallableFrom(caller, (IMethod)invoke.Operand, invoke.OpCode.Code) ||
                    wrapper.Parameters.Any(parameter => !BabelProxyRecoveryPass.AccessibleType(parameter.Type, caller)) ||
                    wrapper.Body.Variables.Any(local => !BabelProxyRecoveryPass.AccessibleType(local.Type, caller)) ||
                    wrapper.Body.Instructions.Select(instruction => instruction.Operand).OfType<ITypeDefOrRef>()
                        .Any(type => !BabelProxyRecoveryPass.AccessibleType(type.ToTypeSig(), caller))) continue;
                batch.Capture(caller);
                var arguments = wrapper.Parameters.Select(parameter => new Local(parameter.Type)).ToArray();
                var locals = wrapper.Body.Variables.ToDictionary(local => local, local => new Local(local.Type));
                foreach (var local in arguments.Concat(locals.Values)) caller.Body.Variables.Add(local);
                var expanded = arguments.Reverse().Select(local => OpCodes.Stloc.ToInstruction(local)).ToList();
                foreach (var instruction in wrapper.Body.Instructions)
                {
                    if (instruction.OpCode.Code is Code.Nop or Code.Ret) continue;
                    if (instruction.IsLdarg()) expanded.Add(OpCodes.Ldloc.ToInstruction(arguments[instruction.GetParameter(wrapper.Parameters)!.Index]));
                    else if (instruction.OpCode.Code is Code.Ldarga or Code.Ldarga_S) expanded.Add(OpCodes.Ldloca.ToInstruction(arguments[instruction.GetParameter(wrapper.Parameters)!.Index]));
                    else if (instruction.IsLdloc()) expanded.Add(OpCodes.Ldloc.ToInstruction(locals[instruction.GetLocal(wrapper.Body.Variables)!]));
                    else if (instruction.IsStloc()) expanded.Add(OpCodes.Stloc.ToInstruction(locals[instruction.GetLocal(wrapper.Body.Variables)!]));
                    else if (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) expanded.Add(OpCodes.Ldloca.ToInstruction(locals[instruction.GetLocal(wrapper.Body.Variables)!]));
                    else expanded.Add(new(instruction.OpCode, instruction.Operand));
                }
                // Keep the original instruction object as the entry so branches and
                // exception boundaries continue to enter before argument transport.
                site.OpCode = expanded[0].OpCode; site.Operand = expanded[0].Operand;
                for (var offset = 1; offset < expanded.Count; offset++) caller.Body.Instructions.Insert(index + offset, expanded[offset]);
                caller.Body.InitLocals = true; caller.Body.KeepOldMaxStack = false;
                bypassed.Add(wrapper); changed.Add(caller); count++;
                batch.RecordChange(context, new("babel-proxy-inlining", "inline-babel-adapter", caller.FullName,
                    $"Expanded retired adapter {wrapper.MDToken} with its original casts, boxing, argument values and distinct temporary locals; initialization was already proved retired."));
            }
        }
        if (count == 0) return 0;
        if (changed.Any(method => !EvaluationStackAnalyzer.Analyze(method).Valid) ||
            !AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
        { diagnostic = "Adapter expansion failed verification; original caller bodies retained."; return 0; }
        batch.Commit(); RecoveryOrphans.Declare(context, bypassed);
        context.TryGetFact<int>("babel.proxies.expandedAdapters", out var previous); context.SetFact("babel.proxies.expandedAdapters", previous + count);
        diagnostic = $"Expanded {count} retired Babel adapter calls, preserving casts and temporary storage.";
        return count;
    }

    private static IEnumerable<MethodDef> Order(HashSet<MethodDef> wrappers)
    {
        var users = wrappers.ToDictionary(method => method, _ => new List<MethodDef>());
        var leaves = new Queue<MethodDef>();
        foreach (var wrapper in wrappers.OrderBy(method => method.MDToken.Raw))
        {
            var target = ((IMethod)wrapper.Body.Instructions.Single(instruction => instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj).Operand).ResolveMethodDef();
            if (target is not null && users.TryGetValue(target, out var callers)) callers.Add(wrapper);
            else leaves.Enqueue(wrapper);
        }
        // A single-call adapter has at most one dependency. Cycles and callers
        // feeding a cycle never enter the queue; acyclic chains expand from leaves.
        while (leaves.TryDequeue(out var wrapper))
        {
            yield return wrapper;
            foreach (var caller in users[wrapper]) leaves.Enqueue(caller);
        }
    }

    private static bool Supported(MethodDef method)
    {
        if (!method.IsStatic || !method.HasBody || method.HasGenericParameters || method.MethodSig is not { CallingConvention: CallingConvention.Default } ||
            method.DeclaringType.BaseType?.FullName != "System.MulticastDelegate" || method.DeclaringType.HasGenericParameters ||
            method.DeclaringType.Methods.Any(initializer => initializer.IsStaticConstructor && !EmptyTypeInitializers.DoesNothing(initializer)) ||
            method.Body.ExceptionHandlers.Count != 0 || method.Body.Instructions.Count > 256 || method.Body.Variables.Count > 32 ||
            method.Parameters.Count > 32 || method.ReturnType.IsByRef || method.ReturnType.IsPointer || method.ReturnType.ContainsGenericParameter || method.Parameters.Any(parameter => parameter.Type.ContainsGenericParameter) ||
            method.Body.Variables.Any(local => local.Type.ContainsGenericParameter)) return false;
        for (var owner = method.DeclaringType.DeclaringType; owner is not null; owner = owner.DeclaringType)
            if (owner.HasGenericParameters) return false;
        var assigned = new HashSet<Local>(); var calls = 0; var il = method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        if (il.Length == 0 || il[^1].OpCode.Code != Code.Ret || !EvaluationStackAnalyzer.Analyze(method).Valid) return false;
        foreach (var instruction in il[..^1])
        {
            if (instruction.IsLdarg() || instruction.OpCode.Code is Code.Ldarga or Code.Ldarga_S)
            { if (instruction.GetParameter(method.Parameters) is null) return false; continue; }
            if (instruction.IsStloc()) { if (instruction.GetLocal(method.Body.Variables) is not { } local) return false; assigned.Add(local); continue; }
            if (instruction.IsLdloc() || instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            { if (instruction.GetLocal(method.Body.Variables) is not { } local || !assigned.Contains(local)) return false; continue; }
            if (instruction.OpCode.Code is Code.Castclass or Code.Box or Code.Unbox or Code.Unbox_Any)
            { if (instruction.Operand is not ITypeDefOrRef type || type.ToTypeSig().ContainsGenericParameter) return false; continue; }
            if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod target && !MethodInliningPass.IsContextSensitiveTarget(target))
            { calls++; continue; }
            return false;
        }
        return calls == 1;
    }
}
