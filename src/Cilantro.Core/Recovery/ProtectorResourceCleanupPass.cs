using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Removes decoded protector tables only after their access paths have disappeared.</summary>
public sealed class ProtectorResourceCleanupPass : DeobfuscationPass
{
    public override string Name => "protector-resource-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["string-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Protector resource cleanup is disabled."]);
        context.TryGetFact<IReadOnlyList<RecoveredResourceOrigin>>("strings.validatedResources", out var strings);
        context.TryGetFact<RecoveredResourceOrigin>("proxy.validatedResource", out var proxy);
        context.TryGetFact<IReadOnlyList<RestoredResourceBundle>>("resources.validatedBundles", out var bundles);
        context.TryGetFact<IReadOnlyList<RecoveredResourceOrigin>>(DependencyInputCompletionPass.RetiredResourcesFact, out var dependencies);
        context.TryGetFact<IReadOnlyList<RetiredIntegrityResource>>(RetiredIntegrityResource.Fact, out var retiredIntegrity);
        var removedOwnerOrigins = LoaderDataOrigins(context).Concat(NecroBitResourceOwnership.RemovedOrigins(context))
            .Concat(IntegrityResourceOwnership.RemovedOrigins(context)).Concat(NumericResourceOwnership.RemovedOrigins(context))
            .Concat(DecodedResourceOwnership.RemovedOrigins(context))
            .Concat((retiredIntegrity ?? []).Where(p => p.IsPreserved(context.Module)).Select(p => p.Source)).Distinct().ToArray();
        var origins = (strings ?? []).Concat(proxy is null ? [] : new[] { proxy })
            .Concat((bundles ?? []).Where(bundle => bundle.IsPreserved(context.Module)).Select(bundle => bundle.Source))
            .Concat(removedOwnerOrigins).Concat(dependencies ?? []).ToArray();
        if (origins.Length == 0) return (PassStatus.Success, 0, ["No successfully decoded input resource is attributed."]);
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var closedAccesses = ClosedReflectionAccesses(context.Module, methods);
        var resourceManagers = ClosedResourceManagers.Find(context.Module);
        closedAccesses.UnionWith(resourceManagers.Accesses);
        closedAccesses.UnionWith(ClosedDebuggerReflection.Find(context.Module));
        var queryImports = ClosedNativeQueryImports.Find(context.Module);
        bool KnownImport(MethodDef method) => IsKnownNonResourceImport(method) || queryImports.Contains(method);
        // Computed names need no literal reference. Retain tables whenever any remaining code
        // can read resources, reflectively obtain a reader, or enter unknown native code.
        bool Blocks(Instruction i) =>
            i.OpCode.Code == Code.Calli || i.Operand is IMethod c &&
            !closedAccesses.Contains(i) &&
            !IsFrameworkTypeHandle(context.Module, i, c) &&
            (c.Name.String.Contains("Resource", StringComparison.Ordinal) ||
             c.DeclaringType.FullName.StartsWith("System.Resources.", StringComparison.Ordinal) ||
             c.DeclaringType.FullName.StartsWith("System.Reflection", StringComparison.Ordinal) ||
             c.DeclaringType.FullName is "System.Type" or "System.Activator" ||
             c.DeclaringType.FullName is "System.Runtime.InteropServices.NativeLibrary" or "System.Runtime.Loader.AssemblyLoadContext" ||
             c.Name == "DynamicInvoke");
        var blockers = methods.Where(m => m.IsPinvokeImpl && !KnownImport(m) || m.HasBody && m.Body.Instructions.Any(Blocks)).ToArray();
        context.TryGetFact<IReadOnlyList<RetiredDependencyResource>>(RetiredDependencyResource.Fact, out var proofs);
        // Full unprotection permits deliberate removal of proven obsolete protector
        // metadata, including resources observable through general-purpose APIs.
        // Attribution alone is insufficient: require a physically retired owner or
        // an intact verified replacement. Application/payload roles and explicit
        // surviving name references remain protected below.
        var retiredOrigins = (proofs ?? []).Where(p => p.IsPreserved(context.Module)).Select(p => p.Source)
            .Concat(removedOwnerOrigins).Where(o => context.Module.Resources.Count(r => r.Name == o.Name) == 1).ToArray();
        if (blockers.Length != 0 && retiredOrigins.Length == 0)
            return (PassStatus.Success, 0, ["Retained decoded resources because computed resource access remains possible in " +
                string.Join(", ", blockers.Take(5).Select(m => m.FullName)) + (blockers.Length > 5 ? ", ..." : "") + "."]);
        var literals = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var roles);
        var applicationNames = (bundles ?? []).SelectMany(bundle => bundle.Entries).Select(entry => entry.Name)
            .Concat((roles ?? []).Where(role => role.Role is ResourceRole.ManagedPayload or ResourceRole.NativePayload or ResourceRole.RestoredApplicationResource)
                .Select(role => role.Resource)).ToHashSet(StringComparer.Ordinal);
        applicationNames.UnionWith(resourceManagers.ReservedNames);
        var candidates = context.Module.Resources.OfType<EmbeddedResource>()
            .Where(r => !applicationNames.Contains(r.Name.String) && !literals.Contains(r.Name.String) && origins.Any(o => o.Matches(r)))
            .Where(r => blockers.Length == 0 || retiredOrigins.Any(o => o.Matches(r)))
            .Select(r => (Resource: r, Index: context.Module.Resources.IndexOf(r))).ToArray();
        if (candidates.Length == 0) return (PassStatus.Success, 0, ["No decoded resource has lost all consumers."]);
        var old = CilantroPipeline.BuildRewriteAllowance(context);
        var removed = old.RemovedResourceSet.Concat(candidates.Select(p => p.Resource.Name.String)).ToHashSet(StringComparer.Ordinal);
        var committed = false;
        try
        {
            foreach (var candidate in candidates) context.Module.Resources.Remove(candidate.Resource);
            var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                old with { RemovedResources = removed });
            if (!check.Passed) return (PassStatus.Partial, 0, ["Resource removal rolled back: " + string.Join("; ", check.Diagnostics)]);
            committed = true;
        }
        finally
        {
            if (!committed)
                foreach (var candidate in candidates.OrderBy(p => p.Index))
                    context.Module.Resources.Insert(candidate.Index, candidate.Resource);
        }
        context.SetFact<IReadOnlySet<string>>("cleanup.removedResources", removed);
        foreach (var candidate in candidates)
            context.AddChange(new(Name, "remove-decoded-protector-resource", candidate.Resource.Name.String,
                $"Removed attributed protector data after its consumers disappeared; SHA-256 {RecoveredResourceOrigin.Capture(candidate.Resource).Sha256}." +
                (blockers.Length != 0 ? " The protector owner was physically removed or its verified replacement remains intact; deliberate protector-metadata removal permits general-purpose introspection to observe its absence." : "")));
        return (PassStatus.Success, candidates.Length, [$"Removed {candidates.Length} obsolete decoded protector resource(s)."]);
    }

    private static bool IsFrameworkTypeHandle(ModuleDef module, Instruction instruction, IMethod method) =>
        instruction.OpCode.Code == Code.Call &&
        method.DeclaringType is TypeRef type &&
        type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
        method.FullName == "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)" &&
        method.MethodSig is { HasThis: false, GenParamCount: 0 };

    private static HashSet<Instruction> ClosedReflectionAccesses(ModuleDef module, IEnumerable<MethodDef> methods)
    {
        var known = new HashSet<Instruction>();
        foreach (var method in methods.Where(method => method.HasBody))
        {
            known.UnionWith(ClosedStackTraceNames.Find(method));
            known.UnionWith(ClosedDiscardedAssembly.Find(method));
            var instructions = method.Body.Instructions;
            var entries = instructions.SelectMany(instruction => instruction.Operand switch
            {
                Instruction target => new[] { target },
                IList<Instruction> targets => targets,
                _ => (IEnumerable<Instruction>)[]
            }).ToHashSet();
            foreach (var handler in method.Body.ExceptionHandlers)
                foreach (var entry in new[] { handler.TryStart, handler.HandlerStart, handler.FilterStart }.OfType<Instruction>())
                    entries.Add(entry);
            for (var index = 0; index + 2 < instructions.Count; index++)
            {
                if (instructions[index].OpCode.Code == Code.Newobj &&
                    FrameworkCall(instructions[index], "System.Void System.Reflection.AssemblyName::.ctor(System.String)"))
                {
                    var cursor = SkipMetadataReceiver(index + 1, "System.Reflection.AssemblyName");
                    if (cursor < instructions.Count && IsCall(instructions[cursor]) &&
                        FrameworkCall(instructions[cursor], "System.String System.Reflection.AssemblyName::get_FullName()") &&
                        !instructions.Skip(index + 1).Take(cursor - index).Any(entries.Contains))
                    {
                        // Parsing a display name yields a string, not an Assembly
                        // or a resource reader. Keep parsing/throwing behavior intact.
                        known.Add(instructions[index]); known.Add(instructions[cursor]);
                    }
                }
                if (instructions[index].OpCode.Code != Code.Call) continue;
                if (FrameworkCall(instructions[index], "System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()"))
                {
                    var cursor = SkipMetadataReceiver(index + 1, "System.Reflection.Assembly");
                    if (cursor < instructions.Count && IsCall(instructions[cursor]) &&
                        FrameworkCall(instructions[cursor], "System.Reflection.AssemblyName System.Reflection.Assembly::GetName()"))
                    {
                        var getName = cursor;
                        cursor = SkipMetadataReceiver(cursor + 1, "System.Reflection.AssemblyName");
                        if (cursor < instructions.Count && IsCall(instructions[cursor]) &&
                            (FrameworkCall(instructions[cursor], "System.String System.Reflection.AssemblyName::get_Name()") ||
                             FrameworkCall(instructions[cursor], "System.Byte[] System.Reflection.AssemblyName::GetPublicKey()")) &&
                            !instructions.Skip(index + 1).Take(cursor - index).Any(entries.Contains))
                        {
                            // The runtime assembly and AssemblyName never escape this expression.
                            // Initialization calls remain unchanged and their bodies are checked
                            // independently for resource/reflection access by the enclosing pass.
                            known.Add(instructions[index]); known.Add(instructions[getName]); known.Add(instructions[cursor]);
                        }
                    }
                }
                var nameIndex = index + 1;
                while (nameIndex < instructions.Count && instructions[nameIndex].OpCode.Code == Code.Nop) nameIndex++;
                var readIndex = nameIndex + 1;
                while (readIndex < instructions.Count && instructions[readIndex].OpCode.Code == Code.Nop) readIndex++;
                // Lifted bodies sometimes spill the name while restoring the receiver's
                // type. Accept only the closed store/cast/reload expression: no calls,
                // writes or alternate entries can change the name or receiver within it.
                if (readIndex + 2 < instructions.Count && instructions[readIndex].IsStloc() &&
                    instructions[readIndex].GetLocal(method.Body.Variables) is { } local &&
                    local.Type.ElementType == ElementType.String &&
                    instructions[readIndex + 1].OpCode.Code == Code.Castclass &&
                    instructions[readIndex + 1].Operand is TypeRef cast &&
                    cast.FullName == "System.Reflection.Assembly" &&
                    cast.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
                    instructions[readIndex + 2].IsLdloc() &&
                    instructions[readIndex + 2].GetLocal(method.Body.Variables) == local)
                {
                    readIndex += 3;
                    while (readIndex < instructions.Count && instructions[readIndex].OpCode.Code == Code.Nop) readIndex++;
                }
                if (readIndex >= instructions.Count) continue;
                var assembly = instructions[index]; var name = instructions[nameIndex]; var read = instructions[readIndex];
                if (assembly.OpCode.Code != Code.Call || name.OpCode.Code != Code.Ldstr || name.Operand is not string ||
                    read.OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    instructions.Skip(index + 1).Take(readIndex - index).Any(entries.Contains) ||
                    !FrameworkCall(assembly, "System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()") ||
                    !FrameworkCall(read, "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)")) continue;
                // Both API calls belong to this closed expression. The existing literal-name
                // retention check below protects the exact resource it reads.
                known.Add(assembly); known.Add(read);
            }

            int SkipMetadataReceiver(int cursor, string typeName)
            {
                cursor = SkipInitialization(cursor);
                if (cursor < instructions.Count && instructions[cursor].OpCode.Code == Code.Castclass &&
                    instructions[cursor].Operand is TypeRef cast && cast.FullName == typeName &&
                    cast.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName)
                    cursor = SkipInitialization(cursor + 1);
                return cursor;
            }

            int SkipInitialization(int cursor)
            {
                while (cursor < instructions.Count)
                {
                    if (instructions[cursor].OpCode.Code == Code.Nop) { cursor++; continue; }
                    if (cursor + 1 < instructions.Count && instructions[cursor].OpCode.Code == Code.Ldtoken &&
                        instructions[cursor].Operand is TypeDef type && type.Module == module &&
                        instructions[cursor + 1].OpCode.Code == Code.Call &&
                        FrameworkCall(instructions[cursor + 1], "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)"))
                    { cursor += 2; continue; }
                    break;
                }
                return cursor;
            }
        }
        return known;

        static bool IsCall(Instruction instruction) => instruction.OpCode.Code is Code.Call or Code.Callvirt;

        bool FrameworkCall(Instruction instruction, string fullName) => instruction.Operand is IMethod method &&
            method.FullName == fullName && method.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
    }

    // These Windows contracts operate on service state, file names, or OS version data;
    // none enumerates/loads a managed resource or accepts a callback. This exception does
    // not remove or rewrite the imports. Unknown libraries, exports and native resolvers
    // remain blockers. Entry-point spelling is case-sensitive, DLL spelling is not.
    internal static bool IsKnownNonResourceImport(MethodDef method)
    {
        if (!method.IsPinvokeImpl || !method.IsStatic || method.HasBody || method.ImplMap?.Module is not { } library ||
            method.MethodSig is not { HasThis: false, GenParamCount: 0 } signature)
            return false;
        if (library.Name.String.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) &&
            method.ImplMap.Name == "IsDebuggerPresent")
            return signature.Params.Count == 0 && signature.RetType.ElementType is ElementType.Boolean or ElementType.I4;
        // These fixed platform queries/state setters do not read assembly resources.
        // Unlike GetWindowText/Length, they do not dispatch a window message to a
        // potentially application-defined window procedure. Calls remain unchanged.
        if (method.ParamDefs.All(parameter => !parameter.HasMarshalType))
        {
            if (library.Name.String.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) &&
                method.ImplMap.Name == "SetThreadExecutionState")
                return signature.RetType.ElementType == ElementType.U4 && signature.Params.Count == 1 &&
                    signature.Params[0].ElementType == ElementType.U4;
            if (library.Name.String.Equals("user32.dll", StringComparison.OrdinalIgnoreCase))
            {
                if (method.ImplMap.Name == "GetForegroundWindow")
                    return signature.Params.Count == 0 && signature.RetType.ElementType == ElementType.I;
                if (method.ImplMap.Name == "SetProcessDPIAware")
                    return signature.Params.Count == 0 && signature.RetType.ElementType == ElementType.Boolean;
                if (method.ImplMap.Name == "GetLastInputInfo")
                    return signature.RetType.ElementType == ElementType.Boolean && signature.Params.Count == 1 &&
                        signature.Params[0] is ByRefSig { Next: ValueTypeSig value } &&
                        value.TypeDefOrRef.ResolveTypeDef() is { IsSequentialLayout: true, HasGenericParameters: false } storage &&
                        storage.BaseType is TypeRef parent && parent.FullName == "System.ValueType" &&
                        parent.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName &&
                        storage.ClassLayout is null && storage.Methods.Count == 0 && storage.Fields.Count == 2 &&
                        storage.Fields.All(field => !field.IsStatic && !field.HasMarshalType && field.FieldType.ElementType == ElementType.U4);
            }
        }
        var expected = (library.Name.String.ToLowerInvariant(), method.ImplMap.Name.String) switch
        {
            ("advapi32.dll", "DeleteService" or "CloseServiceHandle") => 1,
            ("advapi32.dll", "OpenSCManager" or "OpenSCManagerA" or "OpenSCManagerW" or
                "OpenService" or "OpenServiceA" or "OpenServiceW" or "ControlService" or
                "ChangeServiceConfig2" or "ChangeServiceConfig2A" or "ChangeServiceConfig2W") => 3,
            ("advapi32.dll", "CreateService" or "CreateServiceA" or "CreateServiceW") => 13,
            ("advapi32.dll", "QueryServiceStatusEx" or "QueryServiceConfig2" or "QueryServiceConfig2A" or "QueryServiceConfig2W") => 5,
            ("kernel32.dll", "MoveFileEx" or "MoveFileExA" or "MoveFileExW") => 3,
            ("ntdll.dll", "RtlGetVersion") => 1,
            _ => -1
        };
        return signature.Params.Count == expected;
    }

    internal static IReadOnlyList<RecoveredResourceOrigin> LoaderDataOrigins(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            !context.TryGetFact<int>("method-protection.restored", out var restored) || restored == 0 ||
            !context.TryGetFact<LoaderInterpretationEvidence>("bootstrap.evidence", out var evidence) || evidence is null ||
            !evidence.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead))
            return [];
        // Ownership depends on complete resource inputs and separately recorded invocation
        // effects. Dropped debugger/identity probes do not invent another resource read.
        // Unknown truncation scope and any lost resource-read event still refuse attribution.
        var surviving = context.Module.GetTypes().SelectMany(type => type.Methods).ToHashSet();
        var result = new HashSet<RecoveredResourceOrigin>();
        var frames = RebuiltMethods.ElidedLoaderMethods(context).Where(method =>
                method.Rid != 0 && !method.IsStaticConstructor && !surviving.Contains(method) &&
                evidence.EffectsOf(method.MDToken.Raw).WroteMappedImage).Select(method => method.MDToken.Raw).ToHashSet();
        if (context.TryGetFact<bool>("antitamper.neutralized", out var neutralized) && neutralized &&
            context.TryGetFact<uint>("antitamper.entryPoint", out var gate) &&
            !surviving.Any(method => method.MDToken.Raw == gate) &&
            evidence.Observations.Any(observation => observation.Kind == LoaderObservationKind.SignatureVerification && observation.CallStack.Contains(gate)))
            frames.Add(gate);
        foreach (var frame in frames)
        {
            var effects = evidence.EffectsOf(frame);
            if (!effects.AllInvocationsCompleted) continue;
            var reads = evidence.Observations.Where(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead &&
                observation.CallStack.Contains(frame)).Select(observation =>
                System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail)).ToArray();
            // A shared outer initializer can read unrelated payloads too. Attribute only a
            // completed, physically removed writer or neutralized integrity subtree with one input.
            if (reads.Length == 0 || reads.Any(read => read is null)) continue;
            var inputs = reads.Select(read => new RecoveredResourceOrigin(read!.Name, read.Sha256)).Distinct().ToArray();
            if (inputs.Length == 1) result.Add(inputs[0]);
        }
        return result.ToArray();
    }
}
