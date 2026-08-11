using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Strings;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Rewrites metadata-token proxy calls back to direct <c>ldtoken</c> handle loads.
/// </summary>
/// <remarks>
/// Reactor can replace a direct handle load with a runtime resolve through
/// <see cref="System.Reflection.Module"/>, so <c>ldtoken T</c> becomes
/// <c>module.ResolveType(tokenAsInt)</c>. When the integer is a proven constant that is a valid
/// metadata token of the matching kind in this module, the resolve is a pure obfuscation of the
/// canonical handle-load idiom and can be put back verbatim.
///
/// The token is proven with the same offset slicer the string and boolean passes use, and the
/// decoded token must resolve to a real member before any edit, mirroring the bijectivity
/// discipline in delegate-proxy analysis. The receiver of the resolve call must be a single
/// side-effect-free load so removing it cannot drop an observable effect; anything more elaborate
/// is declined rather than guessed. Every rewrite is staged in a body transaction and rolled back
/// unless verification passes.
///
/// Reactor 6 uses a second shape that reaches the same place by a lower road. Instead of calling
/// <c>Module.ResolveType</c> at the site it emits a forwarder of its own —
/// <c>static RuntimeTypeHandle P(int)</c>, whose whole body hands the argument to
/// <c>ModuleHandle.GetRuntimeTypeHandleFromMetadataToken</c> against a module handle it cached at
/// load time — so the site reads <c>ldc.i4 token; call P</c> and mentions no reflection API at all.
/// That form is closer to the original than the first: it yields the handle directly, so a site is
/// exactly <c>ldtoken</c> written the long way, and putting it back needs no call to
/// <c>GetTypeFromHandle</c> at all.
///
/// Which module the cached handle addresses is the one thing that cannot be read off the forwarder,
/// and it decides whether the token means anything here. It is settled by interpretation rather than
/// assumed: the bounded machine runs the initializer that fills the field and carries a mark along
/// the reflection chain from its seed, so the field is accepted only when the handle demonstrably
/// came from a type defined in this module.
/// </remarks>
public sealed class TokenRecoveryPass : DeobfuscationPass
{
    public override string Name => "token-recovery";

    /// <remarks>
    /// Inlining comes first because Reactor puts a pass-through wrapper between the program and the
    /// handle forwarder, and a site that calls the wrapper is not one this pass can read: the
    /// constant it needs is an argument away. Redirecting those sites to the forwarder is exactly
    /// what inlining does, so waiting for it turns the indirect sites into ones this pass recognizes
    /// instead of leaving them to be rewritten by nobody.
    /// </remarks>
    public override IReadOnlyCollection<string> Dependencies =>
        ["method-body-recovery", "method-inlining"];

    private static readonly Dictionary<string, Table> ResolveKinds =
        new(StringComparer.Ordinal)
        {
            ["ResolveType"] = Table.TypeDef,
            ["ResolveMethod"] = Table.Method,
            ["ResolveField"] = Table.Field
        };

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var integerFields = LoadIntegerFields(context);
        var handleLoaders = HandleLoaderReferences.Import(context.Module);
        var forwarders = HandleForwarders.Locate(context, out var forwarderDiagnostic);
        var sites = new List<TokenSite>();
        foreach (var method in context.Module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(item => item.HasBody))
        {
            for (var index = 0; index < method.Body.Instructions.Count; index++)
            {
                if (TryMatchSite(method, index, integerFields, out var site) && site is not null)
                    sites.Add(site);
                else if (TryMatchForwarderSite(method, index, forwarders, out var forwarded) &&
                    forwarded is not null)
                {
                    sites.Add(forwarded);
                }
            }
        }
        if (sites.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No constant-fed metadata-token proxy was detected.", forwarderDiagnostic]);
        }

        var resolved = new List<(TokenSite Site, IMDTokenProvider Member)>();
        foreach (var site in sites)
        {
            if (context.Module.ResolveToken(site.Token) is not { } member ||
                !MemberMatchesKind(member, site.Kind))
            {
                return (PassStatus.Partial, 0,
                [
                    $"Decoded token 0x{site.Token:X8} at {site.Method.MDToken} " +
                    $"IL_{site.Call.Offset:X4} did not resolve to a {site.Kind} member.",
                    "No token proxy was rewritten."
                ]);
            }
            resolved.Add((site, member));
        }

        var transactions = resolved.Select(item => item.Site.Method)
            .Distinct()
            .ToDictionary(method => method, method => new BodyMutationTransaction(method));
        try
        {
            foreach (var (site, member) in resolved)
                RewriteSite(site, member, handleLoaders);
            var verification = AssemblyVerifier.Verify(
                context.Module, context.OriginalIdentity, context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            foreach (var transaction in transactions.Values)
                transaction.Commit();
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException)
        {
            foreach (var transaction in transactions.Values)
                transaction.Rollback();
            return (PassStatus.Failed, 0,
                [$"Token rewrite was rolled back: {exception.Message}"]);
        }
        finally
        {
            foreach (var transaction in transactions.Values)
                transaction.Dispose();
        }

        foreach (var (site, member) in resolved)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "restore-token",
                $"{site.Method.MDToken} IL_{site.Call.Offset:X4}",
                $"Rewrote {site.Kind} resolve of 0x{site.Token:X8} to a direct handle load of {member.MDToken}."));
        }
        var stranded = StrandedForwarders(context, resolved.Select(item => item.Site));
        RecoveryOrphans.DeclareSubtree(context, stranded);
        context.SetFact("tokens.restored", resolved.Count);
        return (PassStatus.Success, resolved.Count,
        [
            $"Rewrote {resolved.Count} constant-fed token proxy call(s) to direct handle loads.",
            stranded.Count == 0
                ? forwarderDiagnostic
                : $"{stranded.Count} handle forwarder(s) lost their last caller."
        ]);
    }

    /// <summary>
    /// Names the forwarders that no longer have a live caller now the rewrite has been committed.
    /// </summary>
    /// <remarks>
    /// A forwarder still called from somewhere is serving a site this pass declined, and that site
    /// is doing something the pass has not accounted for, so it keeps the forwarder alive. Callers
    /// recovery has already stranded are the exception, because Reactor reaches its forwarders
    /// through a pass-through wrapper and inlining redirects the program past the wrapper without
    /// emptying it: the call inside is the residue of a use that no longer exists, and treating it
    /// as one would leave every forwarder permanently attributed to the wrapper it outlived.
    /// </remarks>
    private static HashSet<MethodDef> StrandedForwarders(
        ArtifactContext context,
        IEnumerable<TokenSite> rewritten)
    {
        var forwarders = rewritten
            .Select(site => site.Forwarder)
            .OfType<MethodDef>()
            .ToHashSet();
        if (forwarders.Count == 0)
            return [];
        var orphans = RecoveryOrphans.Of(context);
        foreach (var caller in context.Module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(method => method.HasBody && !orphans.Contains(method.MDToken.Raw)))
        {
            foreach (var instruction in caller.Body.Instructions)
            {
                if (instruction.Operand is IMethod called && called.ResolveMethodDef() is { } target)
                    forwarders.Remove(target);
            }
        }
        return forwarders;
    }

    private static IReadOnlyDictionary<uint, int> LoadIntegerFields(ArtifactContext context) =>
        context.TryGetFact<CapturedStringTable>("strings.table", out var table) && table is not null
            ? table.IntegerFields
            : new Dictionary<uint, int>();

    private static bool TryMatchSite(
        MethodDef method,
        int index,
        IReadOnlyDictionary<uint, int> integerFields,
        out TokenSite? site)
    {
        site = null;
        var call = method.Body.Instructions[index];
        if (call.OpCode.Code is not (Code.Call or Code.Callvirt) ||
            call.Operand is not IMethod called ||
            called.DeclaringType?.FullName != "System.Reflection.Module" ||
            !ResolveKinds.TryGetValue(called.Name.String, out var kind) ||
            called.MethodSig?.Params.Count != 1 ||
            called.MethodSig.Params[0].ElementType != ElementType.I4)
        {
            return false;
        }

        if (!StringOffsetSlicer.TryEvaluate(method, index, integerFields, out var token, out _))
            return false;

        // The receiver sits just below the constant argument. Only a single side-effect-free load
        // may be neutralized, otherwise removing it could drop an observable effect.
        var receiverIndex = FindReceiverProducer(method, index);
        if (receiverIndex < 0 || !IsSideEffectFreeLoad(method.Body.Instructions[receiverIndex]))
            return false;

        site = new TokenSite(
            method, call, method.Body.Instructions[receiverIndex], Argument: null, (uint)token, kind);
        return true;
    }

    /// <summary>
    /// Finds the instruction that pushes the resolve call's receiver, which is the load directly
    /// preceding the constant-token producer chain.
    /// </summary>
    private static int FindReceiverProducer(MethodDef method, int callIndex)
    {
        var index = callIndex - 1;
        while (index >= 0 && method.Body.Instructions[index].OpCode.Code == Code.Nop)
            index--;
        // Skip the constant argument producer: for the shapes this pass accepts it is a single
        // ldc.i4 (possibly with conversions), so walk back over the integer arithmetic prefix.
        var depthGuard = 0;
        while (index >= 0 && depthGuard++ < 64)
        {
            var instruction = method.Body.Instructions[index];
            if (instruction.IsLdcI4() ||
                instruction.OpCode.Code is Code.Conv_I4 or Code.Conv_U4 or Code.Neg or Code.Not)
            {
                index--;
                continue;
            }
            if (instruction.OpCode.Code is Code.Add or Code.Sub or Code.Xor or Code.And or
                Code.Or or Code.Mul or Code.Shl or Code.Shr or Code.Shr_Un)
            {
                index--;
                continue;
            }
            break;
        }
        while (index >= 0 && method.Body.Instructions[index].OpCode.Code == Code.Nop)
            index--;
        return index;
    }

    /// <summary>
    /// Matches <c>ldc.i4 token; call forwarder</c>, the whole of Reactor's second token idiom.
    /// </summary>
    /// <remarks>
    /// The constant is required to be the single instruction before the call rather than sliced out
    /// of an arithmetic prefix, because the rewrite puts the handle load in the call's place and
    /// blanks the producer, and it can only blank a producer it can point at. Nothing is lost by the
    /// restriction: the sites Reactor emits for this idiom push the token literally.
    /// </remarks>
    private static bool TryMatchForwarderSite(
        MethodDef method,
        int index,
        HandleForwarders forwarders,
        out TokenSite? site)
    {
        site = null;
        var call = method.Body.Instructions[index];
        if (index == 0 ||
            call.OpCode.Code != Code.Call ||
            call.Operand is not IMethod called ||
            called.ResolveMethodDef() is not { } target ||
            !forwarders.TryGetKind(target, out var kind))
        {
            return false;
        }
        var argument = method.Body.Instructions[index - 1];
        if (!argument.IsLdcI4())
            return false;
        site = new TokenSite(
            method, call, Receiver: null, argument, (uint)argument.GetLdcI4Value(), kind, target);
        return true;
    }

    private static bool IsSideEffectFreeLoad(Instruction instruction) =>
        instruction.IsLdarg() ||
        instruction.IsLdloc() ||
        instruction.OpCode.Code is Code.Ldsfld or Code.Ldnull or Code.Dup;

    private static bool MemberMatchesKind(IMDTokenProvider member, Table kind) => kind switch
    {
        Table.TypeDef => member is ITypeDefOrRef,
        Table.Method => member is MethodDef,
        Table.Field => member is FieldDef,
        _ => false
    };

    private static void RewriteSite(
        TokenSite site,
        IMDTokenProvider member,
        HandleLoaderReferences handleLoaders)
    {
        if (site.Forwarder is not null)
        {
            RewriteForwarderSite(site, member);
            return;
        }

        var instructions = site.Method.Body.Instructions;
        var receiver = site.Receiver;
        var receiverIndex = receiver is null ? -1 : instructions.IndexOf(receiver);
        var callIndex = instructions.IndexOf(site.Call);
        if (receiver is null || receiverIndex < 0 || callIndex < 0)
            throw new InvalidOperationException("A token proxy site moved during rewriting.");

        // Drop the receiver push, turn the constant into the handle load, and turn the resolve
        // into the matching GetXFromHandle. The net stack effect is preserved: one value in, one
        // out.
        receiver.OpCode = OpCodes.Nop;
        receiver.Operand = null;

        var argumentProducer = instructions[callIndex - 1];
        while (argumentProducer.OpCode.Code == Code.Nop && callIndex - 1 > receiverIndex)
        {
            callIndex--;
            argumentProducer = instructions[callIndex - 1];
        }
        argumentProducer.OpCode = OpCodes.Ldtoken;
        argumentProducer.Operand = member;

        site.Call.OpCode = OpCodes.Call;
        site.Call.Operand = site.Kind switch
        {
            Table.TypeDef => handleLoaders.GetTypeFromHandle,
            Table.Method => handleLoaders.GetMethodFromHandle,
            Table.Field => handleLoaders.GetFieldFromHandle,
            _ => throw new InvalidOperationException("Unknown token kind.")
        };
    }

    /// <summary>
    /// Puts a forwarded token load back as the <c>ldtoken</c> it was compiled from.
    /// </summary>
    /// <remarks>
    /// The forwarder returns the handle itself, so the site is <c>ldtoken</c> spelled as a push and
    /// a call and the original is recovered by blanking the push and turning the call into the
    /// handle load. Both instructions stay where they are, which leaves every branch that targets
    /// them pointing at the same place, and the stack is unchanged: one value consumed and one
    /// produced becomes none consumed and one produced.
    /// </remarks>
    private static void RewriteForwarderSite(TokenSite site, IMDTokenProvider member)
    {
        if (site.Argument is null)
            throw new InvalidOperationException("A forwarded token site has no constant to replace.");
        site.Argument.OpCode = OpCodes.Nop;
        site.Argument.Operand = null;
        site.Call.OpCode = OpCodes.Ldtoken;
        site.Call.Operand = member;
    }

    private sealed record TokenSite(
        MethodDef Method,
        Instruction Call,
        Instruction? Receiver,
        Instruction? Argument,
        uint Token,
        Table Kind,
        MethodDef? Forwarder = null);

    /// <summary>
    /// The module's own <c>int</c>-to-handle forwarders, once their module handle is shown to be
    /// this module's.
    /// </summary>
    private sealed class HandleForwarders
    {
        private const int MaximumSteps = 4_000_000;

        private static readonly Dictionary<string, (Table Kind, string Handle)> Resolvers =
            new(StringComparer.Ordinal)
            {
                ["GetRuntimeTypeHandleFromMetadataToken"] = (Table.TypeDef, "System.RuntimeTypeHandle"),
                ["GetRuntimeMethodHandleFromMetadataToken"] = (Table.Method, "System.RuntimeMethodHandle"),
                ["GetRuntimeFieldHandleFromMetadataToken"] = (Table.Field, "System.RuntimeFieldHandle")
            };

        private readonly Dictionary<MethodDef, Table> _kinds;

        private HandleForwarders(Dictionary<MethodDef, Table> kinds) => _kinds = kinds;

        public bool TryGetKind(MethodDef method, out Table kind) =>
            _kinds.TryGetValue(method, out kind);

        public static HandleForwarders Locate(ArtifactContext context, out string diagnostic)
        {
            var candidates = context.Module.GetTypes()
                .SelectMany(type => type.Methods)
                .Select(method => TryMatchShape(method, out var handle, out var kind)
                    ? (Method: method, Handle: handle!, Kind: kind)
                    : default)
                .Where(candidate => candidate.Handle is not null)
                .ToArray();
            if (candidates.Length == 0)
            {
                diagnostic = "No metadata-token handle forwarder was detected.";
                return new HandleForwarders([]);
            }

            var proven = ProveHomeModuleHandles(
                context,
                candidates.Select(candidate => candidate.Handle).ToArray(),
                out diagnostic);
            var accepted = candidates
                .Where(candidate => proven.Contains(candidate.Handle.FullName))
                .ToDictionary(candidate => candidate.Method, candidate => candidate.Kind);
            if (accepted.Count != 0)
            {
                diagnostic =
                    $"{accepted.Count} handle forwarder(s) resolve tokens against this module.";
            }
            return new HandleForwarders(accepted);
        }

        /// <summary>
        /// Matches a static <c>int</c>-to-handle method whose body is nothing but the resolve.
        /// </summary>
        /// <remarks>
        /// The body is required to be exactly the field address, the argument, the resolve, and the
        /// return, so there is no room for the method to do anything else: the token it is handed is
        /// the token it resolves, and the handle it returns is the handle it got back. That is what
        /// makes a site equivalent to <c>ldtoken</c>, and a longer body would have to be read to know
        /// whether it still is.
        /// </remarks>
        private static bool TryMatchShape(MethodDef method, out IField? handle, out Table kind)
        {
            handle = null;
            kind = default;
            if (!method.IsStatic || !method.HasBody || method.MethodSig?.Params.Count != 1 ||
                method.MethodSig.Params[0].ElementType != ElementType.I4)
            {
                return false;
            }
            var body = method.Body.Instructions
                .Where(instruction => instruction.OpCode.Code != Code.Nop)
                .ToArray();
            if (body.Length != 4 ||
                body[0].OpCode.Code != Code.Ldsflda ||
                body[0].Operand is not IField field ||
                field.FieldSig?.Type.FullName != "System.ModuleHandle" ||
                !body[1].IsLdarg() ||
                body[1].GetParameterIndex() != 0 ||
                body[2].OpCode.Code != Code.Call ||
                body[2].Operand is not IMethod resolve ||
                resolve.DeclaringType?.FullName != "System.ModuleHandle" ||
                !Resolvers.TryGetValue(resolve.Name.String, out var resolver) ||
                method.MethodSig.RetType?.FullName != resolver.Handle ||
                body[3].OpCode.Code != Code.Ret)
            {
                return false;
            }
            handle = field;
            kind = resolver.Kind;
            return true;
        }

        /// <summary>
        /// Returns the candidate handle fields the loader demonstrably filled from this module.
        /// </summary>
        /// <remarks>
        /// Reactor reaches the handle by reflection rather than by naming the module, so which module
        /// it ends up with is a property of a chain of calls and not of anything written at the
        /// forwarder. Running the initializer that fills the field settles it: the machine follows
        /// the chain wherever the obfuscator's forwarders lead, and the mark it carries from the
        /// seeding <c>ldtoken</c> arrives on the stored value only if that seed was a type defined
        /// here. A handle from anywhere else, or an initializer the machine cannot finish, leaves the
        /// field unproven and its forwarders untouched.
        ///
        /// One interpretation is enough. What is being read out is not a decoded value that could
        /// come out differently on a second run, but whether the chain the machine walked began in
        /// this module's metadata, and a run that fails for any reason fails towards leaving the
        /// forwarder alone.
        /// </remarks>
        private static HashSet<string> ProveHomeModuleHandles(
            ArtifactContext context,
            IReadOnlyCollection<IField> candidates,
            out string diagnostic)
        {
            if (!BootstrapMachine.TryRunInitializers(
                    context, MaximumSteps, out var machine, out var why) || machine is null)
            {
                diagnostic = $"Handle forwarders were left alone: loader state did not interpret ({why}).";
                return [];
            }
            foreach (var declaring in candidates
                         .Select(field => field.DeclaringType.ResolveTypeDef())
                         .OfType<TypeDef>()
                         .Distinct())
            {
                if (declaring.FindStaticConstructor() is { HasBody: true } initializer)
                    machine.Execute(initializer);
            }

            var proven = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in candidates)
            {
                var stored = machine.State.ReadStaticField(field);
                if (machine.State.Heap.TryGetModelValue<bool>(
                        stored, LoaderFrameworkIntrinsic.HomeModuleMark, out var home) && home)
                {
                    proven.Add(field.FullName);
                }
            }
            diagnostic = proven.Count == 0
                ? "Handle forwarders were left alone: no cached module handle was shown to be this module's."
                : string.Empty;
            return proven;
        }
    }

    private sealed class HandleLoaderReferences
    {
        private HandleLoaderReferences(
            IMethod getTypeFromHandle,
            IMethod getMethodFromHandle,
            IMethod getFieldFromHandle)
        {
            GetTypeFromHandle = getTypeFromHandle;
            GetMethodFromHandle = getMethodFromHandle;
            GetFieldFromHandle = getFieldFromHandle;
        }

        public IMethod GetTypeFromHandle { get; }
        public IMethod GetMethodFromHandle { get; }
        public IMethod GetFieldFromHandle { get; }

        public static HandleLoaderReferences Import(ModuleDef module)
        {
            var importer = new Importer(module);
            return new HandleLoaderReferences(
                importer.Import(typeof(Type).GetMethod(
                    nameof(Type.GetTypeFromHandle), [typeof(RuntimeTypeHandle)])!),
                importer.Import(typeof(System.Reflection.MethodBase).GetMethod(
                    nameof(System.Reflection.MethodBase.GetMethodFromHandle),
                    [typeof(RuntimeMethodHandle)])!),
                importer.Import(typeof(System.Reflection.FieldInfo).GetMethod(
                    nameof(System.Reflection.FieldInfo.GetFieldFromHandle),
                    [typeof(RuntimeFieldHandle)])!));
        }
    }
}
