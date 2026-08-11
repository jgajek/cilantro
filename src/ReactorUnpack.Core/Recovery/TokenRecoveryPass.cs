using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
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
/// </remarks>
public sealed class TokenRecoveryPass : DeobfuscationPass
{
    public override string Name => "token-recovery";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

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
        var sites = new List<TokenSite>();
        foreach (var method in context.Module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(item => item.HasBody))
        {
            for (var index = 0; index < method.Body.Instructions.Count; index++)
            {
                if (TryMatchSite(method, index, integerFields, out var site) && site is not null)
                    sites.Add(site);
            }
        }
        if (sites.Count == 0)
            return (PassStatus.Success, 0, ["No constant-fed metadata-token proxy was detected."]);

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
        context.SetFact("tokens.restored", resolved.Count);
        return (PassStatus.Success, resolved.Count,
            [$"Rewrote {resolved.Count} constant-fed token proxy call(s) to direct handle loads."]);
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

        site = new TokenSite(method, call, method.Body.Instructions[receiverIndex], (uint)token, kind);
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
        var instructions = site.Method.Body.Instructions;
        var receiverIndex = instructions.IndexOf(site.Receiver);
        var callIndex = instructions.IndexOf(site.Call);
        if (receiverIndex < 0 || callIndex < 0)
            throw new InvalidOperationException("A token proxy site moved during rewriting.");

        // Drop the receiver push, turn the constant into the handle load, and turn the resolve
        // into the matching GetXFromHandle. The net stack effect is preserved: one value in, one
        // out.
        site.Receiver.OpCode = OpCodes.Nop;
        site.Receiver.Operand = null;

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

    private sealed record TokenSite(
        MethodDef Method,
        Instruction Call,
        Instruction Receiver,
        uint Token,
        Table Kind);

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
