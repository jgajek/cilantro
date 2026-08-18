using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Passes;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Reactor's rewrite, which patches individual method-body slots and nothing else.
/// </summary>
/// <remarks>
/// Reactor leaves a stub in every protected method and its loader overwrites just that stub's
/// prefix. The bound is therefore per method: a write that lands outside a catalogued prefix is
/// not part of the recovery, and a byte that changed outside one means the replay did something
/// the loader did not.
/// </remarks>
public sealed class ReactorStubRewritePolicy : IImageRewritePolicy
{
    private readonly IReadOnlyList<StubPrefixWindow> _windows;

    private ReactorStubRewritePolicy(IReadOnlyList<StubPrefixWindow> windows)
    {
        _windows = windows;
        Targets = windows.Select(window => new RewriteTarget(window.Token, window.Rva)).ToArray();
    }

    public string Protector => "Reactor";

    public IReadOnlyList<RewriteTarget> Targets { get; }

    public static bool TryCreate(
        PeImageView image,
        IReadOnlyList<ProtectedMethodStub> stubs,
        out ReactorStubRewritePolicy? policy,
        out string? diagnostic)
    {
        policy = null;
        if (!MethodBodyRecoveryInfrastructure.TryCatalogStubPrefixWindows(
                image,
                stubs,
                out var windows,
                out diagnostic))
        {
            return false;
        }
        policy = new ReactorStubRewritePolicy(windows);
        return true;
    }

    public bool TryReplay(
        PeImageView image,
        IReadOnlyList<MappedImageWrite> writes,
        out byte[] restoredFile,
        out IReadOnlySet<uint> restoredTokens,
        out string? diagnostic) =>
        MethodBodyRecoveryInfrastructure.TryValidateAndReplayWrites(
            image,
            _windows,
            writes,
            out restoredFile,
            out restoredTokens,
            out diagnostic);

    public bool IsStillProtected(MethodDef method) =>
        ReactorStructureDetector.IsProtectedMethodStub(method);

    /// <summary>
    /// Reactor's rewrite covers method-body prefixes only, so it never restores field data.
    /// </summary>
    public bool CoversFieldData(uint rva, int length) => false;
}
