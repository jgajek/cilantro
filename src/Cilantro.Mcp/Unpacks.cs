using System.Collections.Concurrent;

namespace Cilantro.Mcp;

/// <summary>
/// The runs this server started and has not yet seen the end of.
/// </summary>
/// <remarks>
/// <para>
/// Two things are known about a run and they live in different places. How far it has got is on disk,
/// in its <see cref="Cilantro.Core.RunStatus"/> file, because that has to outlive whoever asked and be
/// readable by whoever asks next. Whether it can be stopped is here, in memory, because stopping it
/// means holding the token it is watching — and a token cannot be written to a file.
/// </para>
/// <para>
/// Which is why this is deliberately not the source of truth for anything else. A server restarted
/// while a run was in flight has an empty registry and a status file that carries on being updated by
/// nobody; a caller polling it sees the heartbeat go stale, which is the honest answer. The alternative
/// — inferring liveness from the registry — would have reported every run as gone the moment the
/// server bounced, including the ones that were fine.
/// </para>
/// </remarks>
internal static class Unpacks
{
    /// <summary>
    /// Keyed by status file, which is the one name for a run that both this server and a caller can
    /// work out from the arguments alone. An opaque handle would need looking up somewhere, and the
    /// somewhere would be this dictionary, which does not survive a restart.
    /// </summary>
    private static readonly ConcurrentDictionary<string, CancellationTokenSource> Live =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Starts a run on a thread of its own, unless this server is already running one that would write
    /// to the same status file.
    /// </summary>
    /// <remarks>
    /// The slot is claimed before the work starts, so that two calls arriving together cannot both
    /// think they won. Whatever the work throws is dropped here on purpose: the pipeline records its
    /// own outcome in the status file before letting anything out, and the alternative is an
    /// unobserved task exception surfacing on the finalizer thread with nobody to hand it to.
    /// </remarks>
    public static bool TryStart(string statusPath, Action<CancellationToken> work)
    {
        var key = Path.GetFullPath(statusPath);
        var stopping = new CancellationTokenSource();
        if (!Live.TryAdd(key, stopping))
        {
            stopping.Dispose();
            return false;
        }

        _ = Task.Run(() =>
        {
            try
            {
                work(stopping.Token);
            }
            catch
            {
            }
            finally
            {
                Live.TryRemove(key, out _);
                stopping.Dispose();
            }
        });
        return true;
    }

    /// <summary>Asks a run this server started to stop, and says whether there was one.</summary>
    public static bool TryStop(string statusPath)
    {
        if (!Live.TryGetValue(Path.GetFullPath(statusPath), out var stopping))
        {
            return false;
        }

        try
        {
            stopping.Cancel();
            return true;
        }
        catch (ObjectDisposedException)
        {
            // It finished between the lookup and the cancel, which is the answer the caller wanted
            // anyway. The status file says which way it went.
            return false;
        }
    }

    /// <summary>Whether this server is the one running the run that writes here.</summary>
    public static bool Owns(string statusPath) =>
        Live.ContainsKey(Path.GetFullPath(statusPath));
}
