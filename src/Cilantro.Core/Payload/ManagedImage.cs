using dnlib.IO;

namespace Cilantro.Core.Payload;

/// <summary>What it means for a buffer to turn out not to be a managed image.</summary>
/// <remarks>
/// Most of the places that read an image are sifting candidates: a resource decoded under one key
/// out of thousands, a buffer an interpreted loader was seen handing to the runtime. Nearly all of
/// them are not images at all, and being told so is the ordinary answer rather than a failure.
///
/// The reader says so in whatever way the bytes happen to be wrong, which is more ways than any one
/// site tends to remember — a buffer too short to hold a DOS header does not report a bad image
/// format, it reports running out of bytes. So the question is asked in one place. A site that
/// forgets one of the answers does not merely mislabel a candidate: it throws out of a pass, and a
/// pass that throws takes the passes that depend on it with it, which is how a nested payload came
/// to be reported as an extraction failure when what had happened was one wrong key out of many.
/// </remarks>
public static class ManagedImage
{
    /// <summary>Whether a failure is the reader saying these bytes are not a managed image.</summary>
    public static bool Rejects(Exception failure) =>
        failure is BadImageFormatException or IOException or NotSupportedException or
            ArgumentException or InvalidOperationException or IndexOutOfRangeException or
            DataReaderException;
}
