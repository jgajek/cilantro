using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Cilantro.Core.Analysis;
using Cilantro.Core.Payload;
using dnlib.DotNet;

namespace Cilantro.Core.Native;

/// <summary>What reading a native bootstrap established, and the assembly that was inside it.</summary>
/// <remarks>
/// The provenance fields are not decoration. A recovered assembly is bytes this tool produced rather
/// than bytes it found, so the report has to be able to say how: which routine the key came from,
/// how many candidate routines were considered, and whether the inflated data was the assembly or a
/// loader holding it. Without that, a wrong answer and a right one look identical.
/// </remarks>
public sealed record NativeBootstrapFindings(
    byte[] Assembly,
    string Resource,
    int KeyFileOffset,
    string KeyBytes,
    int EncryptedLength,
    int InflatedLength,
    bool CameFromLoader,
    string? ClrVersion,
    int CandidateRoutines);

/// <summary>
/// Reads .NET Reactor's native bootstrap: the mode where the managed assembly is encrypted into a
/// Win32 resource of an ordinary native executable, which starts the runtime itself.
/// </summary>
/// <remarks>
/// <para>
/// A file protected this way has no CLR header, so every managed reader refuses it before any of
/// this tool's passes could run. That is the whole of the problem: the file is not a .NET assembly,
/// and the .NET assembly is inside it.
/// </para>
/// <para>
/// The format, in order. An <c>RT_RCDATA</c> resource named <c>__</c> holds the payload, encrypted
/// with a 256x256 byte substitution table and nothing else — no block cipher, no stream cipher, so
/// the whole of it is recoverable by reading. The table is derived from six bytes that live in the
/// bootstrap's own decrypt routine as immediate operands, which is why finding that routine is the
/// only search this reader does. Decrypted, the resource is a little-endian <c>int32</c> length
/// followed by a zlib stream. Inflated, it is either the assembly outright or a fourteen-byte header
/// — the runtime version string the bootstrap asks for, such as <c>v4.0.30319</c> — in front of a
/// loader assembly whose first embedded resource is the assembly that was wanted.
/// </para>
/// <para>
/// The format was established by reading NETReactorSlayer, which unpacks it. None of its code is
/// used here: it is GPLv3 and this tool is MIT, so what crossed over is the description above and
/// nothing else.
/// </para>
/// </remarks>
public static class NativeBootstrap
{
    /// <summary>The resource a native bootstrap keeps its payload in.</summary>
    public const string PayloadResourceName = "__";

    /// <summary>
    /// The bytes in front of a loader assembly: ten characters of runtime version, then four more.
    /// </summary>
    private const int LoaderHeaderSize = 14;

    /// <summary>The block the substitution is applied over, independently of every other block.</summary>
    private const int BlockSize = 1024;

    private const int KeyInitLength = 20;
    private const int KeyLength = 32;
    private const int TableSide = 256;

    /// <summary>Marks a table slot as unfilled. Outside byte range on purpose, so no byte collides.</summary>
    private const ushort Unfilled = 0x400;

    /// <summary>
    /// The head of the decrypt routine. Wildcards sit where the two key immediates are, which is
    /// also why they cannot be matched: they differ per protected file, and they are the point.
    /// </summary>
    private static readonly short[] DecryptRoutine =
    [
        0x83, 0xEC, 0x38, 0x53, 0xB0, -1, 0x88, 0x44, 0x24, 0x2B, 0x88, 0x44, 0x24, 0x2F, 0xB0,
        -1, 0x88, 0x44, 0x24, 0x30, 0x88, 0x44, 0x24, 0x31, 0x88, 0x44, 0x24, 0x33, 0x55, 0x56
    ];

    /// <summary>Where the six key bytes sit, relative to the start of the decrypt routine.</summary>
    private static readonly int[] KeyByteOffsets = [0x05, 0x0F, 0x58, 0x6D, 0x98, 0xA6];

    /// <summary>
    /// Whether this file looks like a native bootstrap rather than an ordinary native executable.
    /// </summary>
    /// <remarks>
    /// Deliberately answered from structure alone — no CLR header, and a payload resource under the
    /// name Reactor uses — because this question is asked of every file that fails to load as
    /// managed, and most of those are simply not .NET. Saying yes here only buys an attempt; the
    /// attempt either produces an assembly or refuses.
    /// </remarks>
    public static bool Looks(ReadOnlySpan<byte> bytes)
    {
        if (!PeImageView.TryParse(bytes, out var image) || image is null)
            return false;
        return !HasCliHeader(image) && FindPayload(image) is not null;
    }

    /// <summary>
    /// Recovers the managed assembly a native bootstrap carries, or explains what stopped it.
    /// </summary>
    public static bool TryUnpack(
        ReadOnlySpan<byte> bytes,
        out NativeBootstrapFindings? findings,
        out string reason)
    {
        findings = null;
        if (!PeImageView.TryParse(bytes, out var image) || image is null)
        {
            reason = "The file is not a PE image.";
            return false;
        }

        if (HasCliHeader(image))
        {
            reason = "The file has a CLR header, so it is a managed image rather than a native bootstrap.";
            return false;
        }

        var payload = FindPayload(image);
        if (payload is null)
        {
            reason =
                $"No RT_RCDATA resource named '{PayloadResourceName}' is present, which is where a " +
                "Reactor native bootstrap keeps the assembly.";
            return false;
        }

        if (!Win32ResourceTable.TryReadBytes(image, payload, out var encrypted))
        {
            reason = $"The resource {payload.Describe()} names bytes the image does not carry.";
            return false;
        }

        var routines = FindDecryptRoutines(image);
        if (routines.Count == 0)
        {
            reason =
                "The bootstrap's decrypt routine was not found in any executable section, so the " +
                "key it carries could not be read. Reactor's .NET 1.x bootstrap keeps its key " +
                "elsewhere and is not supported.";
            return false;
        }

        // Every candidate is tried rather than the first, because the routine is located by a code
        // pattern and a pattern can match twice. Which one is right is not decided by preference: an
        // unpack either inflates to an assembly or it does not, so the data settles it.
        var failures = new List<(int Offset, string Reason)>();
        foreach (var routine in routines)
        {
            if (TryUnpackWith(
                    image, payload, encrypted.Span, routine, routines.Count, out findings, out var failure))
            {
                reason = string.Empty;
                return true;
            }
            failures.Add((routine, failure));
        }

        reason = failures.Count == 1
            ? $"The bootstrap's decrypt routine was read at 0x{failures[0].Offset:X}, but " +
                failures[0].Reason
            : $"None of the {failures.Count} candidate decrypt routines yielded an assembly: " +
                string.Join("; ", failures.Select(failure =>
                    $"0x{failure.Offset:X}, {failure.Reason}"));
        return false;
    }

    private static bool TryUnpackWith(
        PeImageView image,
        Win32Resource payload,
        ReadOnlySpan<byte> encrypted,
        int routineOffset,
        int candidates,
        out NativeBootstrapFindings? findings,
        out string reason)
    {
        findings = null;
        var key = new byte[KeyByteOffsets.Length];
        for (var index = 0; index < KeyByteOffsets.Length; index++)
        {
            if (!image.TryReadFile(routineOffset + KeyByteOffsets[index], 1, out var one))
            {
                reason = "the routine runs off the end of the file before its key bytes.";
                return false;
            }
            key[index] = one.Span[0];
        }

        var plain = encrypted.ToArray();
        Decrypt(key, plain);

        if (plain.Length < sizeof(int))
        {
            reason = "the decrypted resource is too short to carry a length.";
            return false;
        }

        var declared = BinaryPrimitives.ReadInt32LittleEndian(plain);
        // The length is the first thing the decryption produces, so it is also the first evidence
        // that the key was right. A wrong key almost always fails here rather than in the inflate.
        if (declared <= 0 || declared > MaximumInflatedLength)
        {
            reason = $"the decrypted length ({declared}) is not a plausible assembly size.";
            return false;
        }

        byte[] inflated;
        try
        {
            inflated = Inflate(plain.AsSpan(sizeof(int)), declared);
        }
        catch (InvalidDataException failure)
        {
            reason = $"the decrypted resource did not inflate ({failure.Message}).";
            return false;
        }

        if (inflated.Length != declared)
        {
            reason = $"the inflated data is {inflated.Length} bytes against a declared {declared}.";
            return false;
        }

        var assembly = inflated;
        var fromLoader = false;
        string? runtimeVersion = null;
        if (!StartsWithDosHeader(inflated))
        {
            if (!StartsWithDosHeader(inflated.AsSpan(LoaderHeaderSize)))
            {
                reason = "the inflated data is neither an image nor a loader holding one.";
                return false;
            }

            runtimeVersion = ReadRuntimeVersion(inflated);
            if (!TryReadLoaderPayload(inflated.AsSpan(LoaderHeaderSize).ToArray(), out assembly, out var loaderFailure))
            {
                reason = loaderFailure;
                return false;
            }
            fromLoader = true;
        }

        findings = new NativeBootstrapFindings(
            assembly,
            payload.Describe(),
            routineOffset,
            Convert.ToHexString(key).ToLowerInvariant(),
            encrypted.Length,
            inflated.Length,
            fromLoader,
            runtimeVersion,
            candidates);
        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// A ceiling on what the length field is allowed to claim, so a wrong key cannot ask for an
    /// allocation the size of its own noise.
    /// </summary>
    private const int MaximumInflatedLength = 512 * 1024 * 1024;

    private static bool HasCliHeader(PeImageView image) =>
        image.TryGetDataDirectory(PeImageView.CliHeaderDirectoryIndex, out var rva, out _) && rva != 0;

    private static Win32Resource? FindPayload(PeImageView image) =>
        Win32ResourceTable
            .Read(image)
            .FirstOrDefault(resource =>
                resource.IsNamed(Win32Resource.RcDataType, PayloadResourceName));

    /// <summary>
    /// Finds every place the decrypt routine could be, by scanning the executable sections.
    /// </summary>
    /// <remarks>
    /// A scan rather than a handful of known file offsets. The offsets a bootstrap puts its routine
    /// at follow from how the stub was built, and the sample that motivated this reader happened to
    /// use one of the published ones — which is not a property to depend on, since a stub built by
    /// any other version of the protector moves it and the tool would report a file it can read as
    /// one it cannot.
    /// </remarks>
    private static List<int> FindDecryptRoutines(PeImageView image)
    {
        const uint executable = 0x2000_0000;
        var found = new List<int>();
        var file = image.CreateFileCopy();
        foreach (var section in image.Sections)
        {
            if ((section.Characteristics & executable) == 0 || section.SizeOfRawData == 0)
                continue;

            var start = checked((int)section.PointerToRawData);
            var end = (int)Math.Min(
                (long)start + section.SizeOfRawData,
                file.Length);
            // The last key byte sits well past the matched head, so a match too close to the end of
            // the section is not a routine this reader can finish reading.
            var last = end - KeyByteOffsets[^1] - 1;
            for (var offset = start; offset <= last; offset++)
            {
                if (Matches(file.AsSpan(offset, DecryptRoutine.Length)))
                    found.Add(offset);
            }
        }

        return found;
    }

    private static bool Matches(ReadOnlySpan<byte> code)
    {
        for (var index = 0; index < DecryptRoutine.Length; index++)
        {
            var expected = DecryptRoutine[index];
            if (expected >= 0 && expected != code[index])
                return false;
        }

        return true;
    }

    /// <summary>
    /// Undoes the substitution, in place, one 1024-byte block at a time.
    /// </summary>
    /// <remarks>
    /// Each block is substituted twice: once forward, where every byte is keyed by the one after it,
    /// and once backward, where every byte is keyed by the already-substituted one before it. The
    /// two ends of the block are keyed by a checksum of the key instead, there being no neighbour.
    /// Nothing carries between blocks, which is what makes the whole resource recoverable without
    /// running any of it.
    /// </remarks>
    private static void Decrypt(ReadOnlySpan<byte> keyBytes, Span<byte> data)
    {
        var table = BuildTable(keyBytes, out var checksum);
        var edge = (byte)(checksum ^ 0x55);

        for (var start = 0; start < data.Length; start += BlockSize)
        {
            var block = data[start..Math.Min(start + BlockSize, data.Length)];
            if (block.Length == 1)
            {
                block[0] = table[block[0] * TableSide + checksum];
                continue;
            }

            for (var index = 0; index < block.Length - 1; index++)
                block[index] = table[block[index] * TableSide + block[index + 1]];
            block[^1] = table[block[^1] * TableSide + edge];

            for (var index = block.Length - 1; index > 0; index--)
                block[index] = table[block[index] * TableSide + block[index - 1]];
            block[0] = table[block[0] * TableSide + checksum];
        }
    }

    /// <summary>
    /// Expands the six key bytes into the 256x256 substitution table, and the checksum that keys the
    /// bytes at each end of a block.
    /// </summary>
    private static byte[] BuildTable(ReadOnlySpan<byte> keyBytes, out byte checksum)
    {
        if (keyBytes.Length != KeyByteOffsets.Length)
            throw new ArgumentException("A native bootstrap key is six bytes.", nameof(keyBytes));

        // Twenty bytes, most of them the key and the rest constant. The constants are the
        // protector's, and they are what makes two files with the same six key bytes share a table.
        ReadOnlySpan<byte> seed =
        [
            0x78, 0x61, 0x32, keyBytes[0], keyBytes[2],
            0x62, keyBytes[3], keyBytes[0], keyBytes[1], keyBytes[1],
            0x66, keyBytes[1], keyBytes[5], 0x33, keyBytes[2],
            keyBytes[4], 0x74, 0x32, keyBytes[3], keyBytes[2]
        ];

        var key = new byte[KeyLength];
        byte total = 0;
        for (var index = 0; index < KeyLength; index++)
        {
            key[index] = (byte)(index +
                seed[index % KeyInitLength] * seed[((index + 0x0B) | 0x1F) % KeyInitLength]);
            total += key[index];
        }

        checksum = total;

        // Column zero first: 256 distinct bytes, generated by summing the key forward from a moving
        // start and stepping a counter whenever the result repeats one already placed.
        var scratch = new ushort[TableSide * TableSide];
        Array.Fill(scratch, Unfilled);
        var counter = 0x0B;
        byte candidate = 0;
        var from = 0;
        for (var row = 0; row < TableSide; row++)
        {
            while (true)
            {
                for (var index = key.Length - 1; index >= from; index--)
                    candidate += (byte)(key[index] + counter);
                from = (from + 1) % key.Length;

                var taken = false;
                for (var seen = 0; seen <= row && !taken; seen++)
                    taken = scratch[seen * TableSide] == candidate;
                if (!taken)
                    break;
                counter++;
            }

            scratch[row * TableSide] = candidate;
        }

        // Then every other column, each one column zero rotated by a step, placed at a position the
        // key picks and skipping positions already filled.
        counter = 0;
        var rotation = 0;
        for (var column = 1; column < TableSide; column++)
        {
            rotation++;
            int at;
            do
            {
                counter++;
                at = 1 + (key[(column + 37 + counter) % key.Length] + counter + total) % 255;
            }
            while (scratch[at] != Unfilled);

            for (var row = 0; row < TableSide; row++)
                scratch[row * TableSide + at] = scratch[((row + rotation) % TableSide) * TableSide];
        }

        // Inverted, because the table above says what a byte became and decryption needs what it was.
        var table = new byte[TableSide * TableSide];
        for (var row = 0; row < TableSide; row++)
        {
            for (var column = 0; column < TableSide; column++)
                table[(byte)scratch[row * TableSide + column] * TableSide + column] = (byte)row;
        }

        return table;
    }

    private static byte[] Inflate(ReadOnlySpan<byte> compressed, int expected)
    {
        using var source = new MemoryStream(compressed.ToArray(), writable: false);
        using var stream = new ZLibStream(source, CompressionMode.Decompress);
        var inflated = new byte[expected];
        var filled = 0;
        while (filled < expected)
        {
            var read = stream.Read(inflated, filled, expected - filled);
            if (read == 0)
                break;
            filled += read;
        }

        // A stream with more in it than the length promised is not truncated to fit: the length is
        // the protector's own, and a disagreement means this is not the data it describes.
        if (filled == expected && stream.ReadByte() != -1)
            throw new InvalidDataException("the stream holds more than its declared length");

        return filled == expected ? inflated : inflated[..filled];
    }

    private static bool StartsWithDosHeader(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 2 && bytes[0] == (byte)'M' && bytes[1] == (byte)'Z';

    private static string? ReadRuntimeVersion(ReadOnlySpan<byte> inflated)
    {
        var header = inflated[..LoaderHeaderSize];
        var end = header.IndexOf((byte)0);
        if (end <= 0)
            return null;
        var text = Encoding.ASCII.GetString(header[..end]);
        return text.All(character => char.IsAsciiLetterOrDigit(character) || character == '.')
            ? text
            : null;
    }

    /// <summary>
    /// Takes the assembly out of the loader the bootstrap inflated, which keeps it as its first
    /// embedded resource and does nothing else worth reading.
    /// </summary>
    private static bool TryReadLoaderPayload(byte[] loader, out byte[] assembly, out string reason)
    {
        assembly = [];
        try
        {
            using var module = ModuleDefMD.Load(loader);
            var resource = module.Resources
                .OfType<EmbeddedResource>()
                .FirstOrDefault();
            if (resource is null)
            {
                reason = "the loader assembly holds no embedded resource to take the assembly from.";
                return false;
            }

            assembly = resource.CreateReader().ToArray();
            if (!StartsWithDosHeader(assembly))
            {
                reason = $"the loader's resource '{resource.Name}' is not an image.";
                return false;
            }

            reason = string.Empty;
            return true;
        }
        catch (Exception failure) when (ManagedImage.Rejects(failure))
        {
            reason = $"the loader assembly did not load ({failure.Message}).";
            return false;
        }
    }
}
