namespace ReactorUnpack.Tests;

/// <summary>
/// What the tests can find in the working copy they are running from.
/// </summary>
/// <remarks>
/// The samples are malware, so they are not in the repository and a fresh checkout has none. The
/// tests that need one say so with <see cref="SampleFactAttribute"/> and are skipped where there are
/// none, which is what keeps such a run honest: it names what it could not check, rather than either
/// failing over a file nobody could have supplied or passing as though it had checked.
/// </remarks>
internal static class Checkout
{
    /// <summary>The directory holding ReactorUnpack.slnx.</summary>
    public static string Root { get; } = FindRoot();

    /// <summary>Where samples live, whether or not any are there.</summary>
    public static string Samples { get; } = Path.Combine(Root, "samples");

    /// <summary>
    /// Whether this checkout has samples at all.
    /// </summary>
    /// <remarks>
    /// Deliberately whether there are any, not whether a particular one is present. A checkout with
    /// samples but not the one a test names is a corpus that has drifted from the suite, and that
    /// should fail where it can be seen instead of quietly not running.
    /// </remarks>
    public static bool HasSamples { get; } =
        Directory.Exists(Samples) &&
        Directory.EnumerateFiles(Samples).Any(file =>
            file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));

    /// <summary>Why a test that needs a sample did not run.</summary>
    public static string WithoutSamples { get; } =
        $"Needs a real sample; {Samples} has none. See docs/corpus.md.";

    /// <summary>The path to a named sample, which has to be there.</summary>
    public static string Sample(string filename)
    {
        var path = Path.Combine(Samples, filename);
        if (!File.Exists(path))
            throw new FileNotFoundException($"Could not locate sample {filename} in {Samples}.");

        return path;
    }

    private static string FindRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "ReactorUnpack.slnx")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            $"No ReactorUnpack.slnx above {AppContext.BaseDirectory}.");
    }
}

/// <summary>
/// What the expensive tests are marked with, so a working session need not run them.
/// </summary>
/// <remarks>
/// Five tests interpret whole samples and account for essentially all of the suite's running time; the
/// other three hundred finish in about twenty seconds together. Anyone changing a message, a name or
/// a report field wants those three hundred and wants them now, so the costly ones carry a trait and
/// can be left out by name:
/// <code>dotnet test ReactorUnpack.slnx -c Release --filter "Cost!=High"</code>
/// The plain <c>dotnet test</c> still runs everything, because these are the tests that prove the tool
/// recovers real malware and no continuous integration can run them: the samples are not in the
/// repository. A gate nothing but a person can close should not also be one they have to remember.
/// </remarks>
internal static class Cost
{
    public const string Key = "Cost";

    /// <summary>Minutes rather than milliseconds: a whole sample goes through the machine.</summary>
    public const string High = "High";
}

/// <summary>A test that reads a real sample, and is skipped in a checkout that has none.</summary>
public sealed class SampleFactAttribute : FactAttribute
{
    public SampleFactAttribute()
    {
        if (!Checkout.HasSamples)
            Skip = Checkout.WithoutSamples;
    }
}

/// <inheritdoc cref="SampleFactAttribute"/>
public sealed class SampleTheoryAttribute : TheoryAttribute
{
    public SampleTheoryAttribute()
    {
        if (!Checkout.HasSamples)
            Skip = Checkout.WithoutSamples;
    }
}
