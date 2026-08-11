namespace ReactorUnpack.Core.Analysis;

/// <summary>
/// Structural recognition of Reactor's machine-generated identifiers.
/// </summary>
/// <remarks>
/// Reactor renames members to short, high-churn tokens such as <c>H1lrRRwH0tOVtn61XvY</c> or
/// <c>gFvcpJGhiO</c>. Rather than match a brittle regex, this classifies by two structural signals:
/// any character outside the normal managed-identifier alphabet is treated as generated, and an
/// otherwise-plain name is treated as generated when adjacent characters change character class
/// (upper, lower, digit) far more often than a hand-written name would. Hand-written names such as
/// <c>GetValue</c>, <c>DecryptString</c>, or <c>Utf8Encoder</c> stay below the threshold.
/// </remarks>
public static class ReactorNameHeuristics
{
    private const int MinimumLength = 8;
    private const double MinimumClassChurn = 0.45;

    public static bool IsGeneratedName(string? name)
    {
        if (string.IsNullOrEmpty(name))
            return false;
        if (name.Any(character => !IsIdentifierCharacter(character)))
            return true;
        if (name.Length < MinimumLength)
            return false;

        var transitions = 0;
        for (var index = 1; index < name.Length; index++)
        {
            if (ClassOf(name[index]) != ClassOf(name[index - 1]))
                transitions++;
        }

        return (double)transitions / (name.Length - 1) >= MinimumClassChurn;
    }

    private static bool IsIdentifierCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is '_';

    private static int ClassOf(char character) => character switch
    {
        _ when char.IsAsciiLetterUpper(character) => 0,
        _ when char.IsAsciiLetterLower(character) => 1,
        _ when char.IsAsciiDigit(character) => 2,
        _ => 3
    };
}
