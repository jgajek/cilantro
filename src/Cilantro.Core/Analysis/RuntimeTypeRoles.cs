using System.Text;

namespace Cilantro.Core.Analysis;

/// <summary>Replaces complete type identifiers without rewriting incidental name substrings.</summary>
internal static class RuntimeTypeRoles
{
    internal static string Replace(string text, IReadOnlyList<(string Name, string Role)> roles)
    {
        var output = new StringBuilder(text.Length);
        for (var at = 0; at < text.Length;)
        {
            (string? Name, string? Role) match = default;
            foreach (var role in roles)
                if (role.Name.Length > (match.Name?.Length ?? 0) && at + role.Name.Length <= text.Length &&
                    text.AsSpan(at, role.Name.Length).SequenceEqual(role.Name) &&
                    (at == 0 || Boundary(text[at - 1])) && (at + role.Name.Length == text.Length || Boundary(text[at + role.Name.Length]))) match = role;
            if (match.Name is not null) { output.Append(match.Role); at += match.Name.Length; }
            else output.Append(text[at++]);
        }
        return output.ToString();
    }

    private static bool Boundary(char value) => char.IsWhiteSpace(value) || value is '[' or ']' or '<' or '>' or '(' or ')' or '&' or '*' or ',' or ':' or '@' or '=';
}
