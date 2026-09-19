namespace Cilantro.Core;

public static class Entropy
{
    public static double Calculate(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var value in data)
        {
            counts[value]++;
        }

        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var probability = (double)count / data.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
