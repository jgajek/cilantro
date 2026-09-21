namespace Probe
{
    // Benign ground truth: protect this build with the same settings as the corpus,
    // then compare these returns and mutated bytes after recovery.
    public static class RecoveryGroundTruth
    {
        public static int Branch(int value)
        {
            var state = unchecked((uint)value * 2654435761u);
            switch ((state >> 29) & 3)
            {
                case 0: return unchecked(value + 17);
                case 1: return value ^ 0x55AA;
                case 2: return unchecked(-value);
                default: return value >> 3;
            }
        }

        public static int Mutate(byte[] bytes, int divisor)
        {
            try
            {
                var sum = 0;
                for (var i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)(bytes[i] ^ (i + 19));
                    sum += bytes[i];
                }
                return sum / divisor;
            }
            catch (System.DivideByZeroException) { return -7; }
            finally
            {
                if (bytes.Length > 0) bytes[bytes.Length - 1] ^= 3;
            }
        }
    }
}
