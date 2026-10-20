using System;

namespace CheckProbe
{
    public static class Program
    {
        private static int notifications;
        private static bool detected;
        public static Action<bool> Callback = OnCheck;
        public static bool Detection { get => detected; set => OnCheck(value); }

        public static int Main(string[] args)
        {
            Console.WriteLine("CHECK_PROBE " + Guarded(3) + " " + Guarded(7));
            Console.WriteLine("Detected:" + detected);
            if (args.Length != 0) Console.WriteLine("Notifications:" + notifications);
            return 0;
        }

        public static int Guarded(int value) => unchecked(value * 17 + 3);

        public static void OnCheck(bool result)
        {
            detected |= result;
            notifications++;
        }
    }
}
