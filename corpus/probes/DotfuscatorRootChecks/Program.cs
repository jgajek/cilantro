using System;
using System.Runtime.Versioning;

[assembly: TargetPlatform("Android34.0")]
[assembly: SupportedOSPlatform("android21.0")]
namespace RootCheckProbe
{
    public static class Program
    {
        private static int notifications;
        private static bool detected;
        public static int Guarded(int value) => unchecked(value * 17 + 3);
        public static void OnCheck(bool result) { detected |= result; notifications++; }

        // Keeps the producer's real Android reference. Desktop oracle trials do
        // not invoke Android APIs; device behavior needs a separate Android trial.
        public static string AndroidTags() => Android.OS.Build.Tags;

        public static int Main(string[] args)
        {
            var replayCleanNotification = args.Length != 0 && args[0] == "--clean-oracle";
            if (replayCleanNotification) OnCheck(false);
            var first = Guarded(3);
            if (replayCleanNotification) OnCheck(false);
            var second = Guarded(7);
            Console.WriteLine("ROOT_PROBE " + first + " " + second);
            Console.WriteLine("Detected:" + detected);
            Console.WriteLine("Notifications:" + notifications);
            return 0;
        }
    }
}
