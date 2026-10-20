using System;
using System.Globalization;
using System.Resources;

namespace SatelliteProbe
{
    internal static class Secrets
    {
        private static readonly ResourceManager Manager = new ResourceManager("SatelliteProbe.Secrets", typeof(Secrets).Assembly);
        public static string Message => Manager.GetString("Message", CultureInfo.CurrentUICulture);
        public static string Unicode => Manager.GetString("Unicode", CultureInfo.CurrentUICulture);
        public static byte[] Bytes => (byte[])Manager.GetObject("Bytes", CultureInfo.CurrentUICulture);
        public static void Release() => Manager.ReleaseAllResources();
    }

    public static class Program
    {
        public static int Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            foreach (var name in new[] { "", "fr", "fr-CA", "fr-FR", "de-DE", "fr-CA" })
            {
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
                Console.WriteLine(name + ":" + Secrets.Message + ":" + Secrets.Unicode + ":" + Convert.ToBase64String(Secrets.Bytes));
                Secrets.Release();
            }
            return 0;
        }
    }
}
