using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Cilantro.Cli;

/// <summary>Classic Windows console hosts require VT processing before accepting ANSI colors.</summary>
[SupportedOSPlatform("windows")]
internal static partial class WindowsConsole
{
    private const uint ProcessedOutput = 0x0001;
    private const uint VirtualTerminalProcessing = 0x0004;

    internal static bool TryEnableVirtualTerminal(int standardHandle)
    {
        var handle = GetStdHandle(standardHandle);
        return GetConsoleMode(handle, out var mode) &&
            EnableOutputMode(mode, enabled => SetConsoleMode(handle, enabled));
    }

    // Preserve wrapping and every other host setting. If enabling VT fails, callers use plain text.
    internal static bool EnableOutputMode(uint mode, Func<uint, bool> setMode)
    {
        var enabled = mode | ProcessedOutput | VirtualTerminalProcessing;
        return mode == enabled || setMode(enabled);
    }

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint GetStdHandle(int standardHandle);

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleMode(nint handle, out uint mode);

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleMode(nint handle, uint mode);
}
