using System.Globalization;
using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

[Flags]
public enum ConfuserExCapability
{
    None = 0,
    InvisibleNames = 1 << 0,
    EncryptedSection = 1 << 1,
    AntiTamper = 1 << 2,
    ConstantsTable = 1 << 3,
    ControlFlowSwitchDispatch = 1 << 4,
    AntiDebug = 1 << 5
}

public sealed record ConfuserExStructureFacts(
    int InvisiblyNamedMemberCount,
    int BodylessMethodCount,
    int MethodsInEncryptedSection,
    string? EncryptedSectionName,
    uint EncryptedSectionRva,
    uint EncryptedSectionSize,
    bool DeclaresVirtualProtect,
    bool DeclaresDebuggerProbe,
    int ModuleInitializerCallCount,
    ConfuserExCapability Capabilities,
    double Confidence)
{
    public bool IsConfuserExProtected => Confidence >= 0.55;

    public bool HasEncryptedSection => EncryptedSectionName is not null;

    public IReadOnlyList<string> CapabilityNames =>
        Enum.GetValues<ConfuserExCapability>()
            .Where(value => value != ConfuserExCapability.None && Capabilities.HasFlag(value))
            .Select(value => value switch
            {
                ConfuserExCapability.InvisibleNames => "invisible-names",
                ConfuserExCapability.EncryptedSection => "encrypted-section",
                ConfuserExCapability.AntiTamper => "anti-tamper",
                ConfuserExCapability.ConstantsTable => "constants-table",
                ConfuserExCapability.ControlFlowSwitchDispatch => "switch-dispatch-control-flow",
                ConfuserExCapability.AntiDebug => "anti-debug",
                _ => value.ToString()
            })
            .ToArray();
}

/// <summary>
/// Recognizes ConfuserEx by the shape it leaves in the module and its image, without relying on
/// any constant a build randomizes.
/// </summary>
/// <remarks>
/// ConfuserEx randomizes its keys and mutates its own algorithms per build, so a signature over
/// the protector's arithmetic recognizes one sample and misses the next. What it cannot randomize
/// is the arrangement: method bodies moved into a section it added and encrypted, which the
/// metadata still points into, decrypted by code the module initializer runs before anything else.
/// Those are properties of the design rather than of a build.
/// </remarks>
public static class ConfuserExStructureDetector
{
    private const uint MemoryExecute = 0x2000_0000;
    private const uint MemoryRead = 0x4000_0000;
    private const uint MemoryWrite = 0x8000_0000;

    private static readonly string[] OrdinarySectionNames =
        [".text", ".rsrc", ".reloc", ".data", ".rdata", ".sdata", ".idata", ".tls", ".bss"];

    public static ConfuserExStructureFacts Analyze(ModuleDefMD module, PeImageView image)
    {
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(image);

        var types = module.GetTypes().ToArray();
        var methods = types.SelectMany(type => type.Methods).ToArray();
        var invisible = types.Count(type => HasInvisibleName(type.Name)) +
            methods.Count(method => HasInvisibleName(method.Name)) +
            types.SelectMany(type => type.Fields).Count(field => HasInvisibleName(field.Name));

        var encrypted = FindEncryptedSection(image);
        var bodyless = methods.Count(method => method.RVA != 0 && !method.HasBody);
        var inEncrypted = encrypted is null
            ? 0
            : methods.Count(method => IsWithin(encrypted, (uint)method.RVA));

        var global = module.GlobalType;
        var initializerCalls = ModuleInitializerCallCount(global);
        var virtualProtect = DeclaresNative(global, "VirtualProtect");
        var debuggerProbe = DeclaresNative(global, "IsDebuggerPresent") ||
            DeclaresNative(global, "CheckRemoteDebuggerPresent");

        var capabilities = ConfuserExCapability.None;
        if (invisible >= 10) capabilities |= ConfuserExCapability.InvisibleNames;
        if (encrypted is not null) capabilities |= ConfuserExCapability.EncryptedSection;
        // Anti-tamper is the conjunction that matters: a section the module initializer has to
        // decrypt before any of the method bodies the metadata places inside it can run.
        if (encrypted is not null && inEncrypted > 0 && initializerCalls > 0 && virtualProtect)
            capabilities |= ConfuserExCapability.AntiTamper;
        if (debuggerProbe) capabilities |= ConfuserExCapability.AntiDebug;
        if (HasConstantsInitializer(global)) capabilities |= ConfuserExCapability.ConstantsTable;

        // Whole percentage points, for the same reason the Reactor detector uses them: the gate is a
        // decimal figure, and weights added up as binary fractions can land just under a total they
        // were meant to reach exactly. No combination of these six misses its gate today, but the
        // arithmetic should not be what decides that.
        var points = 0;
        if (invisible >= 10) points += 30;
        if (encrypted is not null) points += 30;
        if (inEncrypted > 0) points += 20;
        if (virtualProtect) points += 10;
        if (initializerCalls > 0) points += 10;
        if (debuggerProbe) points += 5;
        var score = Math.Min(100, points) / 100.0;

        return new ConfuserExStructureFacts(
            invisible,
            bodyless,
            inEncrypted,
            encrypted?.Name,
            encrypted?.VirtualAddress ?? 0,
            encrypted?.MappedSize ?? 0,
            virtualProtect,
            debuggerProbe,
            initializerCalls,
            capabilities,
            score);
    }

    /// <summary>
    /// The section ConfuserEx added for the code it encrypted: one the linker would not have
    /// produced, asking to be written to as well as executed, and holding method bodies.
    /// </summary>
    public static PeSection? FindEncryptedSection(PeImageView image)
    {
        ArgumentNullException.ThrowIfNull(image);
        return image.Sections.FirstOrDefault(section =>
            !OrdinarySectionNames.Contains(section.Name, StringComparer.Ordinal) &&
            (section.Characteristics & (MemoryRead | MemoryWrite | MemoryExecute)) ==
                (MemoryRead | MemoryWrite | MemoryExecute) &&
            section.MappedSize > 0);
    }

    /// <summary>
    /// Whether a name is made of characters that render as nothing, which is how ConfuserEx makes
    /// distinct members that a reader cannot tell apart.
    /// </summary>
    private static bool HasInvisibleName(UTF8String? name)
    {
        var text = UTF8String.ToSystemStringOrEmpty(name);
        if (text.Length == 0)
            return false;
        foreach (var character in text)
        {
            if (!IsInvisible(character))
                return false;
        }
        return true;
    }

    private static bool IsInvisible(char character) =>
        CharUnicodeInfo.GetUnicodeCategory(character) is
            UnicodeCategory.Format or UnicodeCategory.Control or
            UnicodeCategory.OtherNotAssigned or UnicodeCategory.PrivateUse ||
        character is '\u200B' or '\u200C' or '\u200D' or '\uFEFF';

    private static bool IsWithin(PeSection section, uint rva) =>
        rva != 0 && rva >= section.VirtualAddress &&
        rva - section.VirtualAddress < section.MappedSize;

    private static int ModuleInitializerCallCount(TypeDef global)
    {
        var initializer = global.FindStaticConstructor();
        if (initializer?.HasBody != true)
            return 0;
        return initializer.Body.Instructions
            .Count(instruction =>
                instruction.OpCode.Code is dnlib.DotNet.Emit.Code.Call &&
                (instruction.Operand as IMethod)?.DeclaringType?.FullName == global.FullName);
    }

    /// <summary>
    /// Whether the global type declares a platform call by this entry point, whatever the
    /// obfuscator named the managed method.
    /// </summary>
    private static bool DeclaresNative(TypeDef global, string entryPoint) =>
        global.Methods.Any(method =>
            method.ImplMap is { } native &&
            string.Equals(native.Name, entryPoint, StringComparison.Ordinal));

    /// <summary>
    /// ConfuserEx's constants protection seeds its table from a byte array laid down as field
    /// data, which it fills with <c>RuntimeHelpers.InitializeArray</c>.
    /// </summary>
    private static bool HasConstantsInitializer(TypeDef global) =>
        global.Methods.Any(method => method.HasBody &&
            method.Body.Instructions.Any(instruction =>
                (instruction.Operand as IMethod)?.Name == "InitializeArray"));
}
