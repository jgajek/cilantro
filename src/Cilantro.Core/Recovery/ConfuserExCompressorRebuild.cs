using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>Restores the entry point that ConfuserEx's compressor moved into its wrapper.</summary>
internal static class ConfuserExCompressorRebuild
{
    internal static bool TryRebuild(ArtifactContext context, MethodDef root, byte[] payload,
        out byte[] standalone, out uint entryToken, out string diagnostic)
    {
        standalone = [];
        entryToken = 0;
        diagnostic = string.Empty;
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts?.IsConfuserExProtected != true ||
            root != context.Module.EntryPoint || !root.HasBody ||
            !root.Body.Instructions.Any(instruction => instruction.Operand is IMethod called &&
                called.DeclaringType?.FullName == "System.Reflection.Assembly" &&
                called.Name == "LoadModule") ||
            context.Module.Assembly?.PublicKey is { Data.Length: > 0 })
            return false;

        var signatures = new List<uint>();
        var il = root.Body.Instructions;
        for (var index = 1; index < il.Count; index++)
            if (il[index].Operand is IMethod called &&
                called.DeclaringType?.FullName == "System.Reflection.Module" &&
                called.Name == "ResolveSignature" &&
                il[index - 1].IsLdcI4())
                signatures.Add(unchecked((uint)il[index - 1].GetLdcI4Value()));
        if (signatures.Count != 1 || (signatures[0] & 0xff000000u) != 0x11000000u ||
            !context.Module.Metadata.TablesStream.TryReadStandAloneSigRow(signatures[0] & 0x00ffffffu,
                out var row))
        {
            diagnostic = "The compressor entry signature was not uniquely identified.";
            return false;
        }
        var signature = context.Module.Metadata.BlobStream.Read(row.Signature);
        if (signature.Length < 4)
        {
            diagnostic = "The compressor entry signature is too short.";
            return false;
        }
        entryToken = BinaryPrimitives.ReadUInt32LittleEndian(signature);
        if ((entryToken & 0xff000000u) != 0x06000000u)
        {
            diagnostic = "The compressor entry signature does not name a method definition.";
            return false;
        }
        try
        {
            using var module = ModuleDefMD.Load(payload);
            if (module.Assembly is null || module.Assembly.Name != context.Module.Assembly?.Name ||
                module.EntryPoint is not null ||
                module.ResolveToken(new MDToken(entryToken)) is not MethodDef { IsStatic: true, HasBody: true } entry ||
                entry.MethodSig is not { Params.Count: 0 or 1 } methodSig ||
                methodSig.RetType.ElementType is not (ElementType.Void or ElementType.I4) ||
                methodSig.Params.Count == 1 && methodSig.Params[0].FullName != "System.String[]")
            {
                diagnostic = "The extracted module identity or entry-point method does not match the wrapper.";
                return false;
            }
            module.EntryPoint = entry;
            using var stream = new MemoryStream();
            module.Write(stream);
            standalone = stream.ToArray();
            using var check = ModuleDefMD.Load(standalone);
            if (check.EntryPoint?.MDToken.Raw != entryToken ||
                check.Assembly?.FullName != module.Assembly.FullName ||
                check.Resources.Count != module.Resources.Count)
            {
                standalone = [];
                diagnostic = "The standalone compressor payload did not round-trip with its entry point.";
                return false;
            }
            return true;
        }
        catch (Exception exception) when (exception is BadImageFormatException or IOException or
            ArgumentException or InvalidOperationException)
        {
            standalone = [];
            diagnostic = $"Standalone compressor rebuilding failed: {exception.Message}";
            return false;
        }
    }
}
