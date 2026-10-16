using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core.Native;
using dnlib.DotNet;

// Metadata/extraction only: the input and recovered assembly are never executed.
if (args.Length != 1)
    throw new ArgumentException("Usage: native-capture INPUT");
var bytes = File.ReadAllBytes(args[0]);
if (!NativeBootstrap.TryUnpack(bytes, out var f, out var reason) || f is null)
    throw new InvalidDataException(reason);
using var module = ModuleDefMD.Load(f.Assembly);
Console.WriteLine(JsonSerializer.Serialize(new {
    Input = Path.GetFileName(args[0]),
    InputSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
    NativeBootstrap = NativeBootstrap.Looks(bytes),
    f.Resource, f.KeyFileOffset, f.EncryptedLength, f.InflatedLength,
    f.CameFromLoader, f.ClrVersion, f.CandidateRoutines,
    ManagedBytes = f.Assembly.Length,
    ManagedSha256 = Convert.ToHexStringLower(SHA256.HashData(f.Assembly)),
    Module = module.Name.String,
    Types = System.Linq.Enumerable.Count(module.GetTypes())
}, new JsonSerializerOptions { WriteIndented = true }));
