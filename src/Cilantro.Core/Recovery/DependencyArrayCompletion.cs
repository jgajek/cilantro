using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Removes the generated stream/ToArray round trip without sharing mutable payload arrays.</summary>
internal static class DependencyArrayCompletion
{
    internal static bool Apply(ArtifactContext context, MethodDef helper)
    {
        if (!helper.IsStatic || !helper.HasBody || helper.HasGenericParameters ||
            MemberVisibility.IsExternallyVisible(helper.DeclaringType) || helper.Body.ExceptionHandlers.Count != 0 ||
            helper.MethodSig.Params.Count != 1 || helper.MethodSig.Params[0].ElementType != ElementType.Object ||
            helper.ReturnType.FullName != "System.IO.Stream") return false;
        var il = helper.Body.Instructions;
        var at = 0;
        while (at + 1 < il.Count && il[at].OpCode.Code == Code.Ldtoken && il[at].Operand is TypeDef type &&
            type.Module == context.Module && Framework(il[at + 1], Code.Call,
                "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)")) at += 2;
        // Empty ToArray may return a shared empty array; do not replace it with a fresh identity.
        if (il.Count - at != 7 || !il[at].IsLdcI4() || il[at].GetLdcI4Value() <= 0 ||
            il[at + 1].OpCode.Code != Code.Newarr || il[at + 1].Operand is not ITypeDefOrRef element ||
            element.FullName != "System.Byte" || element.DefinitionAssembly?.FullName != context.Module.CorLibTypes.AssemblyRef.FullName ||
            il[at + 2].OpCode.Code != Code.Dup || il[at + 3].OpCode.Code != Code.Ldtoken ||
            il[at + 3].Operand is not FieldDef field || field.DeclaringType != helper.DeclaringType ||
            !field.IsStatic || !field.IsInitOnly || !field.HasFieldRVA || field.InitialValue?.Length != il[at].GetLdcI4Value() ||
            !Framework(il[at + 4], Code.Call, "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)") ||
            !Framework(il[at + 5], Code.Newobj, "System.Void System.IO.MemoryStream::.ctor(System.Byte[])") ||
            il[at + 6].OpCode.Code != Code.Ret) return false;
        var uses = new List<(MethodDef Caller, Instruction Call)>();
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            foreach (var instruction in method.Body.Instructions)
                if (instruction.Operand is IMethod reference && reference.ResolveMethodDef() == helper)
                {
                    // Generated callers reference the definition directly. Refuse pointers,
                    // tokens, external signatures, alternate entries and escaping streams.
                    if (instruction.Operand != helper || instruction.OpCode.Code != Code.Call ||
                        !DependencyDecoderCompletionPass.OnlyToArray(method, instruction)) return false;
                    uses.Add((method, instruction));
                }
        if (uses.Count == 0) return false;
        using var edit = new BodyMutationBatch(uses.Select(u => u.Caller).Append(helper).Distinct());
        var oldSignature = helper.MethodSig;
        var committed = false;
        try
        {
            foreach (var (caller, call) in uses)
            {
                var cursor = caller.Body.Instructions.IndexOf(call) + 1;
                while (cursor < caller.Body.Instructions.Count)
                {
                    var instruction = caller.Body.Instructions[cursor++];
                    var last = instruction.OpCode.Code == Code.Callvirt;
                    instruction.OpCode = OpCodes.Nop; instruction.Operand = null;
                    if (last) break;
                }
            }
            il[at + 5].OpCode = OpCodes.Nop; il[at + 5].Operand = null;
            helper.MethodSig = MethodSig.CreateStatic(new SZArraySig(context.Module.CorLibTypes.Byte), context.Module.CorLibTypes.Object);
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context)).Passed) return false;
            edit.RecordChange(context, new("dependency-input-completion", "remove-dependency-array-copy", helper.FullName,
                $"Removed the generated stream/ToArray round trip at {uses.Count} call site(s); each successful call still returns fresh payload bytes and runs the original shared initialization."));
            edit.Commit(); committed = true; return true;
        }
        finally { if (!committed) helper.MethodSig = oldSignature; }

        bool Framework(Instruction instruction, Code code, string signature) => instruction.OpCode.Code == code &&
            instruction.Operand is IMethod call && call.FullName == signature &&
            call.DeclaringType.DefinitionAssembly?.FullName == context.Module.CorLibTypes.AssemblyRef.FullName;
    }
}
