using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Type initializers whose bodies do nothing at all.
/// </summary>
/// <remarks>
/// Reactor puts a call to its loader at the head of every type's initializer, and on a type that
/// had no initializer of its own it writes one to hold the call. Eliding the call leaves the body
/// behind with nothing in it, so the assembly ends up carrying an initializer per type that runs
/// and returns. That residue is worth removing for the same reason the call was: it is not the
/// program's, and the oracle for these samples has no initializer on those types at all.
///
/// Emptiness is what makes removal safe, and it is a property of the body rather than of who is
/// thought to have written it. A type initializer runs when the runtime decides the type is being
/// used, so unreachability says much less about it than about an ordinary method — nothing has to
/// call it for it to run. What can be said instead is that running it achieves nothing, and a
/// method that achieves nothing achieves nothing whenever it is called. Removing it also cannot
/// change when anything else happens: the initializer is the only thing the runtime was going to
/// run at that moment, and a type left without one has no such moment.
///
/// Distinguishing the residue from a real initializer needs no separate test, because a type whose
/// own initializer Reactor merely prepended to still has its own code in the body afterwards and so
/// is not empty. The emptiness test therefore separates the initializer Reactor added from the one
/// it borrowed, which is exactly the line that wants drawing.
/// </remarks>
public static class EmptyTypeInitializers
{
    /// <summary>
    /// Whether <paramref name="method"/> is a type initializer that cannot do anything.
    /// </summary>
    /// <remarks>
    /// The bar is deliberately literal: padding and a return, nothing else. Elision leaves
    /// <c>nop</c>s where the call it removed used to be, so that is the shape the residue takes,
    /// and anything richer — a handler, a store, a branch — is a body this cannot reason about and
    /// declines rather than guesses at.
    /// </remarks>
    public static bool DoesNothing(MethodDef method)
    {
        if (!method.IsStaticConstructor || !method.HasBody)
            return false;
        var body = method.Body;
        if (body.HasExceptionHandlers || body.Instructions.Count == 0)
            return false;
        for (var index = 0; index < body.Instructions.Count - 1; index++)
        {
            if (body.Instructions[index].OpCode.Code != Code.Nop)
                return false;
        }

        return body.Instructions[^1].OpCode.Code == Code.Ret;
    }
}
