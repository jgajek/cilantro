using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Whether a member is part of the surface that code outside the assembly can name.
/// </summary>
/// <remarks>
/// This is the boundary at which static evidence runs out. Inside it, the module's own instructions
/// account for every use; outside it, an unseen caller can do anything the member allows. Both
/// reachability roots and the write-once proof therefore turn on the same question, so they ask it
/// in one place.
/// </remarks>
public static class MemberVisibility
{
    public static bool IsExternallyVisible(MethodDef method) =>
        IsExternallyVisible(method.DeclaringType) &&
        (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly);

    public static bool IsExternallyVisible(TypeDef? type)
    {
        while (type is not null)
        {
            if (!type.IsNested)
                return type.IsPublic;
            if (!type.IsNestedPublic && !type.IsNestedFamily && !type.IsNestedFamilyOrAssembly)
                return false;
            type = type.DeclaringType;
        }
        return false;
    }
}
