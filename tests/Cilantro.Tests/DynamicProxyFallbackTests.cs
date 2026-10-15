using System.Dynamic;
using System.Linq.Expressions;
using System.Reflection;

namespace Cilantro.Tests;

public sealed class DynamicProxyFallbackTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public void UnchangedProxyUsesBinderButOverrideCanReplaceInvocation(int kind, bool overridden)
    {
        Proxy<Value> proxy = kind switch { 1 => new Derived(), 2 => new Override(), _ => new Proxy<Value>() };
        var value = kind == 2 ? new OverrideValue() : new Value(proxy);
        dynamic receiver = value;
        object result = receiver.GetType();
        Assert.Equal(overridden, value.OverrideObserved);
        if (overridden) Assert.Equal("custom invocation", result);
        else Assert.Equal(value.GetType(), result);
    }

    public class Proxy<T>
    {
        public virtual bool TryInvokeMember(T value, InvokeMemberBinder binder, object[] args, out object? result)
        { result = null; return false; }
    }
    private sealed class Derived : Proxy<Value> { }
    private sealed class Override : Proxy<Value>
    {
        public override bool TryInvokeMember(Value value, InvokeMemberBinder binder, object[] args, out object? result)
        { result = "custom invocation"; return true; }
    }
    private sealed class OverrideValue() : Value(new Override());
    public class Value(Proxy<Value> proxy) : IDynamicMetaObjectProvider
    {
        public bool OverrideObserved { get; private set; }
        public DynamicMetaObject GetMetaObject(Expression parameter) => new Meta(parameter, this, proxy);
        private sealed class Meta(Expression expression, Value value, Proxy<Value> proxy)
            : DynamicMetaObject(expression, BindingRestrictions.Empty, value)
        {
            public override DynamicMetaObject BindInvokeMember(InvokeMemberBinder binder, DynamicMetaObject[] args)
            {
                var isOverride = proxy.GetType().GetMethods((BindingFlags)52).Any(m =>
                    m.Name == "TryInvokeMember" && m.DeclaringType != typeof(Proxy<Value>) &&
                    m.GetBaseDefinition().DeclaringType == typeof(Proxy<Value>));
                value.OverrideObserved = isOverride;
                if (!isOverride) return base.BindInvokeMember(binder, args);
                // This positive control deliberately uses the custom implementation.
                if (!proxy.TryInvokeMember(value, binder, [], out var result))
                    return base.BindInvokeMember(binder, args);
                return new DynamicMetaObject(Expression.Constant(result, typeof(object)),
                    BindingRestrictions.GetInstanceRestriction(Expression, value));
            }
        }
    }
}
