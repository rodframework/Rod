using System.Net;
using Rod.Redirector;

namespace Rod.Redirector.Tests;

public class CidrAllowListTests
{
    [Fact]
    public void Empty_Allows_All()
    {
        Assert.True(CidrAllowList.AllowAll.Allows(IPAddress.Parse("1.2.3.4")));
        Assert.True(CidrAllowList.AllowAll.Allows(IPAddress.Parse("::1")));
    }

    [Fact]
    public void Null_Input_Yields_AllowAll()
    {
        var list = CidrAllowList.Parse(null);

        Assert.Same(CidrAllowList.AllowAll, list);
    }

    [Fact]
    public void Parses_Comma_Separated_Cidrs()
    {
        var list = CidrAllowList.Parse(new[] { "10.0.0.0/8, 192.168.0.0/16" });

        Assert.True(list.Allows(IPAddress.Parse("10.255.0.1")));
        Assert.True(list.Allows(IPAddress.Parse("192.168.5.5")));
        Assert.False(list.Allows(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public void Handles_Ipv6()
    {
        var list = CidrAllowList.Parse(new[] { "2001:db8::/32" });

        Assert.True(list.Allows(IPAddress.Parse("2001:db8::1")));
        Assert.False(list.Allows(IPAddress.Parse("2001:db9::1")));
    }

    [Fact]
    public void Single_Address_Cidr_Matches_Only_It()
    {
        var list = CidrAllowList.Parse(new[] { "127.0.0.1/32" });

        Assert.True(list.Allows(IPAddress.Parse("127.0.0.1")));
        Assert.False(list.Allows(IPAddress.Parse("127.0.0.2")));
    }

    [Fact]
    public void Rejects_Malformed_Token()
    {
        Assert.Throws<ArgumentException>(() => CidrAllowList.Parse(new[] { "nope" }));
    }

    [Fact]
    public void Ignores_Empty_Entries()
    {
        var list = CidrAllowList.Parse(new[] { "", "10.0.0.0/8", "  " });

        Assert.True(list.Allows(IPAddress.Parse("10.0.0.1")));
        Assert.False(list.Allows(IPAddress.Parse("1.1.1.1")));
    }
}
