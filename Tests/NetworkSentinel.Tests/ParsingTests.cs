using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class ParsingTests
{
    [Fact]
    public void HoneypotPortsParseAndDeduplicate()
    {
        var ports = HoneypotService.ParsePorts(" 2323, 3389 ,2323, nonsense, 70000, 0, 5900 ");
        Assert.Equal(new[] { 2323, 3389, 5900 }, ports);
    }

    [Fact]
    public void HoneypotPortsEmptyInput()
    {
        Assert.Empty(HoneypotService.ParsePorts(null));
        Assert.Empty(HoneypotService.ParsePorts(""));
    }

    [Theory]
    [InlineData("NetworkSentinel-IP-1.2.3.4-In", "1.2.3.4")]
    [InlineData("NetworkSentinel-IP-2001_db8__1-Out", "2001:db8::1")]
    public void ExtractsIpFromManagedRuleName(string ruleName, string expected)
    {
        Assert.True(FirewallService.TryExtractIpFromManagedRule(ruleName, null, out var ip));
        Assert.Equal(expected, ip);
    }

    [Fact]
    public void RejectsForeignRuleName()
    {
        // The LocalAddresses.IsOwnAddress case from the Linux suite is deferred with
        // the rest of the prevention work — that type does not exist here yet.
        Assert.False(FirewallService.TryExtractIpFromManagedRule("com.apple.something", null, out _));
    }
}
