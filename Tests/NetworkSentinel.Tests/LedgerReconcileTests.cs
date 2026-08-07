using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The decision half of startup reconciliation: given what `pfctl -s rules`
/// printed, is a ledger entry actually loaded? Getting this wrong in the "loaded"
/// direction leaves a stale entry suppressing auto-block; getting it wrong in the
/// "missing" direction re-applies or deletes rules for no reason.
/// </summary>
public class LedgerReconcileTests
{
    // pfctl reprints rules in normalized form — no "# name" comments, and ports
    // rendered as "port = N". That is why the reconciler matches on content.
    private const string Dump =
        """
        block drop in quick from 203.0.113.51 to any
        block drop out quick from any to 203.0.113.51
        block drop in quick proto tcp from any to any port = 3389
        """;

    private static FirewallRuleInfo IpRule(string ip) => new()
    {
        Name = FirewallService.IpRuleName(ip, true),
        Kind = FirewallRuleKind.IpBlock,
        Direction = FirewallDirection.Inbound,
        RemoteAddresses = ip,
        Enabled = true,
        IsBlock = true
    };

    private static FirewallRuleInfo PortRule(int port) => new()
    {
        Name = FirewallService.PortRuleName(port, "TCP", true),
        Kind = FirewallRuleKind.PortBlock,
        Direction = FirewallDirection.Inbound,
        LocalPorts = port.ToString(),
        Protocol = "TCP",
        Enabled = true,
        IsBlock = true
    };

    [Fact]
    public void RecognisesALoadedIpRule()
        => Assert.True(FirewallService.IsLoaded(IpRule("203.0.113.51"), Dump));

    [Fact]
    public void RecognisesAnUnloadedIpRule()
        => Assert.False(FirewallService.IsLoaded(IpRule("198.51.100.7"), Dump));

    [Fact]
    public void RecognisesALoadedPortRuleDespiteTheEqualsSign()
        => Assert.True(FirewallService.IsLoaded(PortRule(3389), Dump));

    [Fact]
    public void RecognisesAnUnloadedPortRule()
        => Assert.False(FirewallService.IsLoaded(PortRule(5900), Dump));

    [Fact]
    public void EmptyDumpMeansNothingIsLoaded()
    {
        // The post-reboot case: macOS boots with PF disabled, so the anchor holds
        // nothing even though firewall-rules.json survived.
        Assert.False(FirewallService.IsLoaded(IpRule("203.0.113.51"), ""));
        Assert.False(FirewallService.IsLoaded(PortRule(3389), ""));
    }

    [Theory]
    [InlineData("pfctl: /dev/pf: No such file or directory")]
    [InlineData("anchor does not exist")]
    [InlineData("pf not enabled")]
    [InlineData("Operation not supported by device")]
    public void MissingAnchorOrDisabledPfCountsAsNothingLoaded(string message)
        => Assert.True(FirewallService.LooksLikeNothingLoaded(message));

    [Theory]
    [InlineData("block drop in quick from 203.0.113.51 to any")]
    [InlineData("")]
    public void RealRuleOutputIsNotMistakenForAnError(string message)
        => Assert.False(FirewallService.LooksLikeNothingLoaded(message));

    [Fact]
    public void UncheckableRuleIsLeftAlone()
    {
        // No address and no port to look for: reporting it missing would re-apply or
        // delete a rule on no evidence.
        var vague = new FirewallRuleInfo
        {
            Name = "NetworkSentinel-Something",
            Kind = FirewallRuleKind.IpBlock,
            RemoteAddresses = "",
            Enabled = true,
            IsBlock = true
        };

        Assert.True(FirewallService.IsLoaded(vague, Dump));
    }
}
