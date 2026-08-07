using NetworkSentinel.Models;
using NetworkSentinel.Native;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// DNS hygiene detections, driven by synthetic flows. The monitor must be started for
/// anything to fire — an un-started one is inert on purpose, so a disabled feature
/// cannot raise alerts.
/// </summary>
public class DnsHygieneTests
{
    private const string LocalIp = "192.168.0.105";

    private static NetworkFlow Flow(string dest, int destPort, string src = LocalIp, string proto = "UDP")
        => new()
        {
            Protocol = proto,
            SourceAddress = src,
            SourcePort = 51000,
            DestinationAddress = dest,
            DestinationPort = destPort
        };

    private static DnsHygieneMonitor Started(string approved = "")
    {
        var monitor = new DnsHygieneMonitor { ApprovedResolvers = approved };
        monitor.Start();
        return monitor;
    }

    [Fact]
    public void UnstartedMonitorIsInert()
    {
        var monitor = new DnsHygieneMonitor();
        monitor.ObserveFlow(Flow("8.8.8.8", 53), DateTime.Now);
        Assert.Empty(monitor.DrainPending());
    }

    [Fact]
    public void PlaintextDnsLeavingTheMachineAlerts()
    {
        using var monitor = Started();
        monitor.ObserveFlow(Flow("8.8.8.8", 53), DateTime.Now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal(ThreatType.DnsAnomaly, threat.Type);
    }

    [Fact]
    public void QueriesToAResolverOnThisMachineAreNeverFlagged()
    {
        using var monitor = Started();
        // Local-resolver-with-encrypted-upstream is the arrangement that keeps queries
        // visible here while hiding them from the network. Flagging it would punish the
        // correct setup. "Local" means an address assigned to this host, not merely a
        // private one.
        monitor.ObserveFlow(Flow("127.0.0.1", 53), DateTime.Now);

        Assert.Empty(monitor.DrainPending());
    }

    [Fact]
    public void PlaintextToALanResolverStillCounts()
    {
        using var monitor = Started();
        // A router at 192.168.0.1 is not this machine, so the query really does leave it
        // in the clear — onto the LAN, where anything on the segment can read and rewrite
        // it. Deliberate: only a resolver running *here* is exempt.
        monitor.ObserveFlow(Flow("192.168.0.1", 53), DateTime.Now);

        Assert.Single(monitor.DrainPending());
    }

    [Theory]
    [InlineData(443)]   // ordinary HTTPS to a non-resolver
    [InlineData(80)]
    [InlineData(22)]
    public void NonDnsTrafficIsIgnored(int port)
    {
        using var monitor = Started();
        monitor.ObserveFlow(Flow("93.184.216.34", port), DateTime.Now);
        Assert.Empty(monitor.DrainPending());
    }

    [Fact]
    public void DotToAnApprovedResolverIsEncryptedNotAnAlert()
    {
        using var monitor = Started("9.9.9.9");
        monitor.ObserveFlow(Flow("9.9.9.9", 853), DateTime.Now);

        Assert.Empty(monitor.DrainPending());
        Assert.True(monitor.Counters.Encrypted > 0);
    }

    [Fact]
    public void DohIsOnlyRecognisedForAListedResolver()
    {
        using var monitor = Started("1.1.1.1");
        monitor.ObserveFlow(Flow("1.1.1.1", 443), DateTime.Now);

        // DoH is indistinguishable from the web, so it only counts as encrypted DNS when
        // the destination is a resolver the operator named.
        Assert.Empty(monitor.DrainPending());
        Assert.True(monitor.Counters.Encrypted > 0);
    }

    [Fact]
    public void PlaintextToAnUnapprovedResolverAlerts()
    {
        using var monitor = Started("1.1.1.1");
        monitor.ObserveFlow(Flow("8.8.8.8", 53), DateTime.Now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Contains("8.8.8.8", threat.Title + threat.Detail);
    }

    [Fact]
    public void RepeatedQueriesToOneResolverAreRateLimited()
    {
        using var monitor = Started();
        var now = DateTime.Now;

        // A resolver is queried constantly; one alert is information, fifty is a flood.
        for (var i = 0; i < 50; i++)
            monitor.ObserveFlow(Flow("8.8.8.8", 53), now.AddSeconds(i));

        Assert.Single(monitor.DrainPending());
    }

    [Fact]
    public void AllowlistResolutionDriftAlerts()
    {
        using var monitor = Started();
        var now = DateTime.Now;

        // Seed: the first answer is the baseline, never an alert.
        monitor.ObserveAllowlistResolution("github.com", new[] { "140.82.121.4" }, now);
        Assert.Empty(monitor.DrainPending());

        // Same /24 — CDN rotation, must stay quiet.
        monitor.ObserveAllowlistResolution("github.com", new[] { "140.82.121.9" }, now.AddMinutes(1));
        Assert.Empty(monitor.DrainPending());

        // A network it has never used: an allowlisted address is never auto-blocked, so a
        // hijacked lookup here would grant permanent immunity.
        monitor.ObserveAllowlistResolution("github.com", new[] { "203.0.113.66" }, now.AddHours(2));
        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal(ThreatType.DnsAnomaly, threat.Type);
        Assert.Contains("github.com", threat.Title + threat.Detail);
    }

    [Fact]
    public void VpnClientQueryBypassingTheResolverIsAClientLeak()
    {
        using var monitor = Started("1.1.1.1");
        monitor.IsVpnClientAddress = ip => ip == "10.8.0.2";

        monitor.ObserveFlow(Flow("8.8.8.8", 53, src: "10.8.0.2"), DateTime.Now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Contains("10.8.0.2", threat.Title + threat.Detail);
    }

    [Theory]
    [InlineData("192.168.1.55", "192.168.1.0/24")]
    [InlineData("140.82.121.4", "140.82.121.0/24")]
    public void NetworkOfIsA24ForIPv4(string ip, string expected)
        => Assert.Equal(expected, DnsHygieneMonitor.NetworkOf(ip));

    [Fact]
    public void NetworkOfIsA48ForIPv6()
        => Assert.Equal("2606:4700:0000::/48", DnsHygieneMonitor.NetworkOf("2606:4700::1111"));

    [Fact]
    public void NetworkOfRejectsJunk()
        => Assert.Equal("", DnsHygieneMonitor.NetworkOf("not-an-ip"));

    [Fact]
    public void ParseResolversAcceptsCommasSpacesAndSemicolons()
    {
        var set = DnsHygieneMonitor.ParseResolvers("1.1.1.1, 9.9.9.9;  8.8.8.8  nonsense");
        Assert.Equal(3, set.Count);
        Assert.Contains("1.1.1.1", set);
        Assert.DoesNotContain("nonsense", set);
    }

    [Fact]
    public void ParseResolversHandlesEmptyInput()
    {
        Assert.Empty(DnsHygieneMonitor.ParseResolvers(null));
        Assert.Empty(DnsHygieneMonitor.ParseResolvers("   "));
    }
}
