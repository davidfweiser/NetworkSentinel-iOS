using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The graph all three frontends share. These assertions are the drift gate: the
/// GUI, TUI and web console each used to build this by hand, and the copies
/// disagreed — the poll interval was applied in one of the three.
/// </summary>
public class SentinelCoreTests
{
    [Fact]
    public void AppliesThePersistedPollInterval()
    {
        var settings = new AppSettings { MonitorPollMs = 3500 };
        using var core = new SentinelCore(settings);

        // Only the GUI used to do this, so the TUI and web console ran at the
        // default cadence no matter what was saved.
        Assert.Equal(3500, core.Monitor.PollIntervalMs);
    }

    [Fact]
    public void CrossWiresTheFirewallAndAllowlist()
    {
        using var core = new SentinelCore(new AppSettings());

        Assert.Same(core.Allowlist, core.Firewall.Allowlist);
        Assert.NotNull(core.Monitor.IsIpAllowlisted);
    }

    [Fact]
    public void AllowlistLookupReachesTheAllowlistInstance()
    {
        using var core = new SentinelCore(new AppSettings());
        core.Allowlist.TryAddIp("203.0.113.9", out _);

        // Proves the delegate closes over this graph's allowlist, not a stray one.
        Assert.True(core.Monitor.IsIpAllowlisted!("203.0.113.9"));
        Assert.False(core.Monitor.IsIpAllowlisted!("203.0.113.10"));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(-5, false)]
    [InlineData(30, true)]
    public void ExpiryMinutesToSpan(int minutes, bool expectSpan)
    {
        var span = SentinelCore.ExpiryMinutesToSpan(minutes);
        Assert.Equal(expectSpan, span.HasValue);
        if (expectSpan)
            Assert.Equal(TimeSpan.FromMinutes(minutes), span!.Value);
    }

    [Fact]
    public void WiresThePeerEndpointShieldIntoPrevention()
    {
        using var core = new SentinelCore(new AppSettings());

        // Blocking a WireGuard peer's public endpoint kills that client's tunnel, so the
        // engine has to consult the monitor before auto-blocking. With no peers up this
        // simply never matches, which is why the assertion is on the wiring.
        Assert.NotNull(core.Prevention.IsProtectedAddress);
        Assert.False(core.Prevention.IsProtectedAddress!("203.0.113.99"));
    }

    [Fact]
    public void PassesSuricataAndWireGuardSettingsThrough()
    {
        var settings = new AppSettings
        {
            SuricataEnabled = false,
            SuricataMaxSeverity = 2,
            SuricataIgnoredSids = "2001219,2010935",
            WireGuardPeerMbPer10Min = 4096
        };
        using var core = new SentinelCore(settings);

        Assert.Equal(2, core.Monitor.SuricataMaxSeverity);
        Assert.Equal(new[] { 2001219L, 2010935L }, core.Monitor.SuricataIgnoredSids
            .Split(',').Select(long.Parse).OrderBy(x => x));
        Assert.Equal(4096, core.Monitor.WireGuardPeerMbPer10Min);
    }

    [Fact]
    public void PassesMonitorSettingsThrough()
    {
        var settings = new AppSettings
        {
            GeoLookupEnabled = false,
            ThreatIntelEnabled = false,
            HoneypotEnabled = true,
            HoneypotPorts = "2323, 5900",
            ExfilMbPer10Min = 512
        };
        using var core = new SentinelCore(settings);

        Assert.False(core.Monitor.GeoLookupsEnabled);
        Assert.False(core.Monitor.ThreatIntelEnabled);
        Assert.True(core.Monitor.HoneypotEnabled);
        Assert.Equal(new[] { 2323, 5900 }, core.Monitor.HoneypotPorts);
        Assert.Equal(512, core.Monitor.ExfilThresholdMb);
    }
}
