using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The gate stack, exercised end to end through Apply in dry-run mode — every gate
/// runs and every decision is reported, but no PF rule is ever written, so this is
/// safe to run on a developer machine.
/// </summary>
public class PreventionGateTests
{
    private static PreventionService DryRunEngine(out AppSettings settings, out AllowlistService allowlist)
    {
        settings = new AppSettings();
        allowlist = new AllowlistService();
        return new PreventionService(new FirewallService(), allowlist, settings)
        {
            Enabled = true,
            DryRun = true,
            MinLevel = ThreatLevel.High
        };
    }

    private static ThreatEvent Threat(
        string ip,
        ThreatLevel level = ThreatLevel.High,
        ThreatType type = ThreatType.PortScan)
        => new() { SourceIp = ip, Level = level, Type = type, Title = "test" };

    [Fact]
    public void ActsOnAPublicHighSeverityThreat()
    {
        var engine = DryRunEngine(out _, out _);

        var result = engine.Apply(new[] { Threat("203.0.113.20") });

        var decision = Assert.Single(result.Decisions);
        Assert.Equal("203.0.113.20", decision.Ip);
        Assert.Equal(PreventionAction.Simulated, decision.Action);
        // Dry run writes nothing, so nothing should look like a rule change.
        Assert.False(result.RulesChanged);
    }

    [Theory]
    [InlineData("203.0.113.21", ThreatLevel.Medium, ThreatType.PortScan)]   // below MinLevel
    [InlineData("203.0.113.22", ThreatLevel.Critical, ThreatType.NewRemoteHost)] // informational
    [InlineData("192.168.1.44", ThreatLevel.Critical, ThreatType.PortScan)] // private
    [InlineData("100.64.0.5", ThreatLevel.Critical, ThreatType.PortScan)]   // CGNAT tunnel peer
    [InlineData("224.0.0.251", ThreatLevel.Critical, ThreatType.PortScan)]  // multicast
    [InlineData("not-an-ip", ThreatLevel.Critical, ThreatType.PortScan)]    // unparsable
    public void GatesRejectWhatShouldNeverBeAutoBlocked(string ip, ThreatLevel level, ThreatType type)
    {
        var engine = DryRunEngine(out _, out _);

        var result = engine.Apply(new[] { Threat(ip, level, type) });

        Assert.Empty(result.Decisions);
    }

    [Fact]
    public void NeverActsOnThisMachinesOwnAddress()
    {
        var engine = DryRunEngine(out _, out _);

        // Loopback is also private, so this asserts the own-address gate specifically:
        // on a VPS the host's own address is public and clears every earlier gate.
        Assert.True(LocalAddresses.IsOwnAddress("127.0.0.1"));
        Assert.Empty(engine.Apply(new[] { Threat("127.0.0.1", ThreatLevel.Critical) }).Decisions);
    }

    [Fact]
    public void AllowlistedAddressIsNeverActedOn()
    {
        var engine = DryRunEngine(out _, out var allowlist);
        allowlist.TryAddIp("203.0.113.23", out _);

        Assert.Empty(engine.Apply(new[] { Threat("203.0.113.23") }).Decisions);
    }

    [Fact]
    public void OperatorProtectionShieldsAnAddress()
    {
        var engine = DryRunEngine(out _, out _);
        engine.Protect("203.0.113.24");

        Assert.Empty(engine.Apply(new[] { Threat("203.0.113.24") }).Decisions);

        engine.Unprotect("203.0.113.24");
        Assert.Single(engine.Apply(new[] { Threat("203.0.113.24") }).Decisions);
    }

    [Fact]
    public void ExternallyProtectedAddressIsShielded()
    {
        var engine = DryRunEngine(out _, out _);
        // What the frontends wire to the WireGuard peer-endpoint check: blocking a
        // peer's endpoint kills that client's tunnel.
        engine.IsProtectedAddress = ip => ip == "203.0.113.25";

        Assert.Empty(engine.Apply(new[] { Threat("203.0.113.25") }).Decisions);
        Assert.Single(engine.Apply(new[] { Threat("203.0.113.26") }).Decisions);
    }

    [Fact]
    public void ManuallyReleasedAddressStaysReleased()
    {
        var engine = DryRunEngine(out _, out _);
        engine.NoteUnblocked("203.0.113.27");

        Assert.Empty(engine.Apply(new[] { Threat("203.0.113.27") }).Decisions);
    }

    [Fact]
    public void AlreadyBlockedAddressIsNotReBlocked()
    {
        var engine = DryRunEngine(out _, out _);
        engine.NoteBlocked("203.0.113.28");

        Assert.Empty(engine.Apply(new[] { Threat("203.0.113.28") }).Decisions);
    }

    [Fact]
    public void DryRunDoesNotConsumeTheRetrySlot()
    {
        var engine = DryRunEngine(out _, out _);

        // Watching a batch in dry run used to burn every address's ten-minute retry, so
        // switching blocking on left exactly the attackers you had just reviewed
        // un-blocked. Both passes must report.
        Assert.Single(engine.Apply(new[] { Threat("203.0.113.29") }).Decisions);
        Assert.Single(engine.Apply(new[] { Threat("203.0.113.29") }).Decisions);
    }

    [Fact]
    public void DisabledEngineDoesNothing()
    {
        var engine = DryRunEngine(out _, out _);
        engine.Enabled = false;

        Assert.Empty(engine.Apply(new[] { Threat("203.0.113.30") }).Decisions);
    }

    [Fact]
    public void DescribeReportsDryRun()
    {
        var engine = DryRunEngine(out _, out _);
        Assert.Contains("DRY RUN", engine.Describe());

        engine.DryRun = false;
        Assert.Contains("armed", engine.Describe());

        engine.Enabled = false;
        Assert.Equal("Auto-block OFF", engine.Describe());
    }

    [Theory]
    // What osascript actually returns when the admin password dialog is dismissed —
    // the common case on macOS, and different text from Linux's polkit messages.
    [InlineData("execution error: User canceled. (-128)")]
    [InlineData("Need admin rights for firewall changes. Allow the password dialog, or run from Terminal with sudo.")]
    [InlineData("No way to elevate to modify the host firewall.")]
    [InlineData("Elevation failed or was cancelled.")]
    [InlineData("sudo: a password is required")]
    [InlineData("Sorry, try again.")]
    public void RecognisesMacElevationFailures(string message)
        => Assert.True(PreventionService.LooksLikeElevationFailure(message));

    [Theory]
    [InlineData("pfctl: Syntax error in config file")]
    [InlineData("pfctl did not finish within 30s.")]
    [InlineData("")]
    public void DoesNotMistakeOtherFailuresForElevation(string message)
        => Assert.False(PreventionService.LooksLikeElevationFailure(message));
}
