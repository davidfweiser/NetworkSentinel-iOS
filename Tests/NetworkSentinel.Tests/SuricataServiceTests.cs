using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Drives real EVE JSON lines through the parser. The threat-end resolution is the
/// part worth pinning: Suricata's src_ip is the packet source, which for an outbound
/// C2 callback is this machine — auto-blocking that would firewall the host off from
/// itself.
/// </summary>
public class SuricataServiceTests
{
    private static SuricataService Engine() => new() { MaxSeverity = 3 };

    private static string Alert(
        string srcIp, int srcPort, string destIp, int destPort,
        int severity = 1, long sid = 2001219, string signature = "ET TROJAN Observed C2 Domain")
        => $"{{\"timestamp\":\"2026-08-06T22:00:00.000000-0500\",\"event_type\":\"alert\"," +
           $"\"src_ip\":\"{srcIp}\",\"src_port\":{srcPort},\"dest_ip\":\"{destIp}\",\"dest_port\":{destPort}," +
           $"\"proto\":\"TCP\",\"alert\":{{\"signature\":\"{signature}\",\"category\":\"A Network Trojan was detected\"," +
           $"\"severity\":{severity},\"signature_id\":{sid},\"gid\":1,\"rev\":3}}}}";

    private static ThreatEvent Single(SuricataService svc, string line)
    {
        svc.ProcessLine(line, DateTime.Now);
        return Assert.Single(svc.DrainPending());
    }

    [Fact]
    public void OutboundAlertNamesTheRemoteEndNotThisMachine()
    {
        var svc = Engine();
        // Packet source is a LAN address (this machine); the threat is the far side.
        var threat = Single(svc, Alert("192.168.0.105", 51000, "203.0.113.40", 443));

        Assert.Equal("203.0.113.40", threat.SourceIp);
        Assert.Equal(ThreatType.SignatureMatch, threat.Type);
    }

    [Fact]
    public void InboundAlertNamesTheSource()
    {
        var svc = Engine();
        var threat = Single(svc, Alert("203.0.113.41", 40000, "192.168.0.105", 22));

        Assert.Equal("203.0.113.41", threat.SourceIp);
    }

    [Fact]
    public void OwnPublicAddressCountsAsLocal()
    {
        var svc = Engine();
        // Loopback stands in for "an address assigned to this host": on a VPS the
        // host's own address is public, and a private-range check alone made an
        // outbound alert name the host itself as the threat.
        var threat = Single(svc, Alert("127.0.0.1", 51001, "203.0.113.42", 443));

        Assert.Equal("203.0.113.42", threat.SourceIp);
    }

    [Fact]
    public void Severity1IsCritical()
    {
        var svc = Engine();
        Assert.Equal(ThreatLevel.Critical, Single(svc, Alert("203.0.113.43", 1, "192.168.0.105", 22, severity: 1)).Level);
    }

    [Fact]
    public void SeverityAboveTheCapIsDropped()
    {
        var svc = new SuricataService { MaxSeverity = 2 };
        svc.ProcessLine(Alert("203.0.113.44", 1, "192.168.0.105", 22, severity: 3), DateTime.Now);
        Assert.Empty(svc.DrainPending());
    }

    [Fact]
    public void MutedSidIsDropped()
    {
        var svc = Engine();
        svc.IgnoredSids = SuricataService.ParseSids("2001219, 2010935");
        svc.ProcessLine(Alert("203.0.113.45", 1, "192.168.0.105", 22, sid: 2001219), DateTime.Now);
        Assert.Empty(svc.DrainPending());
    }

    [Theory]
    [InlineData("event_type\":\"flow\"")]
    [InlineData("not json at all")]
    [InlineData("")]
    public void NonAlertLinesAreIgnored(string line)
    {
        var svc = Engine();
        svc.ProcessLine(line, DateTime.Now);
        Assert.Empty(svc.DrainPending());
    }

    [Fact]
    public void ParseSidsIgnoresJunkAndDeduplicates()
    {
        var sids = SuricataService.ParseSids(" 2001219, nonsense, 2001219 ,2010935, ");
        Assert.Equal(new[] { 2001219L, 2010935L }, sids.OrderBy(x => x));
    }

    [Fact]
    public void DefaultEvePathIsOneOfTheKnownLocations()
    {
        string[] known =
        [
            "/opt/homebrew/var/log/suricata/eve.json",
            "/usr/local/var/log/suricata/eve.json",
            "/var/log/suricata/eve.json"
        ];

        Assert.Contains(SuricataService.DefaultEvePath, known);

        // With no eve.json anywhere yet, the default must name a Homebrew prefix rather
        // than the inherited Linux path — Homebrew is the only practical install here.
        if (!known.Any(File.Exists))
            Assert.NotEqual("/var/log/suricata/eve.json", SuricataService.DefaultEvePath);
    }
}
