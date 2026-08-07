using NetworkSentinel.Native;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Parses `pfctl -s state` output. Orientation is the point: pfctl always prints the
/// local end on the left and flips the arrow rather than the operands, so a naive
/// left-is-source reading would name this machine as the source of inbound traffic.
/// </summary>
public class PfStateFlowTests
{
    private static NetworkFlow One(string line)
    {
        var flows = PfFlowEventSource.ParseStates(line);
        return Assert.Single(flows).Flow;
    }

    [Fact]
    public void OutboundFlowKeepsLocalAsSource()
    {
        var flow = One("all tcp 192.168.0.105:53456 -> 17.253.20.125:443       ESTABLISHED:ESTABLISHED");

        Assert.Equal("TCP", flow.Protocol);
        Assert.Equal("192.168.0.105", flow.SourceAddress);
        Assert.Equal(53456, flow.SourcePort);
        Assert.Equal("17.253.20.125", flow.DestinationAddress);
        Assert.Equal(443, flow.DestinationPort);
    }

    [Fact]
    public void InboundFlowMakesTheRemoteEndTheSource()
    {
        // pfctl prints local-first with a reversed arrow. Reading left-to-right would
        // make this machine the source of an inbound SSH attempt.
        var flow = One("en0 tcp 192.168.0.105:22 <- 203.0.113.5:40000          ESTABLISHED:ESTABLISHED");

        Assert.Equal("203.0.113.5", flow.SourceAddress);
        Assert.Equal(40000, flow.SourcePort);
        Assert.Equal("192.168.0.105", flow.DestinationAddress);
        Assert.Equal(22, flow.DestinationPort);
    }

    [Fact]
    public void UdpDnsQueryIsParsed()
    {
        // The whole reason this source exists: a UDP DNS query never shows up as a
        // socket-table connection.
        var flow = One("en0 udp 192.168.0.105:59674 -> 1.1.1.1:53               MULTIPLE:SINGLE");

        Assert.Equal("UDP", flow.Protocol);
        Assert.Equal(53, flow.DestinationPort);
        Assert.Equal("1.1.1.1", flow.DestinationAddress);
    }

    [Fact]
    public void NatParentheticalIsSkipped()
    {
        // "translated (original) -> dest": the translated address is what is on the wire.
        var flow = One("all tcp 10.0.0.5:51000 (192.168.0.105:51000) -> 93.184.216.34:443  ESTABLISHED:ESTABLISHED");

        Assert.Equal("10.0.0.5", flow.SourceAddress);
        Assert.Equal(51000, flow.SourcePort);
        Assert.Equal("93.184.216.34", flow.DestinationAddress);
    }

    [Fact]
    public void IPv6UsesBracketedPorts()
    {
        var flow = One("all tcp 2600:1700::5[53456] -> 2606:4700::1[443]        ESTABLISHED:ESTABLISHED");

        Assert.Equal("2600:1700::5", flow.SourceAddress);
        Assert.Equal(53456, flow.SourcePort);
        Assert.Equal("2606:4700::1", flow.DestinationAddress);
        Assert.Equal(443, flow.DestinationPort);
    }

    [Fact]
    public void IPv6InboundFlips()
    {
        var flow = One("en0 udp 2600:1700::5[53] <- 2606:4700::1[40000]         MULTIPLE:MULTIPLE");

        Assert.Equal("2606:4700::1", flow.SourceAddress);
        Assert.Equal("2600:1700::5", flow.DestinationAddress);
        Assert.Equal(53, flow.DestinationPort);
    }

    [Theory]
    [InlineData("all icmp 192.168.0.105:8 -> 1.1.1.1:8   0:0")]           // not TCP/UDP
    [InlineData("")]
    [InlineData("no state")]
    [InlineData("all tcp 192.168.0.105:53456")]                            // truncated
    [InlineData("garbage garbage garbage garbage garbage")]
    public void UnusableLinesAreSkipped(string line)
        => Assert.Empty(PfFlowEventSource.ParseStates(line));

    [Fact]
    public void ParsesAMultiLineDumpAndKeysEachFlowDistinctly()
    {
        var dump = string.Join("\n",
            "all tcp 192.168.0.105:53456 -> 17.253.20.125:443       ESTABLISHED:ESTABLISHED",
            "en0 udp 192.168.0.105:59674 -> 1.1.1.1:53               MULTIPLE:SINGLE",
            "en0 tcp 192.168.0.105:22 <- 203.0.113.5:40000          ESTABLISHED:ESTABLISHED",
            "all icmp 192.168.0.105:8 -> 1.1.1.1:8                  0:0");

        var flows = PfFlowEventSource.ParseStates(dump);

        Assert.Equal(3, flows.Count);
        Assert.Equal(3, flows.Select(f => f.Key).Distinct().Count());
    }

    [Fact]
    public void SameFlowYieldsAStableKey()
    {
        const string line = "all tcp 192.168.0.105:53456 -> 17.253.20.125:443       ESTABLISHED:ESTABLISHED";
        // Keys are what tell a new flow from one already seen, so identical input must
        // never look like fresh activity.
        Assert.Equal(PfFlowEventSource.ParseStates(line)[0].Key, PfFlowEventSource.ParseStates(line)[0].Key);
    }

    [Theory]
    [InlineData("192.168.0.1:53", "192.168.0.1", 53)]
    [InlineData("2606:4700::1[443]", "2606:4700::1", 443)]
    [InlineData("(192.168.0.1:53)", "192.168.0.1", 53)]
    public void EndpointFormsParse(string field, string expectedIp, int expectedPort)
    {
        Assert.True(PfFlowEventSource.TryParseEndpoint(field, out var ip, out var port));
        Assert.Equal(expectedIp, ip);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData("")]
    [InlineData("192.168.0.1")]          // no port
    [InlineData("2606:4700::1")]         // bare IPv6, no bracketed port
    [InlineData("192.168.0.1:")]
    [InlineData("192.168.0.1:99999")]    // out of range
    public void BadEndpointsAreRejected(string field)
        => Assert.False(PfFlowEventSource.TryParseEndpoint(field, out _, out _));

    [Theory]
    [InlineData("pfctl: pf not enabled", "PF is disabled")]
    [InlineData("sudo: a password is required", "need root")]
    public void FailureMessagesAreActionable(string stderr, string expectedFragment)
        => Assert.Contains(expectedFragment, PfFlowEventSource.DescribeFailure(stderr, root: false));

    [Fact]
    public void DisabledPfIsRecognisedEvenOnAZeroExit()
        => Assert.True(PfFlowEventSource.LooksLikeNoState("pfctl: pf not enabled"));
}
