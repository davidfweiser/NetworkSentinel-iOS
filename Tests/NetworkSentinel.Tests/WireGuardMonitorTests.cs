using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Parses real `wg show all dump` output. The security-relevant assertion is the last
/// one: a device line's field 1 is the interface PRIVATE key and a peer line's field 2
/// is the PRESHARED key, and neither may ever reach a peer object.
/// </summary>
public class WireGuardMonitorTests
{
    // Tab-separated, exactly as wg emits it. Device line: 5 fields. Peer lines: 9.
    private const string PrivateKey = "cGrivateKeyMustNeverAppearAnywhereInParsedOutput=";
    private const string PresharedKey = "cHresharedKeyMustNeverAppearAnywhereInParsedOut==";

    private static readonly string Dump = string.Join("\n",
        $"wg0\t{PrivateKey}\tuPublicKeyOfThisDeviceAAAAAAAAAAAAAAAAAAAAAA=\t51820\toff",
        $"wg0\tpEEr1PublicKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t{PresharedKey}\t203.0.113.60:51820\t10.8.0.2/32\t1780000000\t1048576\t2097152\toff",
        $"wg0\tpEEr2PublicKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff");

    [Fact]
    public void ParsesBothPeers()
    {
        var peers = WireGuardMonitor.ParseDump(Dump);
        Assert.Equal(2, peers.Count);
        Assert.All(peers, p => Assert.Equal("wg0", p.Interface));
    }

    [Fact]
    public void ReadsEndpointAndSplitsTheAddress()
    {
        var peer = WireGuardMonitor.ParseDump(Dump)[0];
        Assert.Equal("203.0.113.60:51820", peer.Endpoint);
        Assert.Equal("203.0.113.60", peer.EndpointIp);
        Assert.Equal("10.8.0.2/32", peer.AllowedIps);
    }

    [Fact]
    public void ReadsTransferCountersAndHandshake()
    {
        var peer = WireGuardMonitor.ParseDump(Dump)[0];
        Assert.Equal(1048576, peer.TransferRx);
        Assert.Equal(2097152, peer.TransferTx);
        Assert.NotNull(peer.LastHandshake);
    }

    [Fact]
    public void NeverConnectedPeerHasNoEndpointOrHandshake()
    {
        var peer = WireGuardMonitor.ParseDump(Dump)[1];
        // wg prints "(none)" rather than an empty field.
        Assert.Equal("", peer.EndpointIp);
        Assert.Null(peer.LastHandshake);
    }

    [Fact]
    public void NoKeyMaterialBeyondThePublicKeyIsEverParsed()
    {
        var peers = WireGuardMonitor.ParseDump(Dump);

        foreach (var peer in peers)
        {
            var all = string.Join("|",
                peer.Interface, peer.PublicKey, peer.Endpoint, peer.EndpointIp, peer.AllowedIps);

            Assert.DoesNotContain(PrivateKey, all);
            Assert.DoesNotContain(PresharedKey, all);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("wg0\ttoo\tfew\tfields")]
    public void MalformedInputYieldsNoPeers(string dump)
        => Assert.Empty(WireGuardMonitor.ParseDump(dump));
}
