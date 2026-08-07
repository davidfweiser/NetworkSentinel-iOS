using NetworkSentinel.Models;
using Xunit;

namespace NetworkSentinel.Tests;

public class ConnectionIdentityTests
{
    private static NetworkConnection Conn(int pid, TcpConnectionState state = TcpConnectionState.Established)
        => new()
        {
            Protocol = "TCP",
            LocalAddress = "192.168.1.10",
            LocalPort = 51000,
            RemoteAddress = "93.184.216.34",
            RemotePort = 443,
            State = state,
            ProcessId = pid
        };

    [Fact]
    public void KeyIgnoresProcessId()
    {
        // A netstat-fallback poll reports pid 0 for every row. If that changed the key,
        // the monitor would see the whole table vanish and reappear.
        Assert.Equal(Conn(0).Key, Conn(4321).Key);
    }

    [Fact]
    public void KeyDistinguishesTheFourTuple()
    {
        var a = Conn(1);
        var b = new NetworkConnection
        {
            Protocol = "TCP",
            LocalAddress = "192.168.1.10",
            LocalPort = 51001,
            RemoteAddress = "93.184.216.34",
            RemotePort = 443,
            ProcessId = 1
        };

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void StateIsMutableAndRaisesChangeNotification()
    {
        var c = Conn(1, TcpConnectionState.SynSent);
        var changed = new List<string?>();
        c.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        c.State = TcpConnectionState.Established;

        // Frozen-at-first-seen state was the old behaviour; the UI needs the live value,
        // and StateText is what the tables actually bind to.
        Assert.Equal(TcpConnectionState.Established, c.State);
        Assert.Contains(nameof(NetworkConnection.State), changed);
        Assert.Contains(nameof(NetworkConnection.StateText), changed);
    }

    [Fact]
    public void SettingTheSameStateRaisesNothing()
    {
        var c = Conn(1, TcpConnectionState.Established);
        var changed = 0;
        c.PropertyChanged += (_, _) => changed++;

        c.State = TcpConnectionState.Established;

        Assert.Equal(0, changed);
    }
}
