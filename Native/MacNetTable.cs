using System.Diagnostics;
using System.Globalization;
using System.Net;
using NetworkSentinel.Models;

namespace NetworkSentinel.Native;

/// <summary>
/// Reads TCP/UDP tables on macOS via <c>lsof</c> (preferred, includes PIDs)
/// with <c>netstat</c> fallback. Replaces Linux /proc/net parsing.
/// </summary>
internal static class MacNetTable
{
    private static readonly Dictionary<string, TcpConnectionState> LsofStates = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CLOSED"] = TcpConnectionState.Closed,
        ["LISTEN"] = TcpConnectionState.Listen,
        ["SYN_SENT"] = TcpConnectionState.SynSent,
        ["SYN_RCVD"] = TcpConnectionState.SynReceived,
        ["SYN_RECEIVED"] = TcpConnectionState.SynReceived,
        ["ESTABLISHED"] = TcpConnectionState.Established,
        ["CLOSE_WAIT"] = TcpConnectionState.CloseWait,
        ["FIN_WAIT_1"] = TcpConnectionState.FinWait1,
        ["FIN_WAIT1"] = TcpConnectionState.FinWait1,
        ["CLOSING"] = TcpConnectionState.Closing,
        ["LAST_ACK"] = TcpConnectionState.LastAck,
        ["FIN_WAIT_2"] = TcpConnectionState.FinWait2,
        ["FIN_WAIT2"] = TcpConnectionState.FinWait2,
        ["TIME_WAIT"] = TcpConnectionState.TimeWait,
    };

    private static readonly Dictionary<string, TcpConnectionState> NetstatStates = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CLOSED"] = TcpConnectionState.Closed,
        ["LISTEN"] = TcpConnectionState.Listen,
        ["SYN_SENT"] = TcpConnectionState.SynSent,
        ["SYN_RCVD"] = TcpConnectionState.SynReceived,
        ["ESTABLISHED"] = TcpConnectionState.Established,
        ["CLOSE_WAIT"] = TcpConnectionState.CloseWait,
        ["FIN_WAIT_1"] = TcpConnectionState.FinWait1,
        ["CLOSING"] = TcpConnectionState.Closing,
        ["LAST_ACK"] = TcpConnectionState.LastAck,
        ["FIN_WAIT_2"] = TcpConnectionState.FinWait2,
        ["TIME_WAIT"] = TcpConnectionState.TimeWait,
    };

    public static IReadOnlyList<NetworkConnection> GetTcpConnections()
    {
        var fromLsof = ReadTcpViaLsof();
        if (fromLsof.Count > 0)
            return fromLsof;

        return ReadTcpViaNetstat();
    }

    public static (IReadOnlyList<ListeningPort> Listeners, IReadOnlyList<NetworkConnection> Connections) GetUdpTable()
    {
        var (listeners, connections) = ReadUdpViaLsof();
        if (listeners.Count > 0 || connections.Count > 0)
            return (listeners, connections);

        return (ReadUdpViaNetstat(), Array.Empty<NetworkConnection>());
    }

    private static List<NetworkConnection> ReadTcpViaLsof()
    {
        var result = new List<NetworkConnection>();
        // -nP: no DNS / numeric ports; -iTCP: TCP only; -F: machine-readable fields
        // p=pid, c=command, n=name, T=TCP info (ST=state)
        if (!TryRun("lsof", "-nP -iTCP -FpcnT", out var output))
            return result;

        int pid = 0;
        string? name = null;
        string? stateToken = null;

        void Flush()
        {
            if (string.IsNullOrEmpty(name))
            {
                name = null;
                stateToken = null;
                return;
            }

            if (!TryParseLsofName(name, out var localIp, out var localPort, out var remoteIp, out var remotePort, out var isListenOnly))
            {
                name = null;
                stateToken = null;
                return;
            }

            var state = TcpConnectionState.Closed;
            if (!string.IsNullOrEmpty(stateToken) && LsofStates.TryGetValue(stateToken, out var mapped))
                state = mapped;
            else if (isListenOnly || (remotePort == 0 && (remoteIp is "0.0.0.0" or "*" or "::" or "")))
                state = TcpConnectionState.Listen;

            if (state == TcpConnectionState.Listen)
            {
                remoteIp = "0.0.0.0";
                remotePort = 0;
            }

            result.Add(new NetworkConnection
            {
                Protocol = "TCP",
                LocalAddress = localIp,
                LocalPort = localPort,
                RemoteAddress = remoteIp,
                RemotePort = remotePort,
                State = state,
                ProcessId = pid
            });

            name = null;
            stateToken = null;
        }

        foreach (var raw in output.Split('\n'))
        {
            if (raw.Length == 0) continue;
            var code = raw[0];
            var value = raw.Length > 1 ? raw[1..] : "";

            switch (code)
            {
                case 'p':
                    Flush();
                    _ = int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out pid);
                    break;
                case 'c':
                    // command name ignored here; ProcessResolver fills display name
                    break;
                case 'n':
                    // Multiple NAME lines per process; flush previous NAME first
                    if (name != null)
                        Flush();
                    name = value;
                    break;
                case 'T':
                    // e.g. ST=ESTABLISHED or QR=0
                    if (value.StartsWith("ST=", StringComparison.OrdinalIgnoreCase))
                        stateToken = value[3..];
                    break;
            }
        }

        Flush();
        return DedupConnections(result);
    }

    private static (List<ListeningPort> Listeners, List<NetworkConnection> Connections) ReadUdpViaLsof()
    {
        var listeners = new List<ListeningPort>();
        var connections = new List<NetworkConnection>();
        if (!TryRun("lsof", "-nP -iUDP -Fpcn", out var output))
            return (listeners, connections);

        int pid = 0;
        foreach (var raw in output.Split('\n'))
        {
            if (raw.Length == 0) continue;
            var code = raw[0];
            var value = raw.Length > 1 ? raw[1..] : "";

            switch (code)
            {
                case 'p':
                    _ = int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out pid);
                    break;
                case 'n':
                    // UDP sockets: unbound/listening (local only, or "*" remote) or
                    // connected (local->remote with a real peer address).
                    if (!TryParseLsofName(value, out var localIp, out var localPort, out var remoteIp, out var remotePort, out _))
                        break;
                    if (localPort <= 0) break;

                    if (remotePort > 0 && remoteIp is not ("" or "0.0.0.0" or "*" or "::"))
                    {
                        connections.Add(new NetworkConnection
                        {
                            Protocol = "UDP",
                            LocalAddress = localIp,
                            LocalPort = localPort,
                            RemoteAddress = remoteIp,
                            RemotePort = remotePort,
                            State = TcpConnectionState.Established,
                            ProcessId = pid
                        });
                        break;
                    }

                    listeners.Add(new ListeningPort
                    {
                        Protocol = "UDP",
                        Address = localIp,
                        Port = localPort,
                        ProcessId = pid,
                        ServiceHint = PortCatalog.GetHint(localPort, "UDP")
                    });
                    break;
            }
        }

        return (DedupListeners(listeners), DedupConnections(connections));
    }

    private static List<NetworkConnection> ReadTcpViaNetstat()
    {
        var result = new List<NetworkConnection>();
        if (!TryRun("netstat", "-an -p tcp", out var output))
            return result;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("tcp", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            // Proto Recv-Q Send-Q Local Foreign (state)
            if (parts.Length < 5) continue;

            if (!TryParseNetstatEndpoint(parts[3], out var localIp, out var localPort))
                continue;
            if (!TryParseNetstatEndpoint(parts[4], out var remoteIp, out var remotePort))
                continue;

            var stateText = parts.Length >= 6 ? parts[5] : "CLOSED";
            var state = NetstatStates.TryGetValue(stateText, out var s) ? s : TcpConnectionState.Closed;
            if (state == TcpConnectionState.Listen)
            {
                remoteIp = "0.0.0.0";
                remotePort = 0;
            }

            result.Add(new NetworkConnection
            {
                Protocol = "TCP",
                LocalAddress = localIp,
                LocalPort = localPort,
                RemoteAddress = remoteIp,
                RemotePort = remotePort,
                State = state,
                ProcessId = 0
            });
        }

        return DedupConnections(result);
    }

    private static List<ListeningPort> ReadUdpViaNetstat()
    {
        var result = new List<ListeningPort>();
        if (!TryRun("netstat", "-an -p udp", out var output))
            return result;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("udp", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;

            if (!TryParseNetstatEndpoint(parts[3], out var localIp, out var localPort))
                continue;
            if (localPort <= 0) continue;

            result.Add(new ListeningPort
            {
                Protocol = "UDP",
                Address = localIp,
                Port = localPort,
                ProcessId = 0,
                ServiceHint = PortCatalog.GetHint(localPort, "UDP")
            });
        }

        return DedupListeners(result);
    }

    private static bool TryParseLsofName(
        string name,
        out string localIp,
        out int localPort,
        out string remoteIp,
        out int remotePort,
        out bool listenOnly)
    {
        localIp = remoteIp = "";
        localPort = remotePort = 0;
        listenOnly = false;

        // Forms:
        //   192.168.1.1:443->1.2.3.4:80
        //   *:22
        //   [::1]:8080
        //   127.0.0.1:53->127.0.0.1:5353
        name = name.Trim();
        var arrow = name.IndexOf("->", StringComparison.Ordinal);
        if (arrow > 0)
        {
            if (!TryParseHostPort(name[..arrow], out localIp, out localPort))
                return false;
            if (!TryParseHostPort(name[(arrow + 2)..], out remoteIp, out remotePort))
            {
                remoteIp = "0.0.0.0";
                remotePort = 0;
            }
            listenOnly = false;
            return true;
        }

        if (!TryParseHostPort(name, out localIp, out localPort))
            return false;
        remoteIp = "0.0.0.0";
        remotePort = 0;
        listenOnly = true;
        return true;
    }

    private static bool TryParseNetstatEndpoint(string token, out string ip, out int port)
        => TryParseHostPort(token, out ip, out port);

    internal static bool TryParseHostPort(string token, out string ip, out int port)
    {
        ip = "";
        port = 0;
        token = token.Trim();
        if (token is "*" or "*.*" or "*:*")
        {
            ip = "0.0.0.0";
            port = 0;
            return true;
        }

        // IPv6: [fe80::1]:80 or fe80::1.80 (netstat uses dots for port on some BSD)
        if (token.StartsWith('['))
        {
            var end = token.IndexOf(']');
            if (end < 1) return false;
            ip = token[1..end];
            var rest = token[(end + 1)..];
            if (rest.StartsWith(':') || rest.StartsWith('.'))
            {
                if (!int.TryParse(rest[1..], NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
                    return false;
            }
            return NormalizeIp(ref ip);
        }

        // netstat IPv6 often: 2600:1700:...:49466 — last segment is port after last .
        // Prefer last ':' for IPv4 host:port; for mixed use last '.' when many colons.
        var lastColon = token.LastIndexOf(':');
        var lastDot = token.LastIndexOf('.');
        var colonCount = 0;
        foreach (var ch in token)
            if (ch == ':') colonCount++;

        if (colonCount > 1 && lastDot > 0)
        {
            // BSD netstat IPv6: addr.port
            var addrPart = token[..lastDot];
            var portPart = token[(lastDot + 1)..];
            if (!int.TryParse(portPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
                return false;
            ip = addrPart == "*" ? "0.0.0.0" : addrPart;
            return NormalizeIp(ref ip);
        }

        if (lastColon > 0)
        {
            var addrPart = token[..lastColon];
            var portPart = token[(lastColon + 1)..];
            if (portPart == "*")
            {
                port = 0;
            }
            else if (!int.TryParse(portPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
            {
                return false;
            }

            ip = addrPart is "*" or "" ? "0.0.0.0" : addrPart;
            return NormalizeIp(ref ip);
        }

        // host only
        ip = token == "*" ? "0.0.0.0" : token;
        return NormalizeIp(ref ip);
    }

    private static bool NormalizeIp(ref string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || ip == "*")
        {
            ip = "0.0.0.0";
            return true;
        }

        // Strip zone id fe80::1%en0
        var pct = ip.IndexOf('%');
        if (pct > 0)
            ip = ip[..pct];

        if (IPAddress.TryParse(ip, out var addr))
        {
            ip = addr.ToString();
            return true;
        }

        // Leave as-is for odd netstat forms; still usable for display
        return !string.IsNullOrWhiteSpace(ip);
    }

    private static List<NetworkConnection> DedupConnections(List<NetworkConnection> list)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<NetworkConnection>(list.Count);
        foreach (var c in list)
        {
            var key = $"{c.Protocol}|{c.LocalAddress}:{c.LocalPort}|{c.RemoteAddress}:{c.RemotePort}|{c.State}|{c.ProcessId}";
            if (seen.Add(key))
                result.Add(c);
        }
        return result;
    }

    private static List<ListeningPort> DedupListeners(List<ListeningPort> list)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<ListeningPort>(list.Count);
        foreach (var p in list)
        {
            var key = $"{p.Protocol}|{p.Address}:{p.Port}|{p.ProcessId}";
            if (seen.Add(key))
                result.Add(p);
        }
        return result;
    }

    private static bool TryRun(string file, string args, out string output)
    {
        output = "";
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            // lsof warns about smbfs / Time Machine mounts — ignore stderr
            using var p = Process.Start(psi);
            if (p == null) return false;
            output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15000);
            return p.ExitCode == 0 || !string.IsNullOrWhiteSpace(output);
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// Facade used by NetworkMonitorService — macOS lsof/netstat implementation.
/// </summary>
internal static class IpHelper
{
    public static IReadOnlyList<NetworkConnection> GetTcpConnections()
        => MacNetTable.GetTcpConnections();

    public static (IReadOnlyList<ListeningPort> Listeners, IReadOnlyList<NetworkConnection> Connections) GetUdpTable()
        => MacNetTable.GetUdpTable();
}

internal static class PortCatalog
{
    private static readonly Dictionary<int, string> Map = new()
    {
        [20] = "FTP Data",
        [21] = "FTP",
        [22] = "SSH",
        [23] = "Telnet",
        [25] = "SMTP",
        [53] = "DNS",
        [80] = "HTTP",
        [110] = "POP3",
        [135] = "RPC / Epmap",
        [139] = "NetBIOS",
        [143] = "IMAP",
        [443] = "HTTPS",
        [445] = "SMB",
        [993] = "IMAPS",
        [995] = "POP3S",
        [1433] = "SQL Server",
        [1521] = "Oracle",
        [3306] = "MySQL",
        [3389] = "RDP",
        [5432] = "PostgreSQL",
        [5900] = "VNC",
        [5985] = "WinRM HTTP",
        [5986] = "WinRM HTTPS",
        [631] = "CUPS",
        [8080] = "HTTP Alt",
        [8443] = "HTTPS Alt"
    };

    public static readonly HashSet<int> SensitivePorts = new()
    {
        21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 631
    };

    public static string GetHint(int port, string protocol)
    {
        if (Map.TryGetValue(port, out var name))
            return name;
        return protocol == "UDP" ? "UDP service" : "Custom / unknown";
    }
}
