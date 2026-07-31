using System.Diagnostics;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the ARP table for the standard LAN man-in-the-middle opener:
/// the default gateway's MAC address changing (ARP spoofing redirects the
/// gateway IP to the attacker's MAC), or another IP claiming the gateway's
/// MAC. Nothing connection-based can see this, so it gets its own poller.
///
/// Sources: `route -n get default` for the gateway IP, `arp -an` for the
/// table. Both run unprivileged.
/// </summary>
public sealed class ArpWatchService : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);

    // "? (192.168.0.1) at e:ea:14:1f:cd:f2 on en0 ifscope [ethernet]"
    private static readonly Regex ArpEntry = new(
        @"\((?<ip>[0-9.]+)\) at (?<mac>[0-9a-fA-F:]+) on (?<if>\S+)",
        RegexOptions.Compiled);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private string _gatewayIp = "";
    private string _gatewayMac = "";
    private volatile string _status = "ARP watch not started";

    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Watching ARP table / default gateway";
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }
        if (cts == null) return;
        cts.Cancel();
        try { _loop?.Wait(1000); } catch { /* ignore */ }
        cts.Dispose();
        _loop = null;
        _status = "ARP watch stopped";
    }

    public IReadOnlyList<ThreatEvent> DrainPending()
    {
        lock (_gate)
        {
            if (_pending.Count == 0) return Array.Empty<ThreatEvent>();
            var list = _pending.ToList();
            _pending.Clear();
            return list;
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                CheckOnce(DateTime.Now);
            }
            catch
            {
                // arp/route hiccup — try again next round
            }

            try { await Task.Delay(PollInterval, ct); }
            catch (TaskCanceledException) { break; }
        }
    }

    /// <summary>One ARP-table inspection; internal for tests / manual replay.</summary>
    internal void CheckOnce(DateTime now)
    {
        var gateway = ReadGatewayIp();
        if (string.IsNullOrEmpty(gateway))
        {
            _status = "ARP watch: no default gateway (offline?)";
            return;
        }

        var table = ReadArpTable();
        if (table.Count == 0) return;

        if (!table.TryGetValue(gateway, out var mac))
            return; // gateway not resolved yet

        lock (_gate)
        {
            if (_gatewayIp != gateway)
            {
                // New network (Wi-Fi change, VPN, DHCP move) — new baseline, not an attack.
                _gatewayIp = gateway;
                _gatewayMac = mac;
                _status = $"Watching gateway {gateway} ({mac})";
                return;
            }

            if (!string.Equals(_gatewayMac, mac, StringComparison.OrdinalIgnoreCase))
            {
                var old = _gatewayMac;
                _gatewayMac = mac;
                Emit(now, $"gwchange|{gateway}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.ArpSpoof,
                    Level = ThreatLevel.Critical,
                    SourceIp = gateway,
                    Title = "Gateway MAC address changed",
                    Detail = $"The default gateway {gateway} changed MAC address from {old} to {mac}. " +
                             "ARP spoofing redirects the gateway to an attacker's MAC to intercept your traffic. " +
                             "A replaced/rebooted router can also cause this — verify your network hardware.",
                    Origin = "Local network gateway",
                    Method = "ARP table watch (gateway MAC change)"
                });
            }

            // Another IP answering with the gateway's MAC. Routers legitimately
            // share a MAC across a couple of their own addresses, so this is High,
            // not Critical, and lists the twin.
            foreach (var (ip, otherMac) in table)
            {
                if (ip == gateway) continue;
                if (!string.Equals(otherMac, mac, StringComparison.OrdinalIgnoreCase)) continue;
                Emit(now, $"dup|{ip}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.ArpSpoof,
                    Level = ThreatLevel.High,
                    SourceIp = ip,
                    Title = "Duplicate gateway MAC on the LAN",
                    Detail = $"{ip} shares the gateway's MAC address ({mac}). Routers sometimes use one MAC for several of " +
                             "their own IPs, but this is also what a spoofed ARP table looks like mid-attack.",
                    Origin = "Local network",
                    Method = "ARP table watch (duplicate MAC)"
                });
            }
        }
    }

    private void Emit(DateTime now, string key, ThreatEvent threat)
    {
        if (_lastEmit.TryGetValue(key, out var last) && now - last < EmitCooldown)
            return;
        _lastEmit[key] = now;
        _pending.Add(threat);
    }

    private static string ReadGatewayIp()
    {
        var output = RunCapture("/sbin/route", "-n", "get", "default");
        if (output == null) return "";
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("gateway:", StringComparison.OrdinalIgnoreCase))
            {
                var value = trimmed["gateway:".Length..].Trim();
                return System.Net.IPAddress.TryParse(value, out var ip) ? ip.ToString() : "";
            }
        }
        return "";
    }

    private static Dictionary<string, string> ReadArpTable()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var output = RunCapture("/usr/sbin/arp", "-an");
        if (output == null) return result;

        foreach (Match m in ArpEntry.Matches(output))
        {
            var ip = m.Groups["ip"].Value;
            var mac = NormalizeMac(m.Groups["mac"].Value);
            if (mac.Length > 0)
                result[ip] = mac;
        }
        return result;
    }

    /// <summary>macOS prints MAC octets without zero padding ("e:ea:14:…"); normalize for comparison.</summary>
    internal static string NormalizeMac(string mac)
    {
        var parts = mac.Split(':');
        if (parts.Length != 6) return "";
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length is < 1 or > 2) return "";
            parts[i] = parts[i].PadLeft(2, '0').ToLowerInvariant();
        }
        return string.Join(':', parts);
    }

    private static string? RunCapture(string file, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(file)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(8000);
            return output;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => Stop();
}
