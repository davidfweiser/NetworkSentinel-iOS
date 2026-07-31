using System.Diagnostics;
using System.Globalization;
using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>
/// Data-exfiltration heuristic. Samples per-connection byte counters with
/// <c>nettop</c> (which lsof cannot provide) and alerts when the outbound
/// volume to a single public host exceeds a threshold within a rolling
/// 10-minute window. Cloud sync and streaming stay quiet via the allowlist
/// hook and by skipping private/LAN destinations (NAS backups, AirDrop).
///
/// nettop reports cumulative bytes per connection, so each sample is diffed
/// against the previous one; the first sighting of a connection is baseline
/// only (its history predates monitoring and must not count).
/// </summary>
public sealed class ExfiltrationMonitor : IDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _lastSeenBytes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<(DateTime Time, long Bytes)>> _perIpWindow = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _perIpProcess = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private volatile string _status = "Exfiltration monitor not started";

    /// <summary>Megabytes of outbound traffic to one host in the window before alerting.</summary>
    public int ThresholdMb { get; set; } = 250;

    /// <summary>Optional allowlist hook — allowlisted destinations never alert.</summary>
    public Func<string, bool>? IsIpAllowlisted { get; set; }

    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Sampling per-connection byte counts (nettop)";
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
        try { _loop?.Wait(1500); } catch { /* ignore */ }
        cts.Dispose();
        _loop = null;
        _status = "Exfiltration monitor stopped";
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
                SampleOnce(DateTime.Now);
            }
            catch (Exception ex)
            {
                _status = $"Exfiltration monitor error: {ex.Message}";
            }

            try { await Task.Delay(SampleInterval, ct); }
            catch (TaskCanceledException) { break; }
        }
    }

    private void SampleOnce(DateTime now)
    {
        var output = RunNettop();
        if (output == null)
        {
            _status = "nettop unavailable — exfiltration monitoring off";
            return;
        }

        // Row shapes (CSV, trailing comma):
        //   Safari.652,143838,123443,          ← process context row
        //   tcp4 10.0.1.5:52034<->1.2.3.4:443,143838,123443,   ← connection row
        string currentProcess = "";
        var liveKeys = new HashSet<string>(StringComparer.Ordinal);

        lock (_gate)
        {
            foreach (var raw in output.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(',')) continue;

                var cols = line.Split(',');
                if (cols.Length < 3) continue;
                var name = cols[0];

                bool isConnection = name.StartsWith("tcp", StringComparison.Ordinal) ||
                                    name.StartsWith("udp", StringComparison.Ordinal);
                if (!isConnection)
                {
                    // "Safari.652" → "Safari"
                    var dot = name.LastIndexOf('.');
                    currentProcess = dot > 0 ? name[..dot] : name;
                    continue;
                }

                if (!long.TryParse(cols[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var bytesOut))
                    continue; // idle sockets report empty byte columns

                var arrow = name.IndexOf("<->", StringComparison.Ordinal);
                if (arrow < 0) continue;
                var remoteToken = name[(arrow + 3)..].Trim();
                if (remoteToken.Length == 0 || remoteToken[0] == '*') continue;
                if (!MacNetTable.TryParseHostPort(remoteToken, out var remoteIp, out _)) continue;
                if (remoteIp is "0.0.0.0" or "::" or "") continue;
                if (GeoIpService.IsNonPublic(remoteIp)) continue;
                if (GeoIpService.IsMulticastOrBroadcast(remoteIp)) continue;

                liveKeys.Add(name);

                long delta;
                if (_lastSeenBytes.TryGetValue(name, out var previous))
                {
                    // Counter went backwards → same local/remote pair, new connection.
                    delta = bytesOut >= previous ? bytesOut - previous : bytesOut;
                }
                else
                {
                    // First sighting: history predates monitoring — baseline only.
                    delta = 0;
                }
                _lastSeenBytes[name] = bytesOut;

                if (delta <= 0) continue;

                if (!_perIpWindow.TryGetValue(remoteIp, out var window))
                {
                    window = new Queue<(DateTime, long)>();
                    _perIpWindow[remoteIp] = window;
                }
                window.Enqueue((now, delta));
                if (!string.IsNullOrEmpty(currentProcess))
                    _perIpProcess[remoteIp] = currentProcess;
            }

            // Forget connections that no longer exist so keys don't grow forever.
            foreach (var gone in _lastSeenBytes.Keys.Where(k => !liveKeys.Contains(k)).ToList())
                _lastSeenBytes.Remove(gone);

            var thresholdBytes = (long)ThresholdMb * 1_000_000;
            foreach (var (ip, window) in _perIpWindow.ToList())
            {
                while (window.Count > 0 && now - window.Peek().Time > Window)
                    window.Dequeue();
                if (window.Count == 0)
                {
                    _perIpWindow.Remove(ip);
                    _perIpProcess.Remove(ip);
                    continue;
                }

                long total = window.Sum(x => x.Bytes);
                if (total < thresholdBytes) continue;
                if (IsIpAllowlisted?.Invoke(ip) == true) continue;
                if (_lastEmit.TryGetValue(ip, out var last) && now - last < EmitCooldown) continue;
                _lastEmit[ip] = now;

                var process = _perIpProcess.TryGetValue(ip, out var p) ? p : "unknown process";
                _pending.Add(new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.DataExfiltration,
                    Level = ThreatLevel.High,
                    SourceIp = ip,
                    Title = $"Large outbound transfer: {total / 1_000_000} MB in {Window.TotalMinutes:0} min",
                    Detail = $"This machine sent {total / 1_000_000} MB to {ip} within the last {Window.TotalMinutes:0} minutes " +
                             $"(process: {process}). Large sustained uploads to a host outside the allowlist can indicate data " +
                             "exfiltration — or a legitimate backup/sync you may want to allowlist.",
                    Origin = "Origin resolving…",
                    Method = "nettop per-connection byte counters"
                });
            }

            _status = $"Sampling nettop · tracking {_perIpWindow.Count} active remote hosts · threshold {ThresholdMb} MB / {Window.TotalMinutes:0} min";
        }
    }

    private static string? RunNettop()
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/nettop")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var a in new[] { "-x", "-L", "1", "-J", "bytes_in,bytes_out" })
                psi.ArgumentList.Add(a);

            using var p = Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(15_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return null;
            }
            return output.Length > 0 ? output : null;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => Stop();
}
