using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the PF packet log for inbound TCP SYNs and turns probes aimed at
/// CLOSED ports into port-scan threat events.
///
/// This is the piece connection polling fundamentally cannot provide: a probe
/// to a closed port is answered with a RST by the kernel and never appears in
/// the socket table, so a classic nmap sweep is invisible to the snapshot
/// heuristics. With the PF log rule installed, every probe leaves a packet on
/// the pflog0 pseudo-interface and full scans are detected within seconds.
///
/// Reading pflog0 directly needs root (BPF access), and the GUI deliberately
/// runs as the normal user. So <see cref="FirewallService.EnableProbeLogging"/>
/// installs the PF rule and starts a detached privileged tcpdump that decodes
/// pflog0 into <see cref="FirewallService.ProbeLogPath"/>; this class only tails
/// that text file, which needs no elevation. When the rule/reader is not
/// installed the file simply never appears and <see cref="Status"/> says so.
/// </summary>
public sealed class ProbeLogMonitor : IDisposable
{
    private static readonly TimeSpan FastWindow = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);

    // tcpdump -e over DLT_PFLOG, e.g.
    // "22:01:02.123456 rule 3/0(match): pass in on en0: 203.0.113.7.54321 > 192.168.1.5.8080: Flags [S], seq 1, win 65535, length 0"
    // "Flags [S]" is a bare SYN; "[S.]" (SYN-ACK) is our own reply and must not count.
    private static readonly Regex ProbeLine = new(
        @"(?<src>[0-9a-fA-F:.]+)\.(?<sport>\d+)\s+>\s+(?<dst>[0-9a-fA-F:.]+)\.(?<dpt>\d+):\s+Flags \[S\]",
        RegexOptions.Compiled);

    private readonly object _gate = new();
    private readonly Dictionary<string, SourceActivity> _sources = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _pending = new();
    private HashSet<int> _listeningPorts = new();

    private CancellationTokenSource? _cts;
    private Task? _tailTask;
    private volatile string _status = "Probe log monitoring not started";

    /// <summary>Human-readable state of the PF log source.</summary>
    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
        }

        var ct = _cts!.Token;
        _tailTask = Task.Run(() => TailProbeLogAsync(ct));
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
        try { _tailTask?.Wait(1500); } catch { /* ignore */ }
        _tailTask = null;
        cts.Dispose();
        _status = "Probe log monitoring stopped";
    }

    /// <summary>Called each poll so probes can be classified open vs. closed against live listeners.</summary>
    public void SetListeningPorts(IReadOnlySet<int> ports)
    {
        lock (_gate)
        {
            _listeningPorts = new HashSet<int>(ports);
        }
    }

    /// <summary>Returns threats detected since the last drain (called from the monitor poll loop).</summary>
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

    /// <summary>
    /// Tails the decoded PF log. The privileged writer restarts tcpdump with a
    /// packet cap to bound the file, which truncates it — so a shrinking file is
    /// expected and means "seek back to the start", not an error.
    /// </summary>
    private async Task TailProbeLogAsync(CancellationToken ct)
    {
        var path = FirewallService.ProbeLogPath;
        try
        {
            // The writer is installed by EnableProbeLogging; it may not exist yet
            // (or at all, if the user declined the password prompt).
            var waited = 0;
            while (!File.Exists(path))
            {
                if (ct.IsCancellationRequested) return;
                if (waited == 0)
                    _status = "Waiting for the PF probe log — enable it in Settings (needs your Mac password).";
                await Task.Delay(2000, ct);
                waited += 2;
                if (waited >= 30)
                {
                    _status =
                        "PF probe log not present — closed-port scan detection is off. " +
                        "Re-run “Authorize firewall”, then re-enable it in Settings.";
                    // Keep waiting; the user may authorize later in the session.
                    waited = 1;
                }
            }

            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            stream.Seek(0, SeekOrigin.End);
            using var reader = new StreamReader(stream);

            // The log file surviving from a previous run proves nothing — the decoder
            // daemon can be gone while the file is still there, and tailing it would
            // report a detection that is not actually running.
            _status = FirewallService.IsProbeWriterRunning()
                ? "Watching PF probe log (pflog0)"
                : "PF probe log decoder is not running — toggle closed-port scan detection off and on to reinstall it.";

            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct);
                if (line == null)
                {
                    // The writer truncates on restart; reopen from the top when that happens.
                    if (!File.Exists(path))
                    {
                        _status = "PF probe log disappeared — closed-port scan detection stopped.";
                        return;
                    }
                    if (stream.Position > new FileInfo(path).Length)
                    {
                        stream.Seek(0, SeekOrigin.Begin);
                        reader.DiscardBufferedData();
                    }
                    await Task.Delay(1000, ct);
                    continue;
                }
                ProcessLine(line, DateTime.Now);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        catch (UnauthorizedAccessException)
        {
            _status = $"PF probe log not readable ({path}) — closed-port scan detection off.";
        }
        catch (Exception ex)
        {
            _status = $"PF probe log monitoring failed: {ex.Message}";
        }
    }

    /// <summary>Parses one decoded PF log line; internal for tests / manual replay.</summary>
    internal void ProcessLine(string line, DateTime now)
    {
        var m = ProbeLine.Match(line);
        if (!m.Success) return;

        var src = m.Groups["src"].Value;
        if (!IPAddress.TryParse(src, out _)) return;
        if (src is "127.0.0.1" or "::1") return;
        if (!int.TryParse(m.Groups["dpt"].Value, out var port)) return;

        lock (_gate)
        {
            // SYNs to LISTENING ports are already visible to the connection
            // heuristics; only closed-port probes are the new signal here.
            if (_listeningPorts.Contains(port)) return;

            if (!_sources.TryGetValue(src, out var activity))
            {
                activity = new SourceActivity();
                _sources[src] = activity;
            }

            activity.Probes.Enqueue((now, port));
            while (activity.Probes.Count > 0 && now - activity.Probes.Peek().Time > LongWindow)
                activity.Probes.Dequeue();

            Evaluate(src, activity, now);

            if (_sources.Count > 2000)
            {
                foreach (var stale in _sources
                             .Where(kv => kv.Value.Probes.Count == 0 ||
                                          now - kv.Value.Probes.Last().Time > LongWindow)
                             .Select(kv => kv.Key).ToList())
                {
                    _sources.Remove(stale);
                }
            }
        }
    }

    private void Evaluate(string src, SourceActivity activity, DateTime now)
    {
        var fastPorts = activity.Probes
            .Where(p => now - p.Time <= FastWindow)
            .Select(p => p.Port).Distinct().Count();
        var longPorts = activity.Probes.Select(p => p.Port).Distinct().Count();

        ThreatLevel? level = null;
        string title, method;
        if (fastPorts >= 8)
        {
            level = ThreatLevel.High;
            title = $"Port scan of closed ports ({fastPorts} ports in {FastWindow.TotalSeconds:0}s)";
            method = "SYNs to non-listening ports (PF log)";
        }
        else if (fastPorts >= 4)
        {
            level = ThreatLevel.Medium;
            title = $"Probing of closed ports ({fastPorts} ports in {FastWindow.TotalSeconds:0}s)";
            method = "SYNs to non-listening ports (PF log)";
        }
        else if (longPorts >= 16)
        {
            level = ThreatLevel.High;
            title = $"Slow scan of closed ports ({longPorts} ports in {LongWindow.TotalMinutes:0} min)";
            method = "Paced SYNs to non-listening ports (PF log)";
        }
        else if (longPorts >= 10)
        {
            level = ThreatLevel.Medium;
            title = $"Slow probing of closed ports ({longPorts} ports in {LongWindow.TotalMinutes:0} min)";
            method = "Paced SYNs to non-listening ports (PF log)";
        }
        else
        {
            return;
        }

        string emitKey = $"{src}|{level}";
        if (_lastEmit.TryGetValue(emitKey, out var last) && now - last < EmitCooldown)
            return;
        _lastEmit[emitKey] = now;
        if (_lastEmit.Count > 4000)
        {
            foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                         .Select(kv => kv.Key).ToList())
            {
                _lastEmit.Remove(stale);
            }
        }

        var samplePorts = string.Join(", ", activity.Probes.Select(p => p.Port).Distinct().OrderBy(p => p).Take(12));
        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.PortScan,
            Level = level.Value,
            SourceIp = src,
            Title = title,
            Detail = $"{src} sent TCP SYNs to ports this machine is NOT listening on (e.g. {samplePorts}). " +
                     "These probes never show up as connections — they were caught by the PF packet log.",
            Origin = "Origin resolving…",
            Method = method
        });
    }

    public void Dispose() => Stop();

    private sealed class SourceActivity
    {
        public Queue<(DateTime Time, int Port)> Probes { get; } = new();
    }
}
