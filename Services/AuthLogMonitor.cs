using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches macOS authentication logging for failed remote logons (SSH, PAM,
/// Screen Sharing) and turns bursts into FailedLogonBurst threat events. This
/// closes the gap the connection-based heuristics cannot see: a brute-force
/// that reuses one TCP session, or paced attempts below the connection-rate
/// thresholds.
///
/// Source preference: `log stream` over the unified log, filtered by predicate
/// to the auth-relevant processes (sshd / sshd-session / sudo / su / login /
/// screensharingd); if `log` is unavailable, falls back to tailing
/// /var/log/system.log. macOS ships OpenSSH, so the sshd message wording is
/// the same as on Linux and the patterns below are shared verbatim.
///
/// Runs entirely without elevation. `log stream` is available to normal users,
/// but the unified log redacts some message arguments as &lt;private&gt; unless
/// private-data logging is enabled — when that hides the peer address we say so
/// in <see cref="Status"/> rather than silently reporting nothing.
/// </summary>
public sealed class AuthLogMonitor : IDisposable
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);
    private const int HighThreshold = 4;
    private const int CriticalThreshold = 10;

    /// <summary>Processes worth streaming; anything else is noise for this purpose.</summary>
    private const string LogPredicate =
        "process == \"sshd\" OR process == \"sshd-session\" OR process == \"sudo\" " +
        "OR process == \"su\" OR process == \"login\" OR process == \"screensharingd\"";

    // "Failed password for invalid user admin from 203.0.113.7 port 51022 ssh2"
    private static readonly Regex FailedPassword = new(
        @"Failed (?:password|publickey|keyboard-interactive(?:/pam)?|none) for (?<invalid>invalid user )?(?<user>\S+) from (?<ip>\S+) port \d+",
        RegexOptions.Compiled);

    // "Invalid user oracle from 203.0.113.7 port 40122"
    private static readonly Regex InvalidUser = new(
        @"Invalid user (?<user>\S*) from (?<ip>\S+)",
        RegexOptions.Compiled);

    // "Connection closed by invalid user a 203.0.113.7 port 50110 [preauth]"
    private static readonly Regex PreauthAbandon = new(
        @"Connection (?:closed|reset) by (?:invalid |authenticating )user (?<user>\S+) (?<ip>\S+) port \d+",
        RegexOptions.Compiled);

    // PAM: "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root"
    private static readonly Regex PamFailure = new(
        @"authentication failure;.*rhost=(?<ip>\S+)(?:\s+user=(?<user>\S+))?",
        RegexOptions.Compiled);

    // "error: maximum authentication attempts exceeded for root from 203.0.113.7 port 33990 ssh2"
    private static readonly Regex MaxAttempts = new(
        @"maximum authentication attempts exceeded for (?:invalid user )?(?<user>\S+) from (?<ip>\S+)",
        RegexOptions.Compiled);

    // Screen Sharing / ARD refuses a session: "Authentication failed for user david from 203.0.113.7"
    private static readonly Regex ScreenSharingFailure = new(
        @"Authentication (?:failed|denied)(?: for (?:user )?(?<user>\S+))? from (?<ip>\S+)",
        RegexOptions.Compiled);

    private readonly object _gate = new();
    private readonly Dictionary<string, IpFailures> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _pending = new();

    private Process? _logStream;
    private CancellationTokenSource? _cts;
    private Task? _tailTask;
    private volatile string _status = "Auth log monitoring not started";

    /// <summary>Counts redacted candidate lines so we can explain an empty result.</summary>
    private int _redactedLines;
    private int _matchedLines;

    /// <summary>Human-readable state of the log source (unified log, system.log, or why neither works).</summary>
    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
        }

        if (!TryStartLogStream())
        {
            var ct = _cts!.Token;
            _tailTask = Task.Run(() => TailSystemLogAsync(ct));
        }
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
        try { _logStream?.Kill(entireProcessTree: true); } catch { /* already gone */ }
        try { _tailTask?.Wait(1000); } catch { /* ignore */ }
        _logStream?.Dispose();
        _logStream = null;
        _tailTask = null;
        cts.Dispose();
        _status = "Auth log monitoring stopped";
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

    private bool TryStartLogStream()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/usr/bin/log",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            foreach (var arg in new[]
            {
                "stream", "--style", "syslog", "--level", "default", "--predicate", LogPredicate
            })
            {
                psi.ArgumentList.Add(arg);
            }

            var proc = Process.Start(psi);
            if (proc == null) return false;

            _logStream = proc;
            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) ProcessLine(e.Data, DateTime.Now);
            };
            proc.BeginOutputReadLine();
            _status = "Watching unified log (sshd/sudo/login/screensharingd)";
            return true;
        }
        catch
        {
            _logStream?.Dispose();
            _logStream = null;
            return false;
        }
    }

    private async Task TailSystemLogAsync(CancellationToken ct)
    {
        const string path = "/var/log/system.log";
        try
        {
            if (!File.Exists(path))
            {
                _status = "Auth log unavailable (no /usr/bin/log, no /var/log/system.log) — logon monitoring off";
                return;
            }

            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            stream.Seek(0, SeekOrigin.End);
            using var reader = new StreamReader(stream);
            _status = "Watching /var/log/system.log";

            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct);
                if (line == null)
                {
                    // At EOF; if the file was rotated under us, reopen from the top.
                    if (stream.Position > new FileInfo(path).Length)
                        stream.Seek(0, SeekOrigin.Begin);
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
            _status = "/var/log/system.log not readable by this user — logon monitoring off (needs an admin account)";
        }
        catch (Exception ex)
        {
            _status = $"Auth log monitoring failed: {ex.Message}";
        }
    }

    /// <summary>Parses one log line; internal for tests / manual replay.</summary>
    internal void ProcessLine(string line, DateTime now)
    {
        string? ip = null, user = null;
        bool immediate = false;

        var m = MaxAttempts.Match(line);
        if (m.Success)
        {
            ip = m.Groups["ip"].Value;
            user = m.Groups["user"].Value;
            immediate = true;
        }
        else if ((m = FailedPassword.Match(line)).Success ||
                 (m = PreauthAbandon.Match(line)).Success ||
                 (m = InvalidUser.Match(line)).Success ||
                 (m = ScreenSharingFailure.Match(line)).Success)
        {
            ip = m.Groups["ip"].Value;
            user = m.Groups["user"].Success ? m.Groups["user"].Value : "";
        }
        else if ((m = PamFailure.Match(line)).Success)
        {
            ip = m.Groups["ip"].Value;
            user = m.Groups["user"].Success ? m.Groups["user"].Value : "";
        }

        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out _))
        {
            // The unified log redacts message arguments as <private> unless private
            // data logging is enabled, which hides exactly the peer address we need.
            // Surface that instead of appearing to work while detecting nothing.
            if (ip != null && ip.Contains("<private>", StringComparison.Ordinal))
                NoteRedaction();
            return;
        }
        if (ip is "127.0.0.1" or "::1") return;

        lock (_gate)
        {
            _matchedLines++;

            if (!_failures.TryGetValue(ip, out var f))
            {
                f = new IpFailures();
                _failures[ip] = f;
            }

            f.Attempts.Enqueue(now);
            if (!string.IsNullOrWhiteSpace(user) && user != "from") f.Users.Add(user);
            while (f.Attempts.Count > 0 && now - f.Attempts.Peek() > Window)
                f.Attempts.Dequeue();

            var count = f.Attempts.Count;
            ThreatLevel? level = null;
            if (immediate || count >= CriticalThreshold) level = ThreatLevel.Critical;
            else if (count >= HighThreshold) level = ThreatLevel.High;
            if (level == null) return;

            // Per-IP cooldown, but let an escalation to Critical break through.
            string emitKey = $"{ip}|{level}";
            if (_lastEmit.TryGetValue(emitKey, out var last) && now - last < EmitCooldown)
                return;
            _lastEmit[emitKey] = now;

            var users = f.Users.Count > 0
                ? $" Accounts tried: {string.Join(", ", f.Users.Take(8))}{(f.Users.Count > 8 ? ", …" : "")}."
                : "";
            _pending.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.FailedLogonBurst,
                Level = level.Value,
                SourceIp = ip,
                Title = immediate
                    ? "SSH max auth attempts exceeded"
                    : $"{count} failed logons in {Window.TotalMinutes:0} min",
                Detail = $"{ip} produced {count} failed authentication attempts within {Window.TotalMinutes:0} minutes.{users}",
                Origin = "Origin resolving…",
                Method = "macOS unified log (sshd / PAM)"
            });

            // Keep the per-IP tables from growing without bound.
            if (_failures.Count > 2000)
            {
                foreach (var stale in _failures
                             .Where(kv => kv.Value.Attempts.Count == 0 ||
                                          now - kv.Value.Attempts.Last() > Window)
                             .Select(kv => kv.Key).ToList())
                {
                    _failures.Remove(stale);
                }
            }
            if (_lastEmit.Count > 4000)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    /// <summary>
    /// Called when a failed-logon line matched but its address was redacted.
    /// Only escalates to the status text once we have seen a run of them and
    /// never parsed a real address, so a single odd line stays quiet.
    /// </summary>
    private void NoteRedaction()
    {
        lock (_gate)
        {
            _redactedLines++;
            if (_redactedLines >= 5 && _matchedLines == 0)
            {
                _status =
                    "Watching unified log, but failed-logon addresses are redacted as <private> — " +
                    "install an Apple logging profile enabling private data for com.apple.sshd to see source IPs.";
            }
        }
    }

    public void Dispose() => Stop();

    private sealed class IpFailures
    {
        public Queue<DateTime> Attempts { get; } = new();
        public HashSet<string> Users { get; } = new(StringComparer.Ordinal);
    }
}
