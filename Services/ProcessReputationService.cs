using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Reputation checks on the local processes behind network connections:
///
///  * shells / script interpreters holding an outbound connection to a public
///    address — the reverse-shell signature;
///  * binaries running from throwaway locations (/tmp, Downloads, /Users/Shared)
///    with network activity;
///  * unsigned binaries (codesign) or binaries still carrying the quarantine
///    xattr that talk to public addresses.
///
/// Path resolution uses proc_pidpath (libproc) — no shelling out per poll.
/// codesign / xattr run once per unique executable path on a background queue
/// and results are cached, so the poll loop never blocks on them.
/// </summary>
public sealed class ProcessReputationService
{
    [DllImport("libproc", EntryPoint = "proc_pidpath")]
    private static extern int proc_pidpath(int pid, byte[] buffer, uint bufferSize);

    private static readonly HashSet<string> ShellNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "zsh", "sh", "dash", "ksh", "csh", "tcsh", "fish",
        "python", "python3", "perl", "ruby", "php", "osascript",
        "nc", "ncat", "netcat", "socat", "telnet"
    };

    private static readonly string[] SuspiciousPathPrefixes =
    {
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"
    };

    /// <summary>Platform paths that are always Apple-signed — not worth a codesign run.</summary>
    private static readonly string[] TrustedPathPrefixes =
    {
        "/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/",
        "/System/Cryptexes/"
    };

    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(30);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, string> _pidPaths = new();
    private readonly ConcurrentDictionary<string, SignatureVerdict> _signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _signatureQueued = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _ownPid = Environment.ProcessId;
    private readonly string _downloadsPrefix;

    private enum SignatureVerdict { Pending, SignedClean, Unsigned, Quarantined }

    public ProcessReputationService()
    {
        _downloadsPrefix = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads") + "/";
    }

    /// <summary>
    /// Feed one poll's connection snapshot. Threats surface via <see cref="DrainPending"/>.
    /// Only outbound connections to public remotes are considered — inbound and
    /// LAN traffic is covered by the other heuristics.
    /// </summary>
    public void Observe(IReadOnlyList<NetworkConnection> snapshot, IReadOnlySet<int> listeningTcpPorts, DateTime now)
    {
        foreach (var c in snapshot)
        {
            if (c.ProcessId <= 0 || c.ProcessId == _ownPid) continue;
            if (c.State != TcpConnectionState.Established) continue;
            if (string.IsNullOrWhiteSpace(c.RemoteAddress)) continue;
            if (GeoIpService.IsNonPublic(c.RemoteAddress)) continue;
            if (GeoIpService.IsMulticastOrBroadcast(c.RemoteAddress)) continue;
            // Inbound sessions land on a listening port; those are someone else's doing.
            if (c.Protocol == "TCP" && listeningTcpPorts.Contains(c.LocalPort)) continue;

            var path = ResolvePath(c.ProcessId);
            var exeName = string.IsNullOrEmpty(path) ? c.ProcessName : Path.GetFileName(path);

            if (ShellNames.Contains(exeName))
            {
                Emit(now, $"shell|{exeName}|{c.RemoteAddress}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.High,
                    SourceIp = c.RemoteAddress,
                    Title = "Shell process with outbound connection",
                    Detail = $"{exeName} (PID {c.ProcessId}) holds an established connection to {c.RemoteAddress}:{c.RemotePort}. " +
                             "A shell or script interpreter talking to a public address is the classic reverse-shell signature. " +
                             "Legitimate uses exist (ssh wrappers, package scripts) — verify what launched it.",
                    Origin = "Origin resolving…",
                    Method = $"Process reputation · {exeName} → {c.RemoteAddress}:{c.RemotePort}"
                });
            }

            if (string.IsNullOrEmpty(path)) continue;

            if (IsSuspiciousPath(path))
            {
                Emit(now, $"path|{path}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.Medium,
                    SourceIp = c.RemoteAddress,
                    Title = "Network activity from a throwaway location",
                    Detail = $"{exeName} is running from {path} and talking to {c.RemoteAddress}:{c.RemotePort}. " +
                             "Malware often stages itself in temp or download folders before persisting.",
                    Origin = "Origin resolving…",
                    Method = "Process reputation · suspicious executable path"
                });
            }

            if (!IsTrustedPath(path))
            {
                var verdict = QueueOrGetSignature(path);
                if (verdict is SignatureVerdict.Unsigned or SignatureVerdict.Quarantined)
                {
                    var what = verdict == SignatureVerdict.Quarantined
                        ? "still carries the macOS quarantine flag (downloaded, never cleared by Gatekeeper)"
                        : "has no valid code signature";
                    Emit(now, $"sig|{path}", new ThreatEvent
                    {
                        Timestamp = now,
                        Type = ThreatType.SuspiciousProcess,
                        Level = ThreatLevel.Medium,
                        SourceIp = c.RemoteAddress,
                        Title = verdict == SignatureVerdict.Quarantined
                            ? "Quarantined binary with network activity"
                            : "Unsigned binary with network activity",
                        Detail = $"{exeName} ({path}) {what} and is talking to {c.RemoteAddress}:{c.RemotePort}.",
                        Origin = "Origin resolving…",
                        Method = "Process reputation · codesign / quarantine"
                    });
                }
            }
        }
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

    private void Emit(DateTime now, string key, ThreatEvent threat)
    {
        lock (_gate)
        {
            if (_lastEmit.TryGetValue(key, out var last) && now - last < EmitCooldown)
                return;
            _lastEmit[key] = now;
            _pending.Add(threat);

            if (_lastEmit.Count > 2000)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    private string ResolvePath(int pid)
    {
        if (_pidPaths.TryGetValue(pid, out var cached))
            return cached;

        string path = "";
        try
        {
            var buffer = new byte[4096];
            int len = proc_pidpath(pid, buffer, (uint)buffer.Length);
            if (len > 0)
                path = Encoding.UTF8.GetString(buffer, 0, len);
        }
        catch
        {
            // libproc unavailable / pid gone
        }

        // PIDs recycle; a short-lived cache is fine and avoids a syscall per poll.
        if (_pidPaths.Count > 4000) _pidPaths.Clear();
        _pidPaths[pid] = path;
        return path;
    }

    private bool IsSuspiciousPath(string path)
        => SuspiciousPathPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)) ||
           path.StartsWith(_downloadsPrefix, StringComparison.OrdinalIgnoreCase);

    private static bool IsTrustedPath(string path)
        => TrustedPathPrefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal));

    private SignatureVerdict QueueOrGetSignature(string path)
    {
        if (_signatures.TryGetValue(path, out var verdict))
            return verdict;

        if (_signatureQueued.TryAdd(path, 0))
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _signatures[path] = CheckSignature(path);
                }
                finally
                {
                    _signatureQueued.TryRemove(path, out _);
                }
            });
        }

        return SignatureVerdict.Pending;
    }

    private static SignatureVerdict CheckSignature(string path)
    {
        try
        {
            // Quarantine first — a signed-but-quarantined binary is still notable.
            if (RunQuiet("/usr/bin/xattr", "-p", "com.apple.quarantine", path) == 0)
                return SignatureVerdict.Quarantined;

            return RunQuiet("/usr/bin/codesign", "--verify", path) == 0
                ? SignatureVerdict.SignedClean
                : SignatureVerdict.Unsigned;
        }
        catch
        {
            // If the tools fail, stay quiet rather than false-positive.
            return SignatureVerdict.SignedClean;
        }
    }

    private static int RunQuiet(string file, params string[] args)
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
        if (p == null) return 1;
        p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        if (!p.WaitForExit(10_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
            return 1;
        }
        return p.ExitCode;
    }
}
