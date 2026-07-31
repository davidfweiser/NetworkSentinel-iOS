using System.IO;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the macOS persistence locations attackers use right after a
/// successful intrusion: LaunchAgents and LaunchDaemons plists. A new plist
/// is how a payload survives reboot, so the alert fires on creation and
/// modification, with removal logged at Info level.
///
/// Purely event-driven (FileSystemWatcher) — no baseline scan, no elevation.
/// </summary>
public sealed class LaunchPersistenceWatcher : IDisposable
{
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromSeconds(10);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, (DateTime Time, ThreatLevel Level)> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = new();
    private volatile string _status = "Launch-item watch not started";

    /// <summary>Our own probe-log daemon plist — installed by this app, not an intrusion.</summary>
    private const string OwnDaemonPlist = "/Library/LaunchDaemons/com.networksentinel.probelog.plist";

    public string Status => _status;

    public void Start()
    {
        Stop();

        var dirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons"
        };

        var watching = new List<string>();
        lock (_gate)
        {
            foreach (var dir in dirs)
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;
                    var w = new FileSystemWatcher(dir, "*.plist")
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                        IncludeSubdirectories = false
                    };
                    w.Created += (_, e) => OnChange(e.FullPath, "created", ThreatLevel.High);
                    w.Changed += (_, e) => OnChange(e.FullPath, "modified", ThreatLevel.Medium);
                    w.Renamed += (_, e) => OnChange(e.FullPath, "created (renamed into place)", ThreatLevel.High);
                    w.Deleted += (_, e) => OnChange(e.FullPath, "removed", ThreatLevel.Info);
                    w.EnableRaisingEvents = true;
                    _watchers.Add(w);
                    watching.Add(dir);
                }
                catch
                {
                    // directory unwatchable — skip
                }
            }
        }

        _status = watching.Count > 0
            ? $"Watching {watching.Count} launch-item folders (LaunchAgents / LaunchDaemons)"
            : "Launch-item watch: no watchable folders found";
    }

    public void Stop()
    {
        lock (_gate)
        {
            foreach (var w in _watchers)
            {
                try { w.Dispose(); } catch { /* ignore */ }
            }
            _watchers.Clear();
        }
        _status = "Launch-item watch stopped";
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

    private void OnChange(string path, string action, ThreatLevel level)
    {
        if (string.Equals(path, OwnDaemonPlist, StringComparison.OrdinalIgnoreCase))
            return;

        var now = DateTime.Now;
        lock (_gate)
        {
            // One alert per file per window: a single save fires several
            // filesystem events (create + write + attrib). A higher-severity
            // event still breaks through so "created" isn't hidden by the
            // "modified" that raced ahead of it.
            if (_lastEmit.TryGetValue(path, out var last) &&
                now - last.Time < CoalesceWindow && level <= last.Level)
                return;
            _lastEmit[path] = (now, level);

            var scope = path.StartsWith("/Library/LaunchDaemons", StringComparison.OrdinalIgnoreCase)
                ? "a system daemon (runs as root at boot)"
                : path.StartsWith("/Library/LaunchAgents", StringComparison.OrdinalIgnoreCase)
                    ? "a login item for all users"
                    : "one of your login items";

            _pending.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.PersistenceChange,
                Level = level,
                SourceIp = "127.0.0.1",
                Title = $"Launch item {action}: {Path.GetFileName(path)}",
                Detail = $"{path} was {action} — {scope}. If you did not just install or update software, " +
                         "inspect this file: launch items are the standard way malware persists across reboots.",
                Origin = "This computer",
                Method = "LaunchAgents / LaunchDaemons folder watch"
            });

            if (_lastEmit.Count > 500)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value.Time > CoalesceWindow)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    public void Dispose() => Stop();
}
