using System.Diagnostics;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Sends OS desktop notifications for Critical threats so the user is warned even
/// when the window is minimized or hidden behind other apps. macOS only for now
/// (osascript, or terminal-notifier when installed); other platforms report
/// unavailable via StatusText.
/// </summary>
public sealed class DesktopNotifier
{
    /// <summary>Same source+type is not re-announced within this window.</summary>
    private static readonly TimeSpan RepeatAfter = TimeSpan.FromMinutes(5);

    private const string OsaScriptPath = "/usr/bin/osascript";

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _lastSent = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _channel;

    public DesktopNotifier()
    {
        // terminal-notifier when present (its own bundle id means a real app icon
        // and a clickable notification); otherwise osascript, which ships with
        // every macOS install and needs nothing extra.
        _channel = !OperatingSystem.IsMacOS() ? null
            : ToolExists("terminal-notifier") ? "terminal-notifier"
            : File.Exists(OsaScriptPath) ? "osascript"
            : null;
    }

    public bool IsAvailable => _channel is not null;

    public string StatusText => _channel switch
    {
        "terminal-notifier" => "Desktop notifications ready (terminal-notifier).",
        "osascript" =>
            "Desktop notifications ready (osascript). They are delivered by macOS under " +
            "“Script Editor” — if nothing appears, allow that app in " +
            "System Settings ▸ Notifications.",
        _ => OperatingSystem.IsMacOS()
            ? "No notification tool found — /usr/bin/osascript is missing."
            : "Desktop notifications are only supported on macOS for now."
    };

    /// <summary>One aggregated notification per batch of Critical threats.</summary>
    public void NotifyCritical(IReadOnlyList<ThreatEvent> threats)
    {
        if (_channel is null || threats.Count == 0)
            return;

        var fresh = new List<ThreatEvent>();
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            foreach (var threat in threats)
            {
                var key = $"{threat.SourceIp}|{threat.Type}";
                if (_lastSent.TryGetValue(key, out var last) && now - last < RepeatAfter)
                    continue;
                _lastSent[key] = now;
                fresh.Add(threat);
            }

            if (_lastSent.Count > 512)
            {
                foreach (var stale in _lastSent.Where(kv => now - kv.Value > RepeatAfter)
                             .Select(kv => kv.Key).ToList())
                    _lastSent.Remove(stale);
            }
        }

        if (fresh.Count == 0)
            return;

        var title = fresh.Count == 1
            ? $"Critical threat: {fresh[0].TypeText}"
            : $"{fresh.Count} critical threats detected";
        var body = string.Join("\n", fresh.Take(4).Select(t =>
            string.IsNullOrEmpty(t.SourceIp) ? t.Title : $"{t.Title} — {t.SourceIp}"));
        if (fresh.Count > 4)
            body += $"\n…and {fresh.Count - 4} more";

        try
        {
            var psi = new ProcessStartInfo
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            if (_channel == "terminal-notifier")
            {
                psi.FileName = "terminal-notifier";
                psi.ArgumentList.Add("-title"); psi.ArgumentList.Add(title);
                psi.ArgumentList.Add("-subtitle"); psi.ArgumentList.Add("Network Sentinel");
                psi.ArgumentList.Add("-message"); psi.ArgumentList.Add(body);
                psi.ArgumentList.Add("-sound"); psi.ArgumentList.Add("Basso");
                // Coalesce so a burst replaces the previous banner instead of stacking.
                psi.ArgumentList.Add("-group"); psi.ArgumentList.Add("ns-critical");
            }
            else
            {
                // Pass the text as argv rather than interpolating it into the script:
                // AppleScript string literals would otherwise need quote/backslash
                // escaping, and threat titles are attacker-influenced.
                psi.FileName = OsaScriptPath;
                psi.ArgumentList.Add("-e"); psi.ArgumentList.Add("on run argv");
                psi.ArgumentList.Add("-e");
                psi.ArgumentList.Add(
                    "display notification (item 1 of argv) with title (item 2 of argv) " +
                    "subtitle (item 3 of argv) sound name \"Basso\"");
                psi.ArgumentList.Add("-e"); psi.ArgumentList.Add("end run");
                psi.ArgumentList.Add("--");
                psi.ArgumentList.Add(body);
                psi.ArgumentList.Add(title);
                psi.ArgumentList.Add("Network Sentinel");
            }
            using var p = Process.Start(psi);
            p?.WaitForExit(3000);
        }
        catch
        {
            // Notifications are best-effort; never let them break monitoring.
        }
    }

    private static bool ToolExists(string name)
    {
        try
        {
            var psi = new ProcessStartInfo("which", name)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(2000);
            return p is { ExitCode: 0 };
        }
        catch
        {
            return false;
        }
    }
}
