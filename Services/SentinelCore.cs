using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// The shared service graph: monitor, firewall, allowlist, settings — constructed,
/// cross-wired, and disposed in ONE place.
///
/// Each frontend (GUI, TUI, web console) used to build this graph itself with a
/// copied ~20-line block, and the copies drifted: only the GUI applied the
/// persisted poll interval, so the TUI and web console silently ran at the default
/// cadence no matter what was saved; only the TUI failed to dispose the allowlist;
/// and every new setting had to be wired three times to exist everywhere. The
/// frontends now own only what is genuinely theirs: event handlers, presentation,
/// and user interaction.
/// </summary>
public sealed class SentinelCore : IDisposable
{
    public AppSettings Settings { get; }
    public NetworkMonitorService Monitor { get; } = new();
    public FirewallService Firewall { get; } = new();
    public AllowlistService Allowlist { get; } = new();
    public PreventionService Prevention { get; }

    public SentinelCore(AppSettings? settings = null)
    {
        Settings = settings ?? AppSettings.Load();

        Prevention = new PreventionService(Firewall, Allowlist, Settings);
        // A persisted value outside the offered range (hand-edited settings.json)
        // must not silently arm auto-block at Low.
        if (Prevention.MinLevel is not (ThreatLevel.Medium or ThreatLevel.High or ThreatLevel.Critical))
            Prevention.MinLevel = ThreatLevel.High;

        Firewall.Allowlist = Allowlist;
        Firewall.AutoBlockExpiry = ExpiryMinutesToSpan(Settings.AutoBlockExpiryMinutes);
        Firewall.StartExpirySweep();

        Monitor.GeoLookupsEnabled = Settings.GeoLookupEnabled;
        Monitor.AuthMonitoringEnabled = Settings.AuthLogMonitorEnabled;
        Monitor.ProbeMonitoringEnabled = Settings.ProbeLogEnabled;
        Monitor.PollIntervalMs = Settings.MonitorPollMs;
        Monitor.ThreatIntelEnabled = Settings.ThreatIntelEnabled;
        Monitor.ProcessReputationEnabled = Settings.ProcessReputationEnabled;
        Monitor.NewListenerAlertsEnabled = Settings.NewListenerAlertsEnabled;
        Monitor.ArpWatchEnabled = Settings.ArpWatchEnabled;
        Monitor.LaunchWatchEnabled = Settings.LaunchItemWatchEnabled;
        Monitor.ExfilMonitorEnabled = Settings.ExfilMonitorEnabled;
        Monitor.ExfilThresholdMb = Settings.ExfilMbPer10Min;
        Monitor.HoneypotPorts = HoneypotService.ParsePorts(Settings.HoneypotPorts);
        Monitor.HoneypotEnabled = Settings.HoneypotEnabled;
        Monitor.WebhookUrl = Settings.WebhookUrl;
        Monitor.WebhookMinLevel = Settings.GetWebhookMinLevel();
        Monitor.IsIpAllowlisted = ip => Allowlist.IsAllowed(ip, out _);

        // Root can re-install the probe-log rule silently; unprivileged runs wait
        // for the user to authorize elevation instead of failing at startup.
        if (Settings.ProbeLogEnabled && Firewall.IsRoot)
            _ = Task.Run(() => Firewall.EnableProbeLogging());

        Allowlist.UseRemoteFeed = Settings.AllowlistUseRemoteFeed;
    }

    /// <summary>0 (and anything negative) means auto-block rules never expire.</summary>
    public static TimeSpan? ExpiryMinutesToSpan(int minutes)
        => minutes > 0 ? TimeSpan.FromMinutes(minutes) : null;

    public void Dispose()
    {
        Monitor.Dispose();
        Allowlist.Dispose();
    }
}
