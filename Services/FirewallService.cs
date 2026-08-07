using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Manages host firewall rules owned by Network Sentinel on macOS via PF
/// (<c>pfctl</c>) anchors. The GUI always runs as the normal user; privileged
/// commands are elevated per-call with <c>osascript</c> (admin password dialog)
/// or <c>sudo</c>.
/// </summary>
public sealed class FirewallService
{
    public const string RulePrefix = "NetworkSentinel";
    public const string PfAnchorName = "com.networksentinel";
    public const string ProbeLogRuleName = "NetworkSentinel-ProbeLog";

    /// <summary>
    /// Decoded PF log lines land here. pflog0 itself is only readable by root
    /// (BPF), so the privileged writer started by <see cref="EnableProbeLogging"/>
    /// decodes it to this world-readable text file and
    /// <see cref="ProbeLogMonitor"/> tails that as the normal user.
    /// </summary>
    public const string ProbeLogPath = "/var/log/networksentinel-probe.log";

    /// <summary>
    /// The decoder runs as a LaunchDaemon, not a backgrounded child. A `nohup … &amp;`
    /// started inside `do shell script … with administrator privileges` does not
    /// survive: osascript reaps the process group when the elevated shell exits, so
    /// the decoder died instantly and closed-port detection silently logged nothing.
    /// launchd is the only mechanism that keeps a root process alive here — and it
    /// restarts it (KeepAlive) and restores it after a reboot for free.
    /// </summary>
    private const string ProbeDaemonLabel = "com.networksentinel.probelog";

    private const string ProbeDaemonPlist = "/Library/LaunchDaemons/com.networksentinel.probelog.plist";
    private const string ProbeWriterPath = "/usr/local/libexec/networksentinel-probe-writer.sh";

    /// <summary>
    /// Cap on packets per tcpdump invocation. The writer loop restarts tcpdump
    /// afterwards, which truncates the log — that is what bounds the file size.
    /// ProbeLogMonitor detects the truncation and reseeks.
    /// </summary>
    private const int ProbePacketCap = 200_000;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public AllowlistService? Allowlist { get; set; }

    /// <summary>True when euid is root (GUI should normally not run as root).</summary>
    public bool IsRoot
    {
        get
        {
            try { return geteuid() == 0; }
            catch { return false; }
        }
    }

    /// <summary>True when firewall changes can be attempted (root or elevatable).</summary>
    public bool IsAdministrator => IsRoot || CanElevate;

    public bool CanElevate => true; // osascript admin dialog is always available on macOS GUI; sudo may work in TUI

    public string PrivilegeText
    {
        get
        {
            if (IsRoot)
                return "Running as root — PF rules can be applied directly.";
            return "Running as your user. Firewall changes will ask for your Mac password (osascript admin dialog or sudo).";
        }
    }

    /// <summary>
    /// Expiry applied to auto-created block rules (null = permanent). Manual
    /// blocks are always permanent; auto-block passes this through.
    /// </summary>
    public TimeSpan? AutoBlockExpiry { get; set; }

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null, bool overrideAllowlist = false, TimeSpan? expiresAfter = null)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        // Auto-block screens CGNAT out one gate earlier, so anything reaching here in
        // that range is a deliberate manual block.
        if (IsNeverBlockable(normalized))
            return FirewallOperationResult.Fail("Refusing to block private/local addresses (LAN, loopback, link-local).");

        if (!overrideAllowlist && Allowlist != null && Allowlist.IsAllowed(normalized, out var allowReason))
            return FirewallOperationResult.Fail($"Refusing to block allowlisted address {normalized} ({allowReason}).");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: true, reason, expiresAfter);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: false, reason, expiresAfter);
            ok &= r.Success;
            results.Add(r.Message);
        }

        return ok
            ? FirewallOperationResult.Ok($"Blocked {normalized} ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockIp(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        var inName = IpRuleName(normalized, true);
        var outName = IpRuleName(normalized, false);
        var r1 = RemoveRuleByName(inName);
        var r2 = RemoveRuleByName(outName);

        if (!r1.Success && !r2.Success)
            return FirewallOperationResult.Fail($"No Network Sentinel block rules found for {normalized}.");

        return FirewallOperationResult.Ok($"Unblocked {normalized}. Removed managed inbound/outbound rules when present.");
    }

    public FirewallOperationResult BlockPort(int port, string protocol, FirewallDirection direction = FirewallDirection.Inbound, string? reason = null)
    {
        if (port is < 1 or > 65535)
            return FirewallOperationResult.Fail("Port must be between 1 and 65535.");

        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (protocol is not ("TCP" or "UDP"))
            return FirewallOperationResult.Fail("Protocol must be TCP or UDP.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsurePortRule(port, protocol, isInbound: true, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsurePortRule(port, protocol, isInbound: false, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        return ok
            ? FirewallOperationResult.Ok($"Port {protocol}/{port} blocked ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockPort(int port, string protocol)
    {
        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        var r1 = RemoveRuleByName(PortRuleName(port, protocol, true));
        var r2 = RemoveRuleByName(PortRuleName(port, protocol, false));
        if (!r1.Success && !r2.Success)
            return FirewallOperationResult.Fail($"No managed port rules for {protocol}/{port}.");

        return FirewallOperationResult.Ok($"Removed managed rules for {protocol}/{port}.");
    }

    public FirewallOperationResult RemoveRule(string ruleName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Fail("Only Network Sentinel managed rules can be removed here.");

            if (!IsAdministrator)
                return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

            var name = ruleName.Trim();

            // Blocks are created as an -In/-Out pair. Removing only the clicked row left
            // the sibling active, so the IP stayed blocked and remove "didn't work".
            var siblings = new List<string> { name };
            if (name.EndsWith("-In", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-In".Length] + "-Out");
            else if (name.EndsWith("-Out", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-Out".Length] + "-In");

            // Drop both from the ledger first, then reload PF once — one password
            // prompt for the pair instead of one per sibling.
            var ledger = LoadLedger();
            var removed = siblings
                .Where(s => ledger.Any(r => string.Equals(r.Name, s, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (removed.Count == 0)
                return FirewallOperationResult.Fail($"No rule named “{name}”.");

            ledger.RemoveAll(r => removed.Contains(r.Name, StringComparer.OrdinalIgnoreCase));
            SaveLedger(ledger);

            var applied = ApplyPfFromLedger();
            if (!applied.Success)
                return FirewallOperationResult.Fail(applied.Message);

            return FirewallOperationResult.Ok(removed.Count > 1
                ? $"Removed inbound + outbound rules ({removed[0]} and its pair)."
                : $"Removed “{removed[0]}”.");
        }
        catch (Exception ex)
        {
            // Never let firewall backend failures tear down the web host process.
            return FirewallOperationResult.Fail($"Remove failed: {ex.Message}");
        }
    }

    /// <param name="skip">Rules to leave in place (kept for API parity with the Windows/Linux builds).</param>
    public FirewallOperationResult RemoveAllManagedRules(Func<FirewallRuleInfo, bool>? skip = null)
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        var rules = LoadLedger();
        var kept = skip == null
            ? new List<FirewallRuleInfo>()
            : rules.Where(skip).ToList();
        var removed = rules.Count - kept.Count;

        // Wiping the ledger also drops the probe-log rule from the anchor, so the
        // privileged decoder would otherwise keep running with nothing logging to it.
        var droppedProbeRule =
            rules.Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase)) &&
            !kept.Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase));

        SaveLedger(kept);

        var script = BuildApplyPfScript(out var buildError);
        if (script == null)
            return FirewallOperationResult.Fail(buildError);
        if (droppedProbeRule)
            script += "\n" + ProbeWriterStopScript();

        var applied = RunPrivilegedShell(script);
        if (!applied.Success)
            return applied;

        var msg = $"Removed {removed} Network Sentinel firewall rule(s).";
        if (kept.Count > 0)
            msg += $" Kept {kept.Count}.";
        return FirewallOperationResult.Ok(msg);
    }

    /// <summary>
    /// Best-effort IP from a managed rule name or remote field (for auto-block suppress after Remove).
    /// </summary>
    public static bool TryExtractIpFromManagedRule(string? ruleName, string? remoteAddresses, out string ip)
    {
        ip = "";
        if (!string.IsNullOrWhiteSpace(remoteAddresses) &&
            TryNormalizeIp(remoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault(), out ip, out _))
            return true;

        if (string.IsNullOrWhiteSpace(ruleName))
            return false;

        // NetworkSentinel-IP-1.2.3.4-In  or  NetworkSentinel-IP-2001_db8__1-Out
        var m = Regex.Match(ruleName.Trim(),
            @"^NetworkSentinel-IP-(.+)-(In|Out)$",
            RegexOptions.IgnoreCase);
        if (!m.Success)
            return false;

        var raw = m.Groups[1].Value.Replace('_', ':');
        return TryNormalizeIp(raw, out ip, out _);
    }

    public FirewallOperationResult UnblockAllowlistedAddresses()
    {
        if (Allowlist == null)
            return FirewallOperationResult.Fail("Allowlist is not available.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to remove firewall rules.");

        var rules = GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock).ToList();
        int removed = 0;
        var notes = new List<string>();

        foreach (var rule in rules)
        {
            var remote = rule.RemoteAddresses;
            if (string.IsNullOrWhiteSpace(remote)) continue;
            if (!Allowlist.IsAllowed(remote, out var why)) continue;

            if (RemoveRuleByName(rule.Name).Success)
            {
                removed++;
                notes.Add($"{remote} ({why})");
            }
        }

        if (removed == 0)
            return FirewallOperationResult.Ok("No allowlisted IPs were blocked by Network Sentinel rules.");

        return FirewallOperationResult.Ok(
            $"Restored {removed} allowlisted address(es): {string.Join("; ", notes.Take(12))}" +
            (notes.Count > 12 ? "…" : ""));
    }

    public IReadOnlyList<FirewallRuleInfo> GetManagedRules()
    {
        var ledger = LoadLedger();
        return ledger
            .OrderBy(r => r.Kind)
            .ThenBy(r => r.RemoteAddresses)
            .ThenBy(r => r.LocalPorts)
            .ThenBy(r => r.Direction)
            .ToList();
    }

    public bool IsIpBlocked(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out _))
            return false;

        return GetManagedRules().Any(r =>
            r.Kind == FirewallRuleKind.IpBlock && !r.IsExpired &&
            string.Equals(r.RemoteAddresses, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public HashSet<string> GetBlockedIps()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock && !r.IsExpired))
        {
            if (!string.IsNullOrWhiteSpace(rule.RemoteAddresses))
                set.Add(rule.RemoteAddresses);
        }
        return set;
    }

    /// <summary>
    /// Pre-authorize elevation with a no-op privileged command so the first real
    /// block does not surprise the user. Does NOT relaunch the GUI as root.
    /// </summary>
    public FirewallOperationResult AuthorizeElevation()
    {
        if (IsRoot)
            return FirewallOperationResult.Ok("Already running as root.");

        // Touch a harmless privileged read — triggers admin password once.
        var probe = RunPrivilegedShell("/sbin/pfctl -s info >/dev/null 2>&1; /sbin/pfctl -e 2>/dev/null; true");
        if (probe.Success)
        {
            // Ensure anchor is hooked for future rule loads.
            var hook = EnsureAnchorHooked();
            if (!hook.Success)
                return FirewallOperationResult.Fail(
                    "Password OK, but could not install PF anchor hook: " + hook.Message);

            return FirewallOperationResult.Ok(
                "Authorization OK. Firewall changes can proceed (you may be prompted again after a while).");
        }

        return FirewallOperationResult.Fail(
            "Elevation failed or was cancelled. " + probe.Message +
            "\n\nRun the app as your user and allow the Mac admin password dialog when blocking.");
    }

    [Obsolete("GUI must not restart as root. Use AuthorizeElevation() instead.")]
    public void RestartAsAdministrator()
    {
        var result = AuthorizeElevation();
        if (!result.Success)
            throw new InvalidOperationException(result.Message);
    }

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason, TimeSpan? expiresAfter = null)
    {
        var name = IpRuleName(ip, isInbound);
        var description = reason ?? $"Blocked by Network Sentinel at {DateTime.Now:u}";

        UpsertLedger(new FirewallRuleInfo
        {
            Name = name,
            Description = description,
            Enabled = true,
            IsBlock = true,
            Direction = isInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
            RemoteAddresses = ip,
            LocalPorts = "",
            Protocol = "Any",
            Kind = FirewallRuleKind.IpBlock,
            ExpiresUtc = expiresAfter.HasValue ? DateTime.UtcNow + expiresAfter.Value : null
        });

        var applied = ApplyPfFromLedger();
        return applied.Success
            ? FirewallOperationResult.Ok($"Rule “{name}” applied (PF).")
            : FirewallOperationResult.Fail($"Failed PF apply {name}: {applied.Message}");
    }

    private FirewallOperationResult EnsurePortRule(int port, string protocol, bool isInbound, string? reason)
    {
        var name = PortRuleName(port, protocol, isInbound);
        var description = reason ?? $"Port blocked by Network Sentinel at {DateTime.Now:u}";

        UpsertLedger(new FirewallRuleInfo
        {
            Name = name,
            Description = description,
            Enabled = true,
            IsBlock = true,
            Direction = isInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
            RemoteAddresses = "",
            LocalPorts = port.ToString(),
            Protocol = protocol.ToUpperInvariant(),
            Kind = FirewallRuleKind.PortBlock
        });

        var applied = ApplyPfFromLedger();
        return applied.Success
            ? FirewallOperationResult.Ok($"Rule “{name}” applied (PF).")
            : FirewallOperationResult.Fail($"Failed PF apply {name}: {applied.Message}");
    }

    private FirewallOperationResult RemoveRuleByName(string name)
    {
        var hadLedger = LoadLedger().Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        RemoveFromLedger(name);
        var applied = ApplyPfFromLedger();

        if (!hadLedger && applied.Success)
            return FirewallOperationResult.Fail($"No rule named “{name}”.");

        return applied.Success
            ? FirewallOperationResult.Ok($"Removed “{name}”.")
            : FirewallOperationResult.Fail(applied.Message);
    }

    /// <summary>
    /// Rebuilds the PF anchor ruleset from the JSON ledger and loads it.
    /// </summary>
    private FirewallOperationResult ApplyPfFromLedger()
    {
        var script = BuildApplyPfScript(out var error);
        if (script == null)
            return FirewallOperationResult.Fail(error);

        return RunPrivilegedShell(script);
    }

    /// <summary>
    /// Writes the anchor file from the ledger and returns ONE privileged script that
    /// hooks the anchor into pf.conf, enables PF, and loads the rules. Callers that
    /// need extra privileged work (see <see cref="EnableProbeLogging"/>) append to
    /// this script rather than making a second elevated call: every RunPrivilegedShell
    /// is its own osascript process and therefore its own password dialog, so an
    /// operation split across calls asked for the password repeatedly and answering
    /// only the first prompt looked exactly like authentication failing.
    /// Returns null and sets <paramref name="error"/> if the rules file cannot be written.
    /// </summary>
    private string? BuildApplyPfScript(out string error)
    {
        error = "";
        // Every apply already carries an elevation prompt, so expired rules are
        // dropped for free here — the ledger and the loaded ruleset stay in sync.
        PruneExpiredFromLedger();
        var rulesPath = UserPfRulesPath;
        try
        {
            File.WriteAllText(rulesPath, BuildPfRuleset(LoadLedger()));
        }
        catch (Exception ex)
        {
            error = $"Could not write PF rules file: {ex.Message}";
            return null;
        }

        var systemRules = $"/etc/pf.anchors/{PfAnchorName}";
        return AnchorHookScript() + "\n" +
               $"cp {ShellQuote(rulesPath)} {ShellQuote(systemRules)}\n" +
               $"chmod 644 {ShellQuote(systemRules)}\n" +
               $"/sbin/pfctl -e 2>/dev/null || true\n" +
               $"/sbin/pfctl -a {ShellQuote(PfAnchorName)} -f {ShellQuote(systemRules)}\n";
    }

    private static string BuildPfRuleset(IEnumerable<FirewallRuleInfo> rules)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Network Sentinel PF anchor — managed rules (do not edit by hand)");
        sb.AppendLine($"# Generated {DateTime.Now:u}");
        sb.AppendLine();

        foreach (var rule in rules.Where(r => r.Enabled && r.IsBlock && !r.IsExpired))
        {
            // Comment encodes rule name for remove-by-name and human debugging
            sb.AppendLine($"# {rule.Name}");
            if (rule.Kind == FirewallRuleKind.IpBlock && !string.IsNullOrWhiteSpace(rule.RemoteAddresses))
            {
                var ip = rule.RemoteAddresses.Trim();
                if (rule.Direction == FirewallDirection.Inbound)
                    sb.AppendLine($"block drop in quick from {ip} to any");
                else
                    sb.AppendLine($"block drop out quick from any to {ip}");
            }
            else if (rule.Kind == FirewallRuleKind.PortBlock &&
                     int.TryParse(rule.LocalPorts, out var port) &&
                     port is >= 1 and <= 65535)
            {
                var proto = (rule.Protocol ?? "tcp").Trim().ToLowerInvariant();
                if (proto is not ("tcp" or "udp"))
                    proto = "tcp";

                if (rule.Direction == FirewallDirection.Inbound)
                    sb.AppendLine($"block drop in quick proto {proto} from any to any port {port}");
                else
                    sb.AppendLine($"block drop out quick proto {proto} from any port {port} to any");
            }
            sb.AppendLine();
        }

        // Probe-log rule, deliberately LAST and deliberately not `quick`.
        //
        // macOS pfctl has no `match` keyword (it is a syntax error here), so the
        // only way to log without a verdict does not exist — the rule has to be a
        // pass. Two things keep that safe: every managed block above is
        // `block drop ... quick`, so a blocked peer short-circuits and never reaches
        // this rule; and `no state` means the pass applies to the SYN alone and
        // creates no state entry, so every other packet of the connection is
        // evaluated exactly as it was before. The net behaviour change is confined
        // to inbound TCP SYNs that nothing else in the ruleset blocked.
        if (rules.Any(r => r.Enabled && string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase)))
        {
            sb.AppendLine($"# {ProbeLogRuleName}");
            sb.AppendLine("pass in log proto tcp from any to any flags S/SA no state");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    // ── Closed-port scan detection (PF log) ──────────────────────────────

    /// <summary>
    /// Installs the PF SYN-log rule and starts the privileged decoder that turns
    /// pflog0 packets into <see cref="ProbeLogPath"/>. Probes to CLOSED ports are
    /// answered with a RST before they ever appear in the socket table, so
    /// connection polling cannot see them — this rule makes them visible.
    ///
    /// Rule load and decoder start happen in ONE elevated shell, so the user sees
    /// a single password dialog.
    /// </summary>
    public FirewallOperationResult EnableProbeLogging()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        UpsertLedger(new FirewallRuleInfo
        {
            Name = ProbeLogRuleName,
            Description = "Logs inbound TCP SYNs via PF so scans of closed ports are detectable",
            Enabled = true,
            IsBlock = false,
            Direction = FirewallDirection.Inbound,
            RemoteAddresses = "",
            LocalPorts = "",
            Protocol = "TCP",
            Kind = FirewallRuleKind.Other
        });

        var script = BuildApplyPfScript(out var error);
        if (script == null)
        {
            RemoveFromLedger(ProbeLogRuleName);
            return FirewallOperationResult.Fail(error);
        }

        var result = RunPrivilegedShell(script + "\n" + ProbeWriterStartScript());
        if (!result.Success)
        {
            // Do not leave the ledger claiming a detection that is not running.
            RemoveFromLedger(ProbeLogRuleName);
            return FirewallOperationResult.Fail($"Failed to enable probe logging: {result.Message}");
        }

        return FirewallOperationResult.Ok("Probe logging enabled (PF log rule + pflog0 decoder).");
    }

    public FirewallOperationResult DisableProbeLogging()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        RemoveFromLedger(ProbeLogRuleName);

        var script = BuildApplyPfScript(out var error);
        if (script == null)
            return FirewallOperationResult.Fail(error);

        var result = RunPrivilegedShell(script + "\n" + ProbeWriterStopScript());
        return result.Success
            ? FirewallOperationResult.Ok("Probe logging disabled.")
            : result;
    }

    public bool IsProbeLoggingInstalled()
        => GetManagedRules().Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Privileged fragment that creates pflog0 and installs + loads the decoder
    /// LaunchDaemon. tcpdump exits after <see cref="ProbePacketCap"/> packets and the
    /// wrapper loop restarts it against a truncated file, which is what bounds the log
    /// size — ProbeLogMonitor treats the shrink as "reseek", not an error.
    /// </summary>
    private static string ProbeWriterStartScript()
    {
        // Both the loop and the plist go into files via QUOTED heredocs so their
        // bodies pass through verbatim — nesting a multi-line loop or XML inside
        // `sh -c '...'` inside AppleScript is exactly what breaks the elevation call.
        //
        // No BPF filter on the tcpdump, on purpose. The PF rule already logs nothing
        // but inbound bare SYNs, so a `tcp[tcpflags]` filter would be redundant — and
        // it compiles to an AF_INET-only test against DLT_PFLOG, which would silently
        // drop every IPv6 probe. ProbeLogMonitor re-checks "Flags [S]" when it parses,
        // which covers both families.
        return $"""
            {ProbeWriterStopScript()}
            /sbin/ifconfig pflog0 create 2>/dev/null || true
            /sbin/ifconfig pflog0 up 2>/dev/null || true
            : > {ProbeLogPath}
            chmod 644 {ProbeLogPath}
            mkdir -p /usr/local/libexec
            cat > {ProbeWriterPath} <<'NSPROBEEOF'
            #!/bin/sh
            while :; do
              /usr/sbin/tcpdump -n -e -l -i pflog0 -c {ProbePacketCap} > {ProbeLogPath} 2>/dev/null
              sleep 1
            done
            NSPROBEEOF
            chown root:wheel {ProbeWriterPath}
            chmod 755 {ProbeWriterPath}
            cat > {ProbeDaemonPlist} <<'NSPLISTEOF'
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
            	<key>Label</key>
            	<string>{ProbeDaemonLabel}</string>
            	<key>ProgramArguments</key>
            	<array>
            		<string>{ProbeWriterPath}</string>
            	</array>
            	<key>RunAtLoad</key>
            	<true/>
            	<key>KeepAlive</key>
            	<true/>
            	<key>ProcessType</key>
            	<string>Background</string>
            </dict>
            </plist>
            NSPLISTEOF
            chown root:wheel {ProbeDaemonPlist}
            chmod 644 {ProbeDaemonPlist}
            # bootstrap is the modern API; fall back to load -w on older systems.
            launchctl bootstrap system {ProbeDaemonPlist} 2>/dev/null || launchctl load -w {ProbeDaemonPlist} 2>/dev/null || true
            """;
    }

    /// <summary>Privileged fragment that unloads the decoder daemon and removes its files.</summary>
    private static string ProbeWriterStopScript()
    {
        return $"""
            launchctl bootout system/{ProbeDaemonLabel} 2>/dev/null || launchctl unload -w {ProbeDaemonPlist} 2>/dev/null || true
            rm -f {ProbeDaemonPlist}
            pkill -f 'tcpdump -n -e -l -i pflog0' 2>/dev/null || true
            rm -f {ProbeWriterPath}
            """;
    }

    /// <summary>
    /// True when the privileged decoder daemon is actually loaded. The PF rule and the
    /// log file can both be present while the decoder is dead, in which case the app
    /// would tail an empty file forever and report a detection that is not running.
    /// </summary>
    public static bool IsProbeWriterRunning()
    {
        try
        {
            var psi = new ProcessStartInfo("/bin/launchctl")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("print");
            psi.ArgumentList.Add($"system/{ProbeDaemonLabel}");

            using var p = Process.Start(psi);
            if (p == null) return false;
            // Drain both pipes concurrently — `launchctl print` is verbose enough to
            // fill a pipe buffer, and a blocking stdout read would deadlock against it
            // while keeping the WaitForExit bound below from ever engaging.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(4000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return false;
            }
            try { Task.WaitAll(stdoutTask, stderrTask); } catch { /* pipes torn down */ }
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Ensures /etc/pf.conf references our anchor (with backup), once.
    /// </summary>
    private FirewallOperationResult EnsureAnchorHooked()
        => RunPrivilegedShell(AnchorHookScript());

    /// <summary>
    /// Idempotent shell fragment: create the anchor file if missing, append the
    /// pf.conf anchor lines if absent, enable and reload PF. Safe to run repeatedly
    /// and safe to concatenate ahead of other privileged commands.
    /// </summary>
    private static string AnchorHookScript()
    {
        var marker = $"anchor \"{PfAnchorName}\"";
        var loadLine = $"load anchor \"{PfAnchorName}\" from \"/etc/pf.anchors/{PfAnchorName}\"";
        var emptyRules = $"/etc/pf.anchors/{PfAnchorName}";

        return $"""
            set -e
            mkdir -p /etc/pf.anchors
            if [ ! -f {ShellQuote(emptyRules)} ]; then
              printf '%s\n' '# Network Sentinel anchor' > {ShellQuote(emptyRules)}
              chmod 644 {ShellQuote(emptyRules)}
            fi
            if [ -f /etc/pf.conf ] && ! grep -qF {ShellQuote(marker)} /etc/pf.conf 2>/dev/null; then
              cp /etc/pf.conf /etc/pf.conf.networksentinel.bak 2>/dev/null || true
              printf '\n# Network Sentinel\n%s\n%s\n' {ShellQuote(marker)} {ShellQuote(loadLine)} >> /etc/pf.conf
            fi
            /sbin/pfctl -e 2>/dev/null || true
            /sbin/pfctl -f /etc/pf.conf 2>/dev/null || true
            """;
    }

    private static string UserPfRulesPath
        => Path.Combine(AppPaths.DataDirectory, "pf-anchor.conf");

    // ── Block expiry ─────────────────────────────────────────────────────

    private Timer? _expiryTimer;

    /// <summary>
    /// Starts the background sweep that removes expired block rules. Removal
    /// needs root for pfctl, so the sweep only acts when it can elevate
    /// silently (running as root, or sudo credentials are cached); otherwise
    /// expired rules are cleaned up by the next user-triggered firewall
    /// change (see <see cref="BuildApplyPfScript"/>) — never by a surprise
    /// password dialog from a timer.
    /// </summary>
    public void StartExpirySweep()
    {
        _expiryTimer ??= new Timer(_ => TrySweepExpired(), null,
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    private void TrySweepExpired()
    {
        try
        {
            if (!LoadLedger().Any(r => r.IsExpired))
                return;
            if (!CanElevateSilently())
                return;

            // BuildApplyPfScript prunes the ledger; the silent shell reloads PF.
            var script = BuildApplyPfScript(out _);
            if (script != null)
                RunPrivilegedShell(script);
        }
        catch
        {
            // sweep is best-effort; the next manual firewall action cleans up
        }
    }

    private bool CanElevateSilently()
    {
        if (IsRoot) return true;
        try
        {
            return RunProcess("sudo", "-n", "/usr/bin/true").Success;
        }
        catch
        {
            return false;
        }
    }

    private static void PruneExpiredFromLedger()
    {
        var ledger = LoadLedger();
        if (ledger.RemoveAll(r => r.IsExpired) > 0)
            SaveLedger(ledger);
    }

    // ── Elevation ────────────────────────────────────────────────────────

    /// <summary>
    /// Runs a shell script elevated via osascript (GUI password) or sudo.
    /// Complex scripts are written to a temp file so AppleScript never has to
    /// embed nested shell quotes (which caused -2740 syntax errors).
    /// </summary>
    private static FirewallOperationResult RunPrivilegedShell(string shellScript)
    {
        if (geteuid() == 0)
            return RunProcess("/bin/bash", "-c", shellScript);

        // 1) sudo -n (cached / passwordless)
        if (CommandExists("sudo"))
        {
            var cached = RunProcess("sudo", "-n", "/bin/bash", "-c", shellScript);
            if (cached.Success)
                return cached;
        }

        // 2) osascript admin dialog — run bash against a temp script file.
        //    Inlining multi-line shell with nested quotes into `do shell script "..."`
        //    breaks AppleScript ("A identifier can't go after this \"\"" / -2740).
        string? tempPath = null;
        try
        {
            tempPath = Path.Combine(
                Path.GetTempPath(),
                $"networksentinel-pf-{Environment.ProcessId}-{Guid.NewGuid():N}.sh");
            var body = shellScript.Replace("\r\n", "\n").Replace('\r', '\n');
            if (!body.EndsWith('\n'))
                body += "\n";
            File.WriteAllText(tempPath, body);

            // Single-quoted path is safe for bash; only AS-escape the outer command.
            var shellCmd = $"/bin/bash {ShellQuote(tempPath)}";
            var asLiteral = shellCmd
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"");

            // The admin dialog waits on a human, so it gets the interactive allowance
            // rather than the 30s one used for non-interactive commands.
            var osa = RunProcessTimed(
                "osascript",
                InteractiveProcessTimeoutMs,
                "-e",
                $"do shell script \"{asLiteral}\" with administrator privileges");
            if (osa.Success)
                return osa;

            // 3) Interactive sudo when we have a TTY (TUI / Terminal) — also a human
            //    typing a password, so the same allowance applies.
            if (CommandExists("sudo") && !Console.IsInputRedirected)
                return RunProcessTimed("sudo", InteractiveProcessTimeoutMs, "/bin/bash", "-c", shellScript);

            return FirewallOperationResult.Fail(
                string.IsNullOrWhiteSpace(osa.Message)
                    ? "Need admin rights for firewall changes. Allow the password dialog, or run from Terminal with sudo."
                    : osa.Message);
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail(ex.Message);
        }
        finally
        {
            if (tempPath != null)
            {
                try { File.Delete(tempPath); }
                catch { /* ignore */ }
            }
        }
    }

    private static bool CommandExists(string name)
    {
        try
        {
            var result = RunProcess("/usr/bin/which", name);
            return result.Success;
        }
        catch
        {
            return false;
        }
    }

    private const int DefaultProcessTimeoutMs = 30_000;

    /// <summary>Paths that raise a password dialog include a human typing — allow minutes, not seconds.</summary>
    private const int InteractiveProcessTimeoutMs = 300_000;

    private static FirewallOperationResult RunProcess(string file, params string[] args)
        => RunProcessTimed(file, DefaultProcessTimeoutMs, args);

    private static FirewallOperationResult RunProcessTimed(string file, int timeoutMs, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            using var p = Process.Start(psi);
            if (p == null)
                return FirewallOperationResult.Fail($"Could not start {file}.");

            // Both pipes drained concurrently: reading stdout to EOF before touching
            // stderr deadlocks when the child fills the stderr buffer first — and the
            // blocked read meant the WaitForExit timeout below never engaged, so a
            // hung pfctl/osascript pinned the calling thread indefinitely.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return FirewallOperationResult.Fail($"{file} did not finish within {timeoutMs / 1000}s.");
            }

            string stdout = stdoutTask.GetAwaiter().GetResult();
            string stderr = stderrTask.GetAwaiter().GetResult();
            string combined = (stdout + "\n" + stderr).Trim();

            if (p.ExitCode == 0)
                return FirewallOperationResult.Ok(combined);

            // pfctl -e often returns non-zero when already enabled
            if (combined.Contains("pf enabled", StringComparison.OrdinalIgnoreCase) ||
                combined.Contains("already enabled", StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Ok(combined);

            return FirewallOperationResult.Fail(string.IsNullOrWhiteSpace(combined)
                ? $"{file} exit code {p.ExitCode}"
                : combined);
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail(ex.Message);
        }
    }

    // ── Rule ledger (JSON under Application Support) ─────────────────────

    private static string LedgerPath
        => Path.Combine(AppPaths.DataDirectory, "firewall-rules.json");

    private static List<FirewallRuleInfo> LoadLedger()
    {
        try
        {
            if (!File.Exists(LedgerPath)) return new List<FirewallRuleInfo>();
            var json = File.ReadAllText(LedgerPath);
            return JsonSerializer.Deserialize<List<FirewallRuleInfo>>(json, JsonOptions)
                   ?? new List<FirewallRuleInfo>();
        }
        catch
        {
            return new List<FirewallRuleInfo>();
        }
    }

    private static void SaveLedger(List<FirewallRuleInfo> rules)
    {
        try
        {
            AppPaths.WriteAtomic(LedgerPath, JsonSerializer.Serialize(rules, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    private static void UpsertLedger(FirewallRuleInfo rule)
    {
        var list = LoadLedger();
        list.RemoveAll(r => string.Equals(r.Name, rule.Name, StringComparison.OrdinalIgnoreCase));
        list.Add(rule);
        SaveLedger(list);
    }

    private static void RemoveFromLedger(string name)
    {
        var list = LoadLedger();
        list.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        SaveLedger(list);
    }

    public static string IpRuleName(string ip, bool inbound)
        => $"{RulePrefix}-IP-{Sanitize(ip)}-{(inbound ? "In" : "Out")}";

    public static string PortRuleName(int port, string protocol, bool inbound)
        => $"{RulePrefix}-Port-{protocol.ToUpperInvariant()}-{port}-{(inbound ? "In" : "Out")}";

    private static string Sanitize(string value)
        => Regex.Replace(value, @"[^A-Za-z0-9.\-_]", "_");

    private static string ShellQuote(string value)
    {
        if (string.IsNullOrEmpty(value)) return "''";
        return "'" + value.Replace("'", "'\\''") + "'";
    }

    public static bool TryNormalizeIp(string? ip, out string normalized, out string error)
    {
        normalized = "";
        error = "";
        if (string.IsNullOrWhiteSpace(ip))
        {
            error = "IP address is empty.";
            return false;
        }

        ip = ip.Trim();
        if (ip.StartsWith('['))
        {
            var end = ip.IndexOf(']');
            if (end > 1)
                ip = ip[1..end];
        }
        else if (ip.Contains(':') && IPAddress.TryParse(ip, out _) == false)
        {
            var idx = ip.LastIndexOf(':');
            if (idx > 0 && ip.Count(c => c == ':') == 1)
                ip = ip[..idx];
        }

        if (!IPAddress.TryParse(ip, out var address))
        {
            error = $"Invalid IP address: {ip}";
            return false;
        }

        // ::ffff:a.b.c.d is how dual-stack sockets report IPv4 peers — rules and
        // bookkeeping should use the IPv4 form so both spellings mean one address.
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        // Drop any IPv6 zone id (fe80::1%en0 parses fine but pfctl rejects it in a
        // rule, and two zone spellings of one address must compare equal).
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            address = new IPAddress(address.GetAddressBytes());

        normalized = address.ToString();
        return true;
    }

    public static bool IsPrivateOrLocal(string ip)
        => GeoIpService.IsNonPublic(ip);

    /// <summary>
    /// Addresses no rule may ever target, because dropping them breaks the machine's
    /// own connectivity: LAN, loopback, link-local, multicast/broadcast.
    ///
    /// Narrower than <see cref="IsPrivateOrLocal"/>, which also covers CGNAT and is
    /// the right gate for <em>automatic</em> blocking. Blocking a tunnel peer is a
    /// bad default, not an impossible request — a hostile tailnet peer brute-forcing
    /// SSH is a real case, and refusing it in the manual path too left the operator
    /// with no way to stop the attack from inside the app.
    /// </summary>
    public static bool IsNeverBlockable(string ip)
        => GeoIpService.IsNonPublic(ip) && !GeoIpService.IsCarrierGradeNat(ip);

    [DllImport("libc")]
    private static extern uint geteuid();
}

public enum FirewallDirection
{
    Inbound,
    Outbound,
    Both
}

public enum FirewallRuleKind
{
    IpBlock,
    PortBlock,
    Other
}

public sealed class FirewallRuleInfo
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; }
    public bool IsBlock { get; init; }
    public FirewallDirection Direction { get; init; }
    public string RemoteAddresses { get; init; } = "";
    public string LocalPorts { get; init; } = "";
    public string Protocol { get; init; } = "Any";
    public FirewallRuleKind Kind { get; init; }

    /// <summary>UTC time this rule stops applying (null = permanent). Set by auto-block expiry.</summary>
    public DateTime? ExpiresUtc { get; init; }

    public bool IsExpired => ExpiresUtc.HasValue && ExpiresUtc.Value <= DateTime.UtcNow;

    public string ExpiryText => ExpiresUtc.HasValue
        ? (IsExpired ? "Expired" : $"Expires {ExpiresUtc.Value.ToLocalTime():HH:mm}")
        : "Permanent";

    public string DirectionText => Direction.ToString();
    public string KindText => Kind switch
    {
        FirewallRuleKind.IpBlock => "IP block",
        FirewallRuleKind.PortBlock => "Port block",
        _ => "Rule"
    };
    /// <summary>Best-effort IP target for display (falls back to parsing the rule name).</summary>
    public string AddressText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(RemoteAddresses) && RemoteAddresses is not ("Any" or "*"))
                return RemoteAddresses;
            var ipMatch = Regex.Match(
                Name,
                @"^NetworkSentinel-IP-(.+)-(In|Out)$",
                RegexOptions.IgnoreCase);
            if (ipMatch.Success)
                return ipMatch.Groups[1].Value.Replace('_', ':');
            return "";
        }
    }

    public string TargetText => Kind == FirewallRuleKind.IpBlock
        ? (string.IsNullOrWhiteSpace(RemoteAddresses) ? "—" : RemoteAddresses)
        : $"{Protocol}/{LocalPorts}";
    public string EnabledText => Enabled ? "On" : "Off";
    public string ActionText => IsBlock ? "Block" : "Allow";
}

public sealed class FirewallOperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = "";

    public static FirewallOperationResult Ok(string message) => new() { Success = true, Message = message };
    public static FirewallOperationResult Fail(string message) => new() { Success = false, Message = message };
}
