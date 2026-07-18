using System.Diagnostics;
using System.Net;
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

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null, bool overrideAllowlist = false)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (IsPrivateOrLocal(normalized))
            return FirewallOperationResult.Fail("Refusing to block private/local addresses (LAN, loopback, link-local).");

        if (!overrideAllowlist && Allowlist != null && Allowlist.IsAllowed(normalized, out var allowReason))
            return FirewallOperationResult.Fail($"Refusing to block allowlisted address {normalized} ({allowReason}).");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: true, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: false, reason);
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
        if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
            return FirewallOperationResult.Fail("Only Network Sentinel managed rules can be removed here.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        return RemoveRuleByName(ruleName);
    }

    public FirewallOperationResult RemoveAllManagedRules()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate to modify the host firewall.");

        SaveLedger(new List<FirewallRuleInfo>());
        var applied = ApplyPfFromLedger();
        if (!applied.Success)
            return applied;

        return FirewallOperationResult.Ok("Removed all Network Sentinel firewall rule(s).");
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
            r.Kind == FirewallRuleKind.IpBlock &&
            string.Equals(r.RemoteAddresses, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public HashSet<string> GetBlockedIps()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock))
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

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason)
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
            Kind = FirewallRuleKind.IpBlock
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
        var hook = EnsureAnchorHooked();
        if (!hook.Success)
            return hook;

        var rulesPath = UserPfRulesPath;
        try
        {
            File.WriteAllText(rulesPath, BuildPfRuleset(LoadLedger()));
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail($"Could not write PF rules file: {ex.Message}");
        }

        // Copy into system path and load anchor. Enable PF if needed.
        var systemRules = $"/etc/pf.anchors/{PfAnchorName}";
        var script =
            $"mkdir -p /etc/pf.anchors && " +
            $"cp {ShellQuote(rulesPath)} {ShellQuote(systemRules)} && " +
            $"chmod 644 {ShellQuote(systemRules)} && " +
            $"/sbin/pfctl -e 2>/dev/null; " +
            $"/sbin/pfctl -a {ShellQuote(PfAnchorName)} -f {ShellQuote(systemRules)}";

        return RunPrivilegedShell(script);
    }

    private static string BuildPfRuleset(IEnumerable<FirewallRuleInfo> rules)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Network Sentinel PF anchor — managed rules (do not edit by hand)");
        sb.AppendLine($"# Generated {DateTime.Now:u}");
        sb.AppendLine();

        foreach (var rule in rules.Where(r => r.Enabled && r.IsBlock))
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

        return sb.ToString();
    }

    /// <summary>
    /// Ensures /etc/pf.conf references our anchor (with backup), once.
    /// </summary>
    private FirewallOperationResult EnsureAnchorHooked()
    {
        var marker = $"anchor \"{PfAnchorName}\"";
        var loadLine = $"load anchor \"{PfAnchorName}\" from \"/etc/pf.anchors/{PfAnchorName}\"";
        var emptyRules = $"/etc/pf.anchors/{PfAnchorName}";

        // Idempotent shell: create anchor file if missing; append pf.conf lines if absent; reload.
        var script = $"""
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
            true
            """;

        return RunPrivilegedShell(script);
    }

    private static string UserPfRulesPath
        => Path.Combine(AppPaths.DataDirectory, "pf-anchor.conf");

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

            var osa = RunProcess(
                "osascript",
                "-e",
                $"do shell script \"{asLiteral}\" with administrator privileges");
            if (osa.Success)
                return osa;

            // 3) Interactive sudo when we have a TTY (TUI / Terminal)
            if (CommandExists("sudo") && !Console.IsInputRedirected)
                return RunProcess("sudo", "/bin/bash", "-c", shellScript);

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

    private static FirewallOperationResult RunProcess(string file, params string[] args)
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

            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(120_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return FirewallOperationResult.Fail($"{file} timed out.");
            }

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
            File.WriteAllText(LedgerPath, JsonSerializer.Serialize(rules, JsonOptions));
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

        normalized = address.ToString();
        return true;
    }

    public static bool IsPrivateOrLocal(string ip)
        => GeoIpService.IsNonPublic(ip);

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

    public string DirectionText => Direction.ToString();
    public string KindText => Kind switch
    {
        FirewallRuleKind.IpBlock => "IP block",
        FirewallRuleKind.PortBlock => "Port block",
        _ => "Rule"
    };
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
