using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace NetworkSentinel.Native;

/// <summary>One observed flow — a connection the kernel is tracking state for.</summary>
public sealed class NetworkFlow
{
    public required string Protocol { get; init; }
    public required string SourceAddress { get; init; }
    public required int SourcePort { get; init; }
    public required string DestinationAddress { get; init; }
    public required int DestinationPort { get; init; }
    public DateTime Observed { get; init; } = DateTime.Now;
}

/// <summary>
/// Flow events from PF's state table, the macOS stand-in for Linux's conntrack
/// netlink source.
///
/// Why this exists at all: the socket tables (<c>lsof</c>, <c>netstat</c>) only show
/// sockets this machine owns, and for UDP they show almost nothing useful — a DNS
/// query is a send on an unconnected socket that is gone before the next poll. PF
/// tracks state for UDP as well as TCP, and for traffic this machine merely forwards,
/// so it sees flows no socket table ever will. That is what makes DNS monitoring
/// possible.
///
/// How it differs from conntrack, and it matters:
///   - It is POLLED, not evented. Linux gets a netlink message per new flow; here we
///     diff successive `pfctl -s state` dumps. A flow that opens and closes inside one
///     interval is never seen. Long-lived flows and repeated queries to the same
///     resolver are seen reliably, which is what the DNS checks are built on.
///   - It needs PF to be *enabled*. macOS boots with PF off unless something turns it
///     on, and a disabled PF has no state table at all.
///   - It needs root. Like conntrack netlink, reading the state table is privileged;
///     unlike it, the privilege is spent per poll, so this only runs when elevation is
///     silent (root, or cached/passwordless sudo). It never raises a password dialog —
///     a monitor that prompts once a second is worse than a monitor that is off.
/// </summary>
public sealed class PfFlowEventSource : IDisposable
{
    /// <summary>
    /// Dump cadence. A second is short enough to catch repeated DNS traffic and long
    /// enough that one privileged subprocess per tick stays cheap.
    /// </summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Ceiling on remembered state keys. A busy forwarder can hold tens of thousands of
    /// states; the set is only there to tell "new" from "already seen", so dropping it
    /// wholesale when it gets big costs one round of duplicate events, not correctness.
    /// </summary>
    private const int MaxRememberedKeys = 60_000;

    private readonly object _gate = new();
    private HashSet<string> _seen = new(StringComparer.Ordinal);

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private volatile string _status = "PF flow events not started";
    private volatile bool _active;

    public event Action<NetworkFlow>? FlowCreated;

    public string Status => _status;

    public bool IsActive => _active;

    public bool Start()
    {
        if (_loop != null)
            return _active;

        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => RunAsync(_cts.Token));
        return true;
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* already gone */ }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { /* best effort */ }
        _cts?.Dispose();
        _cts = null;
        _loop = null;
        _active = false;
        lock (_gate) _seen.Clear();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        // First dump only establishes the baseline. Every state PF already holds is
        // pre-existing, not new, and emitting all of them would look like a burst of
        // fresh activity the moment monitoring starts.
        var primed = false;

        while (!ct.IsCancellationRequested)
        {
            if (!TryDumpStates(out var dump, out var error))
            {
                _active = false;
                _status = error;
                // Nothing will change within a second; back off rather than spawning a
                // privileged subprocess per tick against a condition that needs the
                // operator to fix.
                await SafeDelay(TimeSpan.FromSeconds(15), ct);
                continue;
            }

            var flows = ParseStates(dump);
            var keys = new HashSet<string>(StringComparer.Ordinal);
            var fresh = new List<NetworkFlow>();

            foreach (var (key, flow) in flows)
            {
                keys.Add(key);
                if (primed && !_seen.Contains(key))
                    fresh.Add(flow);
            }

            lock (_gate)
            {
                // Union rather than replace: a state can drop out of one dump and return
                // (PF reuses entries), and treating that as new would double-count it.
                // The cap keeps the union from growing forever.
                if (_seen.Count > MaxRememberedKeys)
                    _seen = keys;
                else
                    foreach (var key in keys) _seen.Add(key);
            }

            _active = true;
            _status = $"PF state table: {flows.Count} flows tracked";

            if (!primed)
            {
                primed = true;
            }
            else
            {
                foreach (var flow in fresh)
                {
                    try { FlowCreated?.Invoke(flow); }
                    catch { /* a bad handler must not kill the poll loop */ }
                }
            }

            await SafeDelay(PollInterval, ct);
        }
    }

    private static async Task SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    /// <summary>
    /// Runs `pfctl -s state` without ever prompting: as root directly, otherwise through
    /// <c>sudo -n</c>. Returns false with a message the console can show verbatim.
    /// </summary>
    private static bool TryDumpStates(out string dump, out string error)
    {
        dump = "";
        error = "";

        var root = geteuid() == 0;
        var psi = new ProcessStartInfo
        {
            FileName = root ? "/sbin/pfctl" : "sudo",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (!root)
        {
            psi.ArgumentList.Add("-n");
            psi.ArgumentList.Add("/sbin/pfctl");
        }
        psi.ArgumentList.Add("-s");
        psi.ArgumentList.Add("state");

        try
        {
            using var proc = Process.Start(psi);
            if (proc == null)
            {
                error = "Could not run pfctl to read the PF state table";
                return false;
            }

            // Both pipes concurrently: the state table can be megabytes and pfctl writes
            // its warnings to stderr, so a blocking read of either one alone deadlocks.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            if (!proc.WaitForExit(10_000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                error = "pfctl did not finish within 10s while reading the state table";
                return false;
            }

            dump = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();

            if (proc.ExitCode != 0 || LooksLikeNoState(stderr))
            {
                error = DescribeFailure(stderr, root);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"PF flow events unavailable: {ex.Message}";
            return false;
        }
    }

    internal static bool LooksLikeNoState(string stderr)
        => stderr.Contains("pf not enabled", StringComparison.OrdinalIgnoreCase)
           || stderr.Contains("Operation not supported", StringComparison.OrdinalIgnoreCase);

    internal static string DescribeFailure(string stderr, bool root)
    {
        if (stderr.Contains("pf not enabled", StringComparison.OrdinalIgnoreCase))
            return "PF is disabled — flow events need `pfctl -e` (blocking an address enables it)";
        if (stderr.Contains("a password is required", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("no tty", StringComparison.OrdinalIgnoreCase))
            return "PF flow events need root — run the console as root, or give it passwordless sudo for pfctl";
        if (!root && stderr.Length == 0)
            return "PF flow events need root — run the console as root, or give it passwordless sudo for pfctl";

        var first = stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
        return string.IsNullOrEmpty(first)
            ? "PF state table unavailable"
            : $"PF state table unavailable: {first}";
    }

    /// <summary>
    /// Parses `pfctl -s state`. Internal so the suite can replay captured output.
    ///
    /// A line looks like one of:
    ///   all tcp 192.168.0.105:53456 -&gt; 17.253.20.125:443  ESTABLISHED:ESTABLISHED
    ///   en0 udp 192.168.0.105:59674 -&gt; 1.1.1.1:53          MULTIPLE:SINGLE
    ///   en0 tcp 192.168.0.105:22 &lt;- 203.0.113.5:40000       ESTABLISHED:ESTABLISHED
    ///   all tcp 10.0.0.5:51000 (192.168.0.105:51000) -&gt; 93.184.216.34:443 ...
    ///   all tcp 2606:4700::1[443] &lt;- 2600:1700::5[53456]    ESTABLISHED:ESTABLISHED
    ///
    /// pfctl always prints the local end on the left of the arrow and the remote end on
    /// the right, flipping the arrow rather than the operands: <c>-&gt;</c> is outbound,
    /// <c>&lt;-</c> is inbound. A parenthesised address is the pre-NAT form of the endpoint
    /// it follows and is skipped — the translated address is the one on the wire.
    ///
    /// Emitted flows are oriented by traffic direction, so SourceAddress is whoever
    /// initiated: the local end for an outbound flow, the remote end for an inbound one.
    /// </summary>
    internal static List<(string Key, NetworkFlow Flow)> ParseStates(string dump)
    {
        var result = new List<(string, NetworkFlow)>();
        if (string.IsNullOrEmpty(dump))
            return result;

        foreach (var raw in dump.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
                continue;

            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            // interface, proto, left, arrow, right — the state summary that follows is
            // not needed here.
            if (fields.Length < 5)
                continue;

            var proto = fields[1].ToUpperInvariant();
            if (proto is not ("TCP" or "UDP"))
                continue;

            // Find the arrow rather than assuming an index: the pre-NAT parenthetical
            // shifts everything after it right by one field.
            var arrow = -1;
            for (var i = 3; i < fields.Length; i++)
            {
                if (fields[i] is "->" or "<-")
                {
                    arrow = i;
                    break;
                }
            }
            if (arrow < 3 || arrow + 1 >= fields.Length)
                continue;

            // The endpoint immediately before the arrow, skipping a parenthetical.
            var leftField = fields[arrow - 1];
            if (leftField.StartsWith('(') && arrow - 2 >= 2)
                leftField = fields[arrow - 2];

            if (!TryParseEndpoint(leftField, out var localIp, out var localPort))
                continue;
            if (!TryParseEndpoint(fields[arrow + 1], out var remoteIp, out var remotePort))
                continue;

            var outbound = fields[arrow] == "->";
            var flow = outbound
                ? new NetworkFlow
                {
                    Protocol = proto,
                    SourceAddress = localIp,
                    SourcePort = localPort,
                    DestinationAddress = remoteIp,
                    DestinationPort = remotePort
                }
                : new NetworkFlow
                {
                    Protocol = proto,
                    SourceAddress = remoteIp,
                    SourcePort = remotePort,
                    DestinationAddress = localIp,
                    DestinationPort = localPort
                };

            var key = $"{flow.Protocol}|{flow.SourceAddress}:{flow.SourcePort}|{flow.DestinationAddress}:{flow.DestinationPort}";
            result.Add((key, flow));
        }

        return result;
    }

    /// <summary>
    /// Splits "addr:port" (IPv4) or "addr[port]" (IPv6, which is how pfctl prints it,
    /// because a bare colon is ambiguous inside an IPv6 literal).
    /// </summary>
    internal static bool TryParseEndpoint(string field, out string address, out int port)
    {
        address = "";
        port = 0;
        if (string.IsNullOrEmpty(field))
            return false;

        field = field.Trim().Trim('(', ')');

        var bracket = field.LastIndexOf('[');
        if (bracket > 0 && field.EndsWith(']'))
        {
            address = field[..bracket];
            return int.TryParse(field[(bracket + 1)..^1], NumberStyles.Integer,
                CultureInfo.InvariantCulture, out port) && port is >= 0 and <= 65535;
        }

        var colon = field.LastIndexOf(':');
        if (colon <= 0 || colon == field.Length - 1)
            return false;

        // A bare IPv6 literal with no port would have several colons; without the
        // bracket form there is no port to read, so leave it alone.
        if (field.IndexOf(':') != colon)
            return false;

        address = field[..colon];
        return int.TryParse(field[(colon + 1)..], NumberStyles.Integer,
            CultureInfo.InvariantCulture, out port) && port is >= 0 and <= 65535;
    }

    public void Dispose() => Stop();

    [DllImport("libc")]
    private static extern uint geteuid();
}
