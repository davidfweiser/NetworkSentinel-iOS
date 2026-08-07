import Foundation
import SwiftUI

// MARK: - Server profile (local)

struct ServerProfile: Identifiable, Codable, Hashable {
    var id: UUID
    var name: String
    var baseURL: String
    var createdAt: Date
    var lastConnectedAt: Date?

    init(id: UUID = UUID(), name: String, baseURL: String, createdAt: Date = .now, lastConnectedAt: Date? = nil) {
        self.id = id
        self.name = name
        self.baseURL = Self.normalizeURL(baseURL)
        self.createdAt = createdAt
        self.lastConnectedAt = lastConnectedAt
    }

    var displayHost: String {
        guard let url = URL(string: baseURL) else { return baseURL }
        let host = url.host ?? baseURL
        if let port = url.port { return "\(host):\(port)" }
        return host
    }

    static func normalizeURL(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return s }
        if !s.hasPrefix("http://") && !s.hasPrefix("https://") {
            s = "http://\(s)"
        }
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }
}

// MARK: - Auth

struct AuthStatus: Codable {
    let ok: Bool
    let configured: Bool
    let authenticated: Bool
    let minPasswordLength: Int?
}

struct AuthResponse: Codable {
    let ok: Bool
    let message: String?
    let authenticated: Bool?
    let configured: Bool?
}

// MARK: - State

struct ServerState: Codable {
    let ok: Bool
    let version: String?
    let clock: String?
    let statusMessage: String?
    let firewall: FirewallInfo?
    let settings: SettingsInfo?
    let stats: StatsInfo?
    let allowlistStatus: String?
    let connections: [ConnectionInfo]?
    let hosts: [HostInfo]?
    let threats: [ThreatInfo]?
    let ports: [PortInfo]?
    let firewallRules: [FirewallRuleInfo]?
    let allowlist: [AllowlistEntry]?
    let activity: [ActivityPoint]?
}

struct FirewallInfo: Codable {
    let isAdmin: Bool?
    let isRoot: Bool?
    let privilegeText: String?
}

struct SettingsInfo: Codable {
    let autoBlockEnabled: Bool?
    let autoBlockMinLevel: String?
    /// The engine's own one-line summary — web ≥ 0.6.3. Every frontend used to build this
    /// string itself and every one of them dropped the same thing: dry run. The server
    /// publishes it so a console cannot read "Auto-block ON" while the engine is
    /// deliberately writing no rules.
    let autoBlockSummary: String?
    let blockInbound: Bool?
    let blockOutbound: Bool?
    /// Present on Network Sentinel web ≥ 0.3.0
    let geoLookupEnabled: Bool?
    /// Present on Network Sentinel web ≥ 0.3.0
    let allowlistUseRemoteFeed: Bool?
    /// Auth-log brute-force monitoring — present on web ≥ 0.3.3
    let authLogMonitorEnabled: Bool?
    /// Human-readable state of the auth-log watcher (which log, or why it is unavailable).
    let authLogStatus: String?
    /// Closed-port scan detection via firewall SYN logging — present on web ≥ 0.3.4
    let probeLogEnabled: Bool?
    /// Human-readable state of the probe-log watcher (rule installed, needs elevation, …).
    let probeLogStatus: String?
    /// Server-side Critical warnings (desktop notification in the GUI, tab badge +
    /// browser notification in the web console) — present on web ≥ 0.3.5.
    /// Independent of this app's own notifications.
    let criticalAlertsEnabled: Bool?

    // MARK: Intrusion-detection suite (web ≥ 0.4.0)
    //
    // `threatIntelEnabled` is the probe for the whole group: a server that sends it sends
    // all of these, so the app gates one card on that single field.

    /// Remote peers checked against FireHOL level1 / Spamhaus DROP; a match is Critical.
    let threatIntelEnabled: Bool?
    /// Feed state — entry counts, last refresh, or why the feeds are unavailable.
    let threatIntelStatus: String?
    /// Unsigned/quarantined binaries talking to public hosts, executables in temp
    /// folders, shells with outbound connections.
    let processReputationEnabled: Bool?
    /// New port listening after the baseline, or a known port changing owner process.
    let newListenerAlertsEnabled: Bool?
    /// Default-gateway MAC changes and duplicate MACs on the LAN.
    let arpWatchEnabled: Bool?
    let arpWatchStatus: String?
    /// LaunchAgents / LaunchDaemons watch — the macOS name for the persistence watcher.
    let launchItemWatchEnabled: Bool?
    let launchWatchStatus: String?
    /// The same watcher on Linux and Windows, where persistence lives in systemd units,
    /// cron and autostart entries rather than launch items. Both platforms ship one key,
    /// never both, so the app reads whichever is present and writes back the same one.
    let persistenceWatchEnabled: Bool?
    let persistenceWatchStatus: String?
    /// Outbound byte volume to a single non-allowlisted public host.
    let exfilMonitorEnabled: Bool?
    /// Megabytes to one host within 10 minutes before the alert fires. Server floor is 10.
    let exfilMbPer10Min: Int?
    let exfilStatus: String?
    /// Decoy TCP ports; any completed connection is a Critical with no false-positive path.
    let honeypotEnabled: Bool?
    /// Comma-separated decoy port list, e.g. `2323,3389,5900`.
    let honeypotPorts: String?
    let honeypotStatus: String?
    /// Critical threats POSTed to ntfy / Slack / Discord / generic JSON. Empty = off.
    let webhookUrl: String?
    let webhookStatus: String?
    /// Minutes before an auto-created block rule is removed again. 0 = never.
    let autoBlockExpiryMinutes: Int?

    // MARK: Prevention engine, DNS, VPN and signatures (web ≥ 0.6.0)
    //
    // `preventionDryRun` is the probe for the 0.6 group as a whole: one enforcement engine
    // now backs every frontend, and a server that reports its dry-run flag reports the rest
    // of this block too. Each feature below is still gated on its own field, because the
    // detectors need root and a server without it publishes the setting plus the reason.

    /// Auto-block runs every gate and reports what it *would* drop, writing no rules.
    let preventionDryRun: Bool?
    /// Conntrack `NEW` events, so a snapshot is taken because something happened rather
    /// than because the poll timer fired. Needs root on the server.
    let conntrackEventsEnabled: Bool?
    let conntrackStatus: String?
    /// Plaintext DNS egress, encrypted DNS going away, unapproved resolvers, and
    /// allowlisted domains resolving into networks they have never used before.
    let dnsHygieneEnabled: Bool?
    /// Comma-separated resolver IPs. DoH is HTTPS and indistinguishable from web traffic,
    /// so it only counts as encrypted DNS when its destination is listed here.
    let dnsApprovedResolvers: String?
    let dnsHygieneStatus: String?
    /// WireGuard peers, which no other part of the server can see — a tunnel is one
    /// unconnected UDP socket with no peer in the socket table.
    let wireGuardMonitorEnabled: Bool?
    /// Megabytes per peer per 10 minutes before an alert. 0 = off, and off is the default:
    /// a peer streaming video legitimately moves gigabytes.
    let wireGuardPeerMbPer10Min: Int?
    let wireGuardStatus: String?
    /// Read-only peer table. Public keys only — the server drops private and preshared
    /// keys at parse time, so they never reach any client.
    let wireGuardPeers: [WireGuardPeerInfo]?
    /// Suricata EVE ingestion: payload inspection this app does not attempt itself.
    let suricataEnabled: Bool?
    /// Absolute path to `eve.json`. Empty resets the server to its own default.
    let suricataEvePath: String?
    /// Suricata counts severity down — 1 is most severe. Alerts numbered above this are
    /// dropped, so a lower number is a quieter feed.
    let suricataMaxSeverity: Int?
    /// Comma-separated signature ids to mute.
    let suricataIgnoredSids: String?
    let suricataStatus: String?

    // MARK: Remote access (web ≥ 0.5.0)

    /// TLS is bound at startup, so these are saved now and applied on the next restart —
    /// `httpsActive` is the only field that says what the console is actually serving.
    let httpsEnabled: Bool?
    let httpsActive: Bool?
    let httpsPort: Int?
    let httpsRedirect: Bool?
    let httpsStatus: String?
    let tlsCertPath: String?
    let tlsKeyPath: String?
    let duckDnsEnabled: Bool?
    let duckDnsDomain: String?
    /// Whether a token is stored. The token itself is never sent to any client.
    let duckDnsTokenSet: Bool?
    let duckDnsStatus: String?
    let acmeEmail: String?
    /// Certificate issuance waits on DNS propagation and runs for minutes, so it reports
    /// progress through state rather than through the action's own reply.
    let certIssueBusy: Bool?
    let certIssueMessage: String?
    let certIssueOk: Bool?

    let isMonitoring: Bool?

    // MARK: Persistence watch, under whichever name this server uses

    /// `nil` when the server predates the watcher entirely.
    var startupWatchEnabled: Bool? { persistenceWatchEnabled ?? launchItemWatchEnabled }
    var startupWatchStatus: String? { persistenceWatchStatus ?? launchWatchStatus }

    /// The `set_setting` key this server answers to. Writing the other one comes back as
    /// `Unknown setting`, which reads to the user as a toggle that silently does nothing.
    var startupWatchSettingKey: String? {
        if persistenceWatchEnabled != nil { return "persistenceWatchEnabled" }
        if launchItemWatchEnabled != nil { return "launchItemWatchEnabled" }
        return nil
    }

    /// Same watcher, but naming it after what it actually watches on that host is the
    /// difference between a row you can act on and one you have to guess at.
    var startupWatchTitle: String {
        persistenceWatchEnabled != nil ? "Startup-item watch" : "Launch-item watch"
    }
}

/// One WireGuard peer as the server reports it. Read-only by design: revoking a peer is a
/// WireGuard configuration change, not something a monitoring console does behind your back.
struct WireGuardPeerInfo: Codable, Identifiable {
    var id: String { "\(iface ?? "")|\(publicKey ?? shortKey ?? "")" }
    let iface: String?
    /// Truncated public key, for display where the full one will not fit.
    let shortKey: String?
    let publicKey: String?
    /// Public `host:port` the peer's tunnel packets arrive from.
    let endpoint: String?
    let allowedIps: String?
    let handshake: String?
    let rxMb: Int?
    let txMb: Int?
}

struct StatsInfo: Codable {
    let listeningPorts: Int?
    let activeConnections: Int?
    let remoteHosts: Int?
    let threatsToday: Int?
    let highThreats: Int?
    let statusText: String?
    let isMonitoring: Bool?
}

struct ConnectionInfo: Codable, Identifiable {
    /// Prefer stable fields; disambiguate duplicates via index in `uniqued(by:)`.
    var id: String {
        [
            protocolName,
            local,
            remote,
            state ?? "",
            process ?? "",
            "\(pid ?? 0)",
            lastSeen ?? ""
        ].joined(separator: "|")
    }
    let protocolName: String
    let local: String
    let remote: String
    let remoteAddress: String?
    let remotePort: Int?
    let state: String?
    let process: String?
    let pid: Int?
    let geo: String?
    let lastSeen: String?

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case local, remote, remoteAddress, remotePort, state, process, pid, geo, lastSeen
    }
}

struct HostInfo: Codable, Identifiable {
    var id: String { ip }
    let ip: String
    let name: String?
    let hostName: String?
    let geo: String?
    let active: Int?
    let total: Int?
    let ports: Int?
    let threat: String?
    let threatLevel: Int?
    let status: String?
    let blocked: Bool?
    let lastSeen: String?
}

struct ThreatInfo: Codable, Identifiable {
    var id: String {
        [
            // `ts` carries the date; `time` alone is HH:mm:ss and repeats every day,
            // which would make yesterday's alert look like today's to the dedupe store.
            ts ?? time,
            sourceIp,
            title,
            level,
            type ?? "",
            detail ?? "",
            method ?? ""
            // Deliberately not the 0.6.3 enforcement verdict. A threat is a record of what
            // was seen, and blocking moves underneath it afterwards — a rule gets written,
            // expires, or is released by hand. Folding the verdict into the identity would
            // mint a fresh id for an event already reported, and `CriticalAlertService`
            // would notify about it a second time on the poll that blocked it.
        ].joined(separator: "|")
    }
    /// Full ISO-8601 timestamp — present on web ≥ 0.3.5. Older servers send only `time`.
    let ts: String?
    let time: String
    let level: String
    let levelNum: Int?
    let type: String?
    let sourceIp: String
    let title: String
    let detail: String?
    let origin: String?
    let method: String?

    // MARK: Enforcement verdict (web ≥ 0.6.3)
    //
    // The server now runs each batch of threats past the prevention engine before any
    // alert about it leaves the machine, so a warning that names an address can say
    // whether that address is actually being blocked. All three fields are absent on
    // older servers and null on a threat that names no blockable address, which is the
    // difference between "not blocked" and "nothing to block".

    /// The full sentence, for the line under the row — `BLOCKED — auto-block rule added`,
    /// `NOT blocked — auto-block is off`, `Not blocked — allowlisted (…)`.
    let blockStatus: String?
    /// The same verdict in one word: `Blocked`, `Dry run`, `Failed` or `No`. The server
    /// settled this vocabulary once so its GUI, TUI and web console cannot describe the
    /// same state three ways — but it is worded for a cell under a *Blocked* column, and
    /// a phone list has no column header to read it against. The app maps it to the
    /// self-contained `BlockVerdict.label` and leaves `blockStatus` to say why, verbatim.
    let blockShort: String?
    /// True when traffic to and from the address is being dropped right now.
    let blocked: Bool?

    /// Where `sourceIp` stands with the prevention engine, or nil when there is nothing
    /// to say — an older server, or a threat naming no blockable address.
    ///
    /// Suppressed for the host-local detections too. The server does answer for those
    /// ("Not blocked — private address, never auto-blocked"), but the row has already
    /// replaced the address with *what* was detected, exactly because there is no peer to
    /// firewall; a "No" beside it only raises a question the row has already answered.
    var blockVerdict: BlockVerdict? {
        guard isBlockable, let short = blockShort, !short.isEmpty else { return nil }
        if blocked == true { return .blocked }
        switch short.lowercased() {
        case "blocked": return .blocked
        case "dry run": return .dryRun
        case "failed": return .failed
        default: return .notBlocked
        }
    }

    /// Whether offering **Block** on this threat leads anywhere.
    ///
    /// Several detectors report an address the server will refuse to firewall: the ones
    /// that watch the machine itself (new listener, persistence change) report `127.0.0.1`,
    /// DNS hygiene reports the resolver being queried — routinely a LAN or tunnel address —
    /// and a WireGuard peer with no current endpoint falls back to loopback too. Showing
    /// Block there is a button whose only outcome is an error toast, and on the attention
    /// card it would be the primary action.
    ///
    /// CGNAT is deliberately still blockable — see `AppModel.requestBlock(ip:)`, which asks
    /// first, because what it cuts off may be the tunnel you reach the server through.
    var isBlockable: Bool { IPScope.of(sourceIp).isBlockable }

    /// SF Symbol for the server's threat-type text. Web 0.4.0 took the type count from
    /// eight to fifteen and 0.6.0 to eighteen; a list where every row is the same triangle
    /// makes them all look like one thing.
    var icon: String {
        switch (type ?? "").lowercased() {
        case "new listener": return "antenna.radiowaves.left.and.right"
        case "suspicious process": return "cpu"
        case "known-bad address": return "xmark.shield.fill"
        case "honeypot hit": return "target"
        case "arp spoofing": return "point.3.connected.trianglepath.dotted"
        case "persistence change": return "arrow.clockwise.circle"
        case "data exfiltration": return "arrow.up.doc"
        case "port scan", "sensitive port probe": return "dot.radiowaves.left.and.right"
        case "brute-force pattern", "failed logon burst": return "person.badge.key"
        case "new remote host": return "globe"
        case "suspicious outbound": return "arrow.up.right"
        case "rapid reconnect", "short-lived burst": return "arrow.left.arrow.right"
        // Web 0.6.0
        case "signature match": return "doc.text.magnifyingglass"
        case "vpn peer change": return "key.fill"
        case "dns anomaly": return "magnifyingglass.circle"
        default: return "exclamationmark.triangle"
        }
    }
}

// MARK: - Enforcement verdict

/// The prevention engine's answer to "is this address being blocked?", which web 0.6.3
/// attaches to every threat it reports.
///
/// A warning that names an address and stops there sends you to the console to find out
/// whether anything was actually done about it — at the one moment that is least
/// affordable. The server therefore decides before the alert leaves the machine, and this
/// enum only chooses how the answer is coloured and whether the row's action should be
/// Block or Unblock. The words themselves stay the server's.
enum BlockVerdict {
    /// A rule is in force — traffic to and from the address is being dropped.
    case blocked
    /// It cleared every gate, but prevention is in dry-run mode so no rule was written.
    case dryRun
    /// A block was attempted and the firewall refused it.
    case failed
    /// Deliberately left alone; `ThreatInfo.blockStatus` names the gate that stopped it.
    case notBlocked

    /// Red for an address being dropped — the same badge the Hosts tab already gives a
    /// blocked peer. Amber for the two verdicts that are *not* stopping anything and want
    /// a look; muted for one that was left alone on purpose.
    var tint: Color {
        switch self {
        case .blocked: return NSTheme.danger
        case .dryRun, .failed: return NSTheme.warning
        case .notBlocked: return NSTheme.muted
        }
    }

    /// Reads on its own, without the column header the server's own word assumes.
    var label: String {
        switch self {
        case .blocked: return "Blocked"
        case .dryRun: return "Dry run"
        case .failed: return "Block failed"
        case .notBlocked: return "Not blocked"
        }
    }

    var icon: String {
        switch self {
        case .blocked: return "hand.raised.fill"
        case .dryRun: return "eye"
        case .failed: return "exclamationmark.triangle.fill"
        case .notBlocked: return "hand.raised.slash"
        }
    }

    /// How an alert leads with this verdict, in the same two forms the server's own
    /// desktop popups, browser notifications and webhooks use. Dry run and a refused rule
    /// both count as NOT blocked here, because neither one is stopping anything.
    var alertPrefix: String { isBlocked ? "Blocked" : "NOT blocked" }

    /// Whether the useful action on this address is to release it rather than block it.
    /// Re-blocking would only rewrite a rule already in force.
    var isBlocked: Bool { self == .blocked }
}

// MARK: - Address scope

/// Where an address sits relative to what the server will firewall, mirroring its
/// `FirewallService.IsNeverBlockable`: LAN, loopback, link-local and multicast are refused
/// outright, and CGNAT (100.64/10 — Tailscale and most WireGuard tunnels) is the one
/// non-public range a manual block still reaches.
enum IPScope: Equatable {
    case publicAddress
    case carrierGradeNAT
    case privateOrLocal
    case notAnAddress

    /// Manual block reaches public addresses, and CGNAT deliberately.
    var isBlockable: Bool { self == .publicAddress || self == .carrierGradeNAT }

    static func of(_ raw: String) -> IPScope {
        var s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if s.isEmpty || s == "*" || s == "localhost" { return .notAnAddress }
        if s.hasPrefix("["), s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        // Drop an IPv6 zone id (`fe80::1%en0`); it is interface scope, not address.
        if let pct = s.firstIndex(of: "%") { s = String(s[s.startIndex..<pct]) }

        guard s.contains(":") else { return ipv4(s) }
        // A dual-stack socket reports IPv4 peers as `::ffff:a.b.c.d`. Judging the mapped
        // form as IPv6 would call every LAN peer of an IPv6 listener public.
        if let tail = s.split(separator: ":").last, tail.contains(".") {
            return ipv4(String(tail))
        }
        return ipv6(s)
    }

    private static func ipv4(_ s: String) -> IPScope {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return .notAnAddress }
        var b: [Int] = []
        for part in parts {
            guard let v = Int(part), (0...255).contains(v) else { return .notAnAddress }
            b.append(v)
        }
        if b[0] == 0 || b[0] == 10 || b[0] == 127 { return .privateOrLocal }
        if b[0] == 172, (16...31).contains(b[1]) { return .privateOrLocal }
        if b[0] == 192, b[1] == 168 { return .privateOrLocal }
        if b[0] == 169, b[1] == 254 { return .privateOrLocal }
        if b[0] == 100, (64...127).contains(b[1]) { return .carrierGradeNAT }
        if b[0] >= 224 { return .privateOrLocal }
        return .publicAddress
    }

    private static func ipv6(_ s: String) -> IPScope {
        guard s.allSatisfy({ $0.isHexDigit || $0 == ":" }) else { return .notAnAddress }
        if s == "::" || s == "::1" { return .privateOrLocal }
        // fe80::/10 link-local, fec0::/10 site-local (deprecated but still refused),
        // fc00::/7 unique-local, ff00::/8 multicast.
        let leading2 = String(s.prefix(2))
        let leading3 = String(s.prefix(3))
        if leading2 == "fc" || leading2 == "fd" || leading2 == "ff" { return .privateOrLocal }
        if ["fe8", "fe9", "fea", "feb", "fec", "fed", "fee", "fef"].contains(leading3) {
            return .privateOrLocal
        }
        return .publicAddress
    }
}

struct PortInfo: Codable, Identifiable {
    /// Include endpoint + process so multiple listeners on the same port don't collide
    /// (e.g. two TCP:22 rows with missing pid both became "TCP-22-0").
    var id: String {
        [
            protocolName,
            "\(port)",
            endpoint ?? "",
            process ?? "",
            "\(pid ?? 0)",
            hint ?? ""
        ].joined(separator: "|")
    }
    let protocolName: String
    let endpoint: String?
    let port: Int
    let process: String?
    let pid: Int?
    let hint: String?

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case endpoint, port, process, pid, hint
    }
}

struct FirewallRuleInfo: Codable, Identifiable {
    var id: String {
        [
            name,
            kind ?? "",
            address ?? "",
            target,
            ports ?? "",
            direction ?? "",
            protocolName ?? "",
            action ?? "",
            description ?? "",
            "\(isProtected ?? false)"
        ].joined(separator: "|")
    }
    let name: String
    /// Web console's own allow rule for its listen port — must not be removed from the client.
    let isProtected: Bool?
    let kind: String?
    /// Explicit address field (0.3+); falls back to target when absent.
    let address: String?
    let target: String
    let ports: String?
    let direction: String?
    let protocolName: String?
    let enabled: Bool?
    let action: String?
    let description: String?

    /// Best display target for block/unblock of IPs.
    var displayAddress: String {
        if let address, !address.isEmpty { return address }
        return target
    }

    var isProtectedRule: Bool { isProtected == true }

    enum CodingKeys: String, CodingKey {
        case name, isProtected, kind, address, target, ports, direction
        case protocolName = "protocol"
        case enabled, action, description
    }
}

struct AllowlistEntry: Codable, Identifiable {
    var id: String { "\(kind)|\(value)|\(detail ?? "")" }
    let kind: String
    let value: String
    let detail: String?
}

struct ActivityPoint: Codable, Identifiable {
    var id: String { "\(time)|\(connections ?? 0)|\(threats ?? 0)|\(hosts ?? 0)" }
    let time: String
    let connections: Int?
    let threats: Int?
    let hosts: Int?
}

// MARK: - Unique list IDs

/// Wraps a value with a guaranteed-unique `id` for SwiftUI `ForEach` when the API
/// returns duplicate rows (same port, same connection key, etc.).
struct UniqueRow<T>: Identifiable {
    let id: String
    let value: T
}

extension Array where Element: Identifiable, Element.ID == String {
    /// Appends `#2`, `#3`, … when base ids repeat so ForEach never sees collisions.
    func uniquedRows() -> [UniqueRow<Element>] {
        var seen: [String: Int] = [:]
        return map { element in
            let base = element.id
            let n = seen[base, default: 0]
            seen[base] = n + 1
            let unique = n == 0 ? base : "\(base)#\(n)"
            return UniqueRow(id: unique, value: element)
        }
    }
}

struct ActionResponse: Codable {
    let ok: Bool
    let message: String?

    /// The server's reply to a verb it has never heard of (`Unknown action: sleep`).
    /// Distinguishes "this server is older than the feature" from "the action failed",
    /// which is what lets a newer action name fall back to its older alias.
    var isUnknownAction: Bool {
        (message ?? "").localizedCaseInsensitiveContains("unknown action")
    }
}

// MARK: - Threat helpers

struct CriticalAlertPayload: Identifiable, Equatable {
    let id = UUID()
    let serverName: String
    let threat: ThreatInfo
    let extraCount: Int

    static func == (lhs: CriticalAlertPayload, rhs: CriticalAlertPayload) -> Bool {
        lhs.id == rhs.id
    }
}

enum ThreatSeverity: Int, Comparable {
    case none = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    static func from(level: String?, levelNum: Int?) -> ThreatSeverity {
        if let n = levelNum {
            return ThreatSeverity(rawValue: min(max(n, 0), 4)) ?? .none
        }
        switch (level ?? "").lowercased() {
        case "critical": return .critical
        case "high": return .high
        case "medium": return .medium
        case "low": return .low
        default: return .none
        }
    }

    var color: Color {
        switch self {
        case .none: return .secondary
        case .low: return Color(red: 0.35, green: 0.75, blue: 0.95)
        case .medium: return Color(red: 0.95, green: 0.75, blue: 0.25)
        case .high: return Color(red: 0.98, green: 0.45, blue: 0.25)
        case .critical: return Color(red: 0.95, green: 0.25, blue: 0.35)
        }
    }

    var label: String {
        switch self {
        case .none: return "None"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        case .critical: return "Critical"
        }
    }
}
