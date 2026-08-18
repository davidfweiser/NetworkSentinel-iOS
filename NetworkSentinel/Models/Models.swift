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
    /// Bandwidth meter — web ≥ 0.7.0. Absent on older servers and on this one when the
    /// meter has never been switched on.
    let traffic: TrafficInfo?
    /// The firewall ledger in evaluation order — web ≥ 0.7.0. Distinct from
    /// `firewallRules`, which is only the blocks this app and the engine minted.
    ///
    /// On web ≥ 0.7.4 this is no longer a ledger but a scan of the whole host firewall —
    /// UFW's rules, WireGuard's, Docker's and this app's, in one list. The shape is
    /// unchanged, so a 0.7.0–0.7.3 server still decodes; what changes is how much of the
    /// machine it describes, and that a row may now belong to something else entirely.
    let configRules: [ConfigRuleInfo]?
    /// What the scan found the host firewall to *be* — backend, status, default policies —
    /// web ≥ 0.7.4. Absent on older servers, where `configRules` is the app's own ledger and
    /// there is no host-wide reading to report.
    let hostFirewall: HostFirewallInfo?
    /// Every socket accepting connections on the host, and whether the firewall admits it —
    /// web ≥ 0.7.4. Distinct from `ports`, which is the monitor's own view of listening
    /// ports and says nothing about whether they are reachable.
    let listeners: [HostListener]?
}

/// The host firewall as one reading — web ≥ 0.7.4.
///
/// Before 0.7.4 the Firewall Config screen showed this app's ledger and nothing else, which
/// on a UFW box is a near-empty page sitting beside a firewall full of rules. The server now
/// reads `ufw status verbose`, `nft -j list ruleset`, `iptables -S` and `ss -tulpnH` and
/// folds them into one list. This is the header for that list: which backend actually owns
/// the machine, whether it is switched on, and what happens to traffic no rule matches.
///
/// The reads are inspections, so a server without elevation still answers — with a short
/// list and a `privilegeNote` saying that is why. A short list is not the same as an empty
/// firewall and the two must not be shown as though they were.
struct HostFirewallInfo: Codable {
    /// The machine. The firewall is named after the host it protects, not after this app.
    let host: String?
    /// "UFW", "nftables", "iptables" or "none".
    let backend: String?
    let status: String?
    let enabled: Bool?
    /// What the chain does with inbound traffic no rule matched — "Accept", "Drop", "Reject".
    /// The whole meaning of an Allow rule hangs on this: under a default of Drop an Allow is
    /// what makes a service reachable at all, under Accept it only opens a path through the
    /// rules above it.
    let defaultInbound: String?
    let defaultOutbound: String?
    let description: String?
    /// What could not be read, and what would fix it. Empty when the scan saw everything.
    let privilegeNote: String?
    /// "12 Inbound · 3 Outbound", or "No rules".
    let rulesSummary: String?
    /// Every backend that answered, not just the one that owns the host — a box can have
    /// nftables rules underneath an active UFW.
    let backendsSeen: [String]?
    let errors: [String]?
    /// Local time of the scan, `HH:mm:ss`. The scan is cached server-side, so this is how
    /// old the list is — it is not the poll time.
    let scannedAt: String?

    var isEnabled: Bool { enabled == true }

    /// True when inbound traffic matching nothing is dropped. The default when the server
    /// says nothing is the safe reading, not the permissive one.
    var dropsInboundByDefault: Bool {
        (defaultInbound ?? "").caseInsensitiveCompare("Accept") != .orderedSame
    }

    /// One line for the screen header: `athena · UFW · Active · 12 Inbound · 3 Outbound`.
    var headline: String {
        [host, backend, status, rulesSummary]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }
}

/// A socket listening on the host, and what the firewall does to traffic arriving at it —
/// web ≥ 0.7.4.
///
/// A listener the firewall does not admit is not reachable however loudly it is listening,
/// and a listener nothing covers is the one worth knowing about. That is the whole reason
/// this list sits under the rules rather than on the Ports screen: the pairing is the reading.
struct HostListener: Codable, Identifiable {
    /// Nothing here is unique on its own — one process binds many ports, one port answers on
    /// two addresses — so identity is the whole tuple.
    var id: String {
        [protocolName, address, port, process, service]
            .map { $0 ?? "" }
            .joined(separator: "|")
    }
    let protocolName: String?
    /// The bind address. `0.0.0.0` or `::` is every interface; `127.0.0.1` is this machine only.
    let address: String?
    let port: String?
    /// What usually answers on this port, from the server's port catalogue.
    let service: String?
    let process: String?
    /// "Open", "Restricted", "Not allowed", "Local only", "No firewall" or "Unknown".
    let covered: String?

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case address, port, service, process, covered
    }

    /// How alarming the coverage is. `Open` is a warning rather than an error — a web server
    /// is supposed to be open — but it is the row to read first, and `No firewall` says the
    /// question was never asked.
    enum Exposure {
        case open, restricted, closed, none, unknown
    }

    var exposure: Exposure {
        switch (covered ?? "").lowercased() {
        case "open": return .open
        case "restricted": return .restricted
        case "not allowed", "local only": return .closed
        case "no firewall": return .none
        default: return .unknown
        }
    }

    /// The port as a single number, or nil when the scan could only label it — `ss` prints a
    /// name for some kernel sockets, and a rule cannot be written against a name.
    var portNumber: Int? {
        let text = (port ?? "").trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty, text.allSatisfy(\.isWholeNumber) else { return nil }
        return Int(text)
    }

    /// `sshd on 0.0.0.0:22` — who is listening and where, for the note on a rule seeded from
    /// this socket. The server's GUI and web console build the same phrase from the same
    /// fields, so an operator moving between the three reads one sentence about one socket.
    var describedSource: String {
        let name = (process ?? "").trimmingCharacters(in: .whitespaces)
        let who = name.isEmpty || name == "—" ? "an unidentified process" : name
        let bind = (address ?? "").trimmingCharacters(in: .whitespaces)
        let place = bind.isEmpty ? "port \(port ?? "?")" : "\(bind):\(port ?? "?")"
        return "\(who) on \(place)"
    }

    /// The rule this socket argues for — web ≥ 0.7.4's *New rule* on a listening row.
    ///
    /// Protocol and port carry over. The bind address deliberately does not: Addresses on an
    /// inbound rule matches the *far end* of a connection, so seeding it with `0.0.0.0`, `::`
    /// or this host's own LAN address would write a rule matching nothing an attacker sends.
    ///
    /// Nil when the port is not a plain number, because a form opened on an unparseable port
    /// is worse than no form — the server would refuse it after the round trip.
    var newRuleDraft: FirewallRuleDraft? {
        guard let portNumber else { return nil }
        var draft = FirewallRuleDraft()
        draft.direction = .inbound
        draft.protocolName = (protocolName ?? "").caseInsensitiveCompare("UDP") == .orderedSame ? "UDP" : "TCP"
        draft.ports = String(portNumber)
        return draft
    }

    /// Why the fields arrived filled in, and why one of them did not.
    var newRuleNote: String? {
        guard let draft = newRuleDraft else { return nil }
        return "Writes a rule for \(draft.protocolName) port \(draft.ports), which \(describedSource) is "
             + "listening on. Addresses is left empty (every address) — it matches the remote end, not the "
             + "address the service is bound to. Applying needs root or pkexec/sudo on the server."
    }

    /// What to say instead of opening a form on a port that is not a number.
    var newRuleRefusal: String {
        "“\(port ?? "")” is not a single port number, so there is nothing to prefill — write the "
        + "rule by hand with Add rule."
    }
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
    /// Bandwidth accounting on the host's interfaces — present on web ≥ 0.7.0. The probe
    /// for the `traffic` object: a server that sends this sends that.
    let trafficMeterEnabled: Bool?
    /// Which interfaces are being counted, or why none are.
    let trafficStatus: String?
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

    /// Red for an address being dropped — the same badge Remote Computers already gives a
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

    /// The rule name without its `-In` / `-Out` suffix. The server writes every block as a
    /// pair, so the base name — not the individual rule — is the thing the user blocked.
    var baseName: String {
        for suffix in ["-In", "-Out"] where name.lowercased().hasSuffix(suffix.lowercased()) {
            return String(name.dropLast(suffix.count))
        }
        return name
    }

    /// Port and protocol of a managed port block, read back out of the server's rule name
    /// (`FirewallService.PortRuleName`: `NetworkSentinel-Port-TCP-8080-In`). Nil for IP
    /// blocks. This is what lets the Ports list know a listener is already blocked and
    /// offer Unblock instead of a Block button that has nothing left to do.
    var blockedPort: (port: Int, protocolName: String)? {
        let parts = baseName.split(separator: "-")
        guard parts.count == 4,
              parts[1].caseInsensitiveCompare("Port") == .orderedSame,
              let port = Int(parts[3])
        else { return nil }
        return (port, parts[2].uppercased())
    }

    var isPortRule: Bool { blockedPort != nil }

    /// The address of a managed IP block, read back out of the rule name
    /// (`FirewallService.IpRuleName`: `NetworkSentinel-IP-1.2.3.4-In`, with `:` sanitized
    /// to `_` for IPv6). This is the normalised form `unblock` expects, so it is also what
    /// tells a threat row its source is already blocked.
    var blockedIPAddress: String? {
        let parts = baseName.split(separator: "-")
        guard parts.count == 3, parts[1].caseInsensitiveCompare("IP") == .orderedSame
        else { return nil }
        return parts[2].replacingOccurrences(of: "_", with: ":")
    }
}

/// One block as the user made it: the `-In` / `-Out` rules the server writes as a pair,
/// collapsed into a single row the way the web console's Firewall tab shows them. The
/// server's `RemoveRule` deletes both halves whichever one is named, so listing them
/// separately gave two rows where one removal made both disappear — which reads as the
/// list failing to update rather than as one block being lifted.
///
/// Never empty: `groupedByBlock()` only creates a group around a rule it already has.
struct FirewallRuleGroup: Identifiable {
    let id: String
    let rules: [FirewallRuleInfo]

    var primary: FirewallRuleInfo { rules[0] }
    var directions: [String] { rules.compactMap { $0.direction }.filter { !$0.isEmpty } }
    var isProtected: Bool { rules.contains { $0.isProtectedRule } }
    /// A pair with one half disabled is still blocking, so On wins over Off.
    var isEnabled: Bool { rules.contains { $0.enabled == true } }
}

extension Array where Element == FirewallRuleInfo {
    /// Groups `-In` / `-Out` siblings, keeping the server's ordering.
    func groupedByBlock() -> [FirewallRuleGroup] {
        var order: [String] = []
        var byBase: [String: [FirewallRuleInfo]] = [:]
        for (index, rule) in enumerated() {
            let key = rule.baseName.isEmpty ? "rule-\(index)" : rule.baseName
            if byBase[key] == nil { order.append(key) }
            byBase[key, default: []].append(rule)
        }
        return order.compactMap { key in
            guard let rules = byBase[key], !rules.isEmpty else { return nil }
            return FirewallRuleGroup(id: key, rules: rules)
        }
    }

    /// Managed port blocks keyed `"TCP/8080"`, for cross-referencing the listening ports.
    func blockedPortKeys() -> Set<String> {
        Set(compactMap { rule in
            rule.blockedPort.map { "\($0.protocolName)/\($0.port)" }
        })
    }

    /// Addresses that currently carry a managed IP block.
    func blockedIPs() -> Set<String> {
        Set(compactMap { $0.blockedIPAddress })
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

// MARK: - Bandwidth meter (web ≥ 0.7.0)

/// How much has moved, as against `ActivityPoint`'s how many are talking. They answer
/// different questions and the app keeps them apart: one connection pulling a disk image is
/// invisible to the connection count and is the whole story here.
///
/// Every reading arrives twice — once as a number and once as the server's own formatted
/// string. The app draws with the numbers and *prints* the strings, because the server
/// settled the byte convention once (SI: 1 GB is 1,000,000,000 bytes, the convention link
/// speeds and data caps use) and a phone re-deriving it would eventually disagree with the
/// console about the same month.
struct TrafficInfo: Codable {
    let enabled: Bool?
    /// Which interfaces are counted, or why none are.
    let status: String?
    /// How much wall-clock the `live` series covers — `last 12 min`, `measuring…`,
    /// `meter off`. The series carries no timestamps, so this is the only x-axis there is.
    let window: String?
    /// Formatted current rates, or `—` before the meter has two samples to subtract.
    let inRate: String?
    let outRate: String?
    let monthLabel: String?
    let monthIn: String?
    let monthOut: String?
    let monthTotal: String?
    /// `1.2 GB per day so far` — the month divided by the days elapsed, not by the days in
    /// the month, so it reads as a running pace rather than a forecast.
    let monthDailyAverage: String?
    /// Capped at 120 samples server-side, oldest first.
    let live: [TrafficSample]?
    /// One bucket per day of the current month.
    let days: [TrafficBucket]?
    /// The last 12 calendar months.
    let months: [TrafficBucket]?

    /// Whether there is a reading to show. The meter reports `enabled` separately from
    /// having data: it is switched on the moment the setting flips, and stays empty until
    /// it has two counter samples to subtract.
    var hasReading: Bool {
        guard enabled == true else { return false }
        return !(live ?? []).isEmpty
    }
}

/// One instant of the live series. No timestamp — the samples are evenly spaced and
/// `TrafficInfo.window` says how far back they reach.
struct TrafficSample: Codable {
    let inBps: Double?
    let outBps: Double?
}

/// Bytes in and out over one span — a calendar day on the month chart, a calendar month on
/// the year chart.
struct TrafficBucket: Codable, Identifiable {
    var id: String { label }
    let label: String
    let bytesIn: Int64?
    let bytesOut: Int64?
    /// The server's formatting of the same two numbers.
    let inText: String?
    let outText: String?

    var total: Int64 { (bytesIn ?? 0) + (bytesOut ?? 0) }
}

// MARK: - Firewall configuration (web ≥ 0.7.0)

/// One rule in the firewall ledger, as the server evaluates it.
///
/// Distinct from `FirewallRuleInfo`, which is the narrower list of blocks this app and the
/// prevention engine minted. This is everything, in evaluation order — engine blocks first,
/// then the operator's own rules — so precedence is something you can see rather than infer.
/// A permissive operator rule sitting above a block is the bug this list exists to make
/// visible, and it is invisible in a set that leaves half the rules out.
struct ConfigRuleInfo: Codable, Identifiable {
    /// The rule's whole shape, hashed into one string by the server — web ≥ 0.7.4.
    ///
    /// Names are not unique across a host: two UFW rules can both be called
    /// `allow-inbound-ssh`, and once the list stopped being this app's private ledger the
    /// name stopped being able to identify a row. `delete_host_rule` takes this and nothing
    /// else, and the server refuses an ambiguous match rather than guessing which of two
    /// identical rules to remove.
    let key: String?
    /// Identity for the list. The key when the server sends one, the name on a 0.7.0–0.7.3
    /// server that has no keys — where the list *is* this app's ledger and names are unique.
    var id: String { (key?.isEmpty == false ? key : nil) ?? name }
    /// The server's own handle for the rule. Still what `remove_rule` and the `replace` field
    /// of `save_config_rule` take, but only meaningful for a rule this app wrote.
    let name: String
    /// The operator's wording, or one the server minted from the rule's own fields.
    let label: String?
    /// The console's own allow rule for its listen port. The server refuses to remove or
    /// shadow it, because doing so cuts off the request carrying the change.
    let isProtected: Bool?
    /// True for a rule the operator wrote in Firewall Config, false for one the engine minted.
    let isCustom: Bool?
    /// True for a rule read out of the kernel that this app did not write — UFW's, Docker's,
    /// WireGuard's — web ≥ 0.7.4. It can still be edited and removed, but the write goes out
    /// through whichever backend owns it, and an edit is a delete-and-rewrite rather than an
    /// edit in place.
    let isForeign: Bool?
    let inbound: Bool?
    let action: String?
    let direction: String?
    let protocolName: String?
    let ports: String?
    let addresses: String?
    /// Where the rule came from — the engine, the operator, an import.
    let origin: String?
    /// When an auto-block rule lapses. Empty on a rule that never expires.
    let expiry: String?

    enum CodingKeys: String, CodingKey {
        case name, key, label, isProtected, isCustom, isForeign, inbound, action, direction
        case protocolName = "protocol"
        case ports, addresses, origin, expiry
    }

    var isAllow: Bool { (action ?? "").caseInsensitiveCompare("Allow") == .orderedSame }
    var isProtectedRule: Bool { isProtected == true }
    /// A rule the host owns rather than this app — web ≥ 0.7.4.
    var isForeignRule: Bool { isForeign == true }

    /// Everything but the console's own allow rule can be edited on 0.7.4, where the server
    /// can write through UFW as well as its own table. On an older server the list is this
    /// app's ledger and only the operator's own rules are rewritable — an engine block there
    /// is lifted by unblocking its address, not by rewriting the rule underneath it, which
    /// would leave the engine believing it still holds a block it no longer has.
    ///
    /// `key` is the probe for which server this is: only 0.7.4 sends one.
    var isEditable: Bool {
        guard !isProtectedRule else { return false }
        return key?.isEmpty == false || isCustom == true
    }

    /// True once the server identifies rules by shape — web ≥ 0.7.4.
    ///
    /// It is the probe for the whole host-firewall API: where there is a key there is a
    /// `delete_host_rule` that takes it, and removal goes that way for *every* rule rather
    /// than only foreign ones. Which backend owns a rule is the server's decision to make —
    /// it routes ours back through its ledger and UFW's through `ufw delete` — and a name
    /// lookup from here would be the app guessing at it with a string that is not unique.
    var hasHostKey: Bool { key?.isEmpty == false }

    /// Whether port 22 falls in this rule's port list — the one removal worth naming out loud,
    /// because dropping the rule that admits SSH can end the session the host is administered
    /// over and nothing in this app can put it back.
    ///
    /// Matched as a whole number so `2222` and `1022` do not count, and a range is expanded
    /// rather than string-matched: `20-25` admits SSH and contains no literal 22.
    var matchesSSH: Bool {
        // Every port includes 22.
        if FirewallRuleDraft.isAllPorts(ports) { return true }
        let field = (ports ?? "").trimmingCharacters(in: .whitespaces)

        return field.split(separator: ",").contains { part in
            let piece = part.trimmingCharacters(in: .whitespaces)
            // `8000-8001` and `8000:8001` are both forms the server accepts.
            let bounds = piece.split(maxSplits: 1, whereSeparator: { $0 == "-" || $0 == ":" }).map {
                Int($0.trimmingCharacters(in: .whitespaces))
            }
            switch bounds.count {
            case 1: return bounds[0] == 22
            case 2:
                guard let low = bounds[0], let high = bounds[1] else { return false }
                return low <= 22 && 22 <= high
            default: return false
            }
        }
    }

    /// What the rule matches, in one line: `TCP 22 · 10.0.0.0/8`. The server spells out both
    /// unrestricted cases — `All IPv4, All IPv6` and `All ports` — and "every port" is the
    /// half worth spelling out, because a rule with no port is the one that does more than it
    /// looks like it does.
    /// The six columns the web console and the desktop grid print, each in the server's own
    /// wording. A blank cell is not the same reading as "every port" or "every address", and
    /// leaving one out is how this screen ended up showing less than the other two.
    var protocolText: String {
        let text = (protocolName ?? "").trimmingCharacters(in: .whitespaces)
        return text.isEmpty ? "Any" : text
    }

    var portsText: String {
        let text = (ports ?? "").trimmingCharacters(in: .whitespaces)
        return text.isEmpty ? "All ports" : text
    }

    var addressesText: String {
        let text = (addresses ?? "").trimmingCharacters(in: .whitespaces)
        return text.isEmpty ? "All IPv4, All IPv6" : text
    }

    /// "Sources" reads wrong on an outbound rule, where the field is the far end. Both other
    /// front-ends swap the word with the direction; so does this one.
    var addressHeading: String { (inbound ?? true) ? "Sources" : "Destinations" }

    var originText: String {
        let text = (origin ?? "").trimmingCharacters(in: .whitespaces)
        return text.isEmpty ? "—" : text
    }

    var matchSummary: String {
        var parts: [String] = []
        let proto = protocolName ?? ""
        if !proto.isEmpty && proto.caseInsensitiveCompare("Any") != .orderedSame {
            parts.append(proto)
        }
        parts.append(FirewallRuleDraft.isAllPorts(ports) ? "all ports" : ports!)
        if let addresses, !addresses.isEmpty { parts.append(addresses) }
        return parts.joined(separator: " · ")
    }

    /// The draft that opens when this rule is edited.
    var draft: FirewallRuleDraft {
        FirewallRuleDraft(
            label: label ?? "",
            action: FirewallRuleDraft.Action(serverText: action),
            direction: FirewallRuleDraft.Direction(serverText: direction, inbound: inbound),
            protocolName: FirewallRuleDraft.protocolMatching(protocolName),
            // The server's "any" placeholders are text for reading, not for typing back:
            // `All ports` sent back as a port range is a rule the server cannot parse, and
            // clearing the field is what actually means "every port" on the wire.
            ports: FirewallRuleDraft.isAllPorts(ports) ? "" : (ports ?? ""),
            addresses: FirewallRuleDraft.isAnyAddress(addresses) ? "" : (addresses ?? "")
        )
    }
}

/// A rule being composed, and the client half of the server's validation.
///
/// The server is the authority — it revalidates everything and refuses anything that would
/// cut off the console, which it can do because it knows its own listen ports and this app
/// does not. What is mirrored here is only the purely textual part, so a typo'd port range
/// is caught while the keyboard is still up instead of after a round trip.
///
/// The order matters and getting it backwards is dangerous rather than merely untidy:
/// normalising re-renders the port field from what parsed and drops what did not, so
/// `443-80` would come out as an empty port field — and an empty port field means *every
/// port*. Validate what was typed, never what was normalised. The server carries the same
/// warning over `FirewallRuleSpecs.TryPrepare`.
struct FirewallRuleDraft: Equatable {
    enum Action: String, CaseIterable, Identifiable {
        case allow = "Allow"
        case block = "Block"
        var id: String { rawValue }

        init(serverText: String?) {
            self = (serverText ?? "").caseInsensitiveCompare("Allow") == .orderedSame ? .allow : .block
        }
    }

    enum Direction: String, CaseIterable, Identifiable {
        case inbound = "Inbound"
        case outbound = "Outbound"
        var id: String { rawValue }

        /// `direction` is the display text and `inbound` the boolean; a server sends both,
        /// so prefer the text and fall back to the flag.
        init(serverText: String?, inbound: Bool?) {
            if let serverText, serverText.caseInsensitiveCompare("Outbound") == .orderedSame {
                self = .outbound
            } else if let serverText, serverText.caseInsensitiveCompare("Inbound") == .orderedSame {
                self = .inbound
            } else {
                self = (inbound ?? true) ? .inbound : .outbound
            }
        }
    }

    /// The server's list, in its order. `Any` is last because it is the widest.
    static let protocols = ["TCP", "UDP", "ICMP", "Any"]

    /// Protocol and port for a well-known service, as the web console's `RULE_PRESETS` and the
    /// desktop's `RulePresets` list them — same names, same order, so a rule written from a
    /// preset on a phone is the rule the console would have written.
    ///
    /// The desktop carries one the web console does not (the console's own ports); it is kept,
    /// because a rule about the port this app is talking over is worth being able to name.
    struct Preset: Identifiable, Equatable {
        let name: String
        let protocolName: String
        let ports: String
        var id: String { name }
    }

    static let presetCustom = "Custom"

    static let presets: [Preset] = [
        Preset(name: "SSH (22/tcp)", protocolName: "TCP", ports: "22"),
        Preset(name: "HTTP (80/tcp)", protocolName: "TCP", ports: "80"),
        Preset(name: "HTTPS (443/tcp)", protocolName: "TCP", ports: "443"),
        Preset(name: "DNS (53/udp)", protocolName: "UDP", ports: "53"),
        Preset(name: "MySQL (3306/tcp)", protocolName: "TCP", ports: "3306"),
        Preset(name: "PostgreSQL (5432/tcp)", protocolName: "TCP", ports: "5432"),
        Preset(name: "WireGuard (51820/udp)", protocolName: "UDP", ports: "51820"),
        Preset(name: "Web console (18765,18443/tcp)", protocolName: "TCP", ports: "18765, 18443"),
        Preset(name: "ICMP (ping)", protocolName: "ICMP", ports: "")
    ]

    /// The preset these values *are*, so the picker keeps saying so while the fields hold what
    /// it filled in, and drops back to Custom the moment either is typed over.
    static func presetMatching(protocolName: String, ports: String) -> String {
        let typed = ports.trimmingCharacters(in: .whitespaces)
        let match = presets.first {
            $0.protocolName.caseInsensitiveCompare(protocolName) == .orderedSame
                && $0.ports.caseInsensitiveCompare(typed) == .orderedSame
        }
        return match?.name ?? presetCustom
    }

    var label: String = ""
    var action: Action = .block
    var direction: Direction = .inbound
    var protocolName: String = "TCP"
    /// `22`, `8000-8001`, `80, 443`, or empty for every port.
    var ports: String = ""
    /// Comma-separated addresses or CIDR blocks. Empty means every address.
    var addresses: String = ""

    static func protocolMatching(_ raw: String?) -> String {
        let text = (raw ?? "").trimmingCharacters(in: .whitespaces)
        return protocols.first { $0.caseInsensitiveCompare(text) == .orderedSame } ?? "TCP"
    }

    /// The words the server treats as "every address", so the field can be left blank
    /// without the app sending back a literal `All IPv4, All IPv6` for it to re-parse.
    private static let anyAddressWords: Set<String> = [
        "", "any", "anywhere", "all", "all ipv4", "all ipv6", "all ipv4, all ipv6",
        "0.0.0.0/0", "::/0"
    ]

    static func isAnyAddress(_ raw: String?) -> Bool {
        anyAddressWords.contains((raw ?? "").trimmingCharacters(in: .whitespaces).lowercased())
    }

    /// The server's wording for an unrestricted port field. It sends `All ports` rather than
    /// an empty string, and typing that back would be read as a port named "All ports" — the
    /// same trap `isAnyAddress` exists for.
    static func isAllPorts(_ raw: String?) -> Bool {
        let text = (raw ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        return text.isEmpty || text == "all ports" || text == "any"
    }

    /// Nil when the draft is worth sending; the reason when it is not.
    var validationError: String? {
        if let error = Self.portError(ports) { return error }
        if let error = Self.addressError(addresses) { return error }

        let hasPorts = !ports.trimmingCharacters(in: .whitespaces).isEmpty
        if hasPorts && protocolName.caseInsensitiveCompare("ICMP") == .orderedSame {
            return "ICMP has no ports — clear the port range or pick TCP/UDP."
        }

        // The one shape that is always a mistake: a pass rule with no protocol, no port and
        // no address punches a hole for everything.
        if action == .allow, protocolName.caseInsensitiveCompare("Any") == .orderedSame,
           !hasPorts, Self.isAnyAddress(addresses) {
            return "An Allow rule with protocol Any, no port and no address would allow all traffic. "
                 + "Set a port, a protocol, or an address."
        }

        return nil
    }

    /// True when the rule matches every address and every port in its direction. The server
    /// refuses a *block* shaped like this outright — it would take the machine off the
    /// network, this console with it — so saying so before the round trip is the difference
    /// between a warning and a rejection.
    var isCatchAll: Bool {
        ports.trimmingCharacters(in: .whitespaces).isEmpty
            && Self.isAnyAddress(addresses)
            && protocolName.caseInsensitiveCompare("Any") == .orderedSame
    }

    private static func portError(_ raw: String) -> String? {
        let text = raw.trimmingCharacters(in: .whitespaces)
        if text.isEmpty { return nil }

        for token in text.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) })
        where !token.isEmpty {
            // `8000-8001` and `8000:8001` are the two forms the server accepts. A separator
            // at either end (`-80`) splits to a single valid-looking bound, so it has to be
            // refused before the split rather than after it.
            let isSeparator: (Character) -> Bool = { $0 == "-" || $0 == ":" }
            guard let first = token.first, let last = token.last,
                  !isSeparator(first), !isSeparator(last)
            else { return "Invalid port: \(token)" }

            let bounds = token.split(whereSeparator: isSeparator)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            guard bounds.count <= 2, !bounds.isEmpty,
                  bounds.allSatisfy({ !$0.isEmpty && $0.count <= 5 && $0.allSatisfy(\.isNumber) })
            else { return "Invalid port: \(token)" }

            let numbers = bounds.compactMap { Int($0) }
            guard numbers.count == bounds.count, numbers.allSatisfy({ (1...65535).contains($0) })
            else { return "Port out of range: \(token)" }
            if numbers.count == 2, numbers[0] > numbers[1] {
                return "Port range starts after it ends: \(token)"
            }
        }
        return nil
    }

    private static func addressError(_ raw: String) -> String? {
        if isAnyAddress(raw) { return nil }

        for token in raw.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) })
        where !token.isEmpty {
            if anyAddressWords.contains(token.lowercased()) { continue }

            guard token.contains("/") else {
                // `IPScope` already parses both families the way the server does, down to
                // the IPv4-mapped IPv6 form. Reusing it keeps one address parser in the app.
                if IPScope.of(token) == .notAnAddress { return "Invalid address: \(token)" }
                continue
            }

            let parts = token.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { return "Invalid network: \(token)" }
            let address = parts[0].trimmingCharacters(in: .whitespaces)
            guard IPScope.of(address) != .notAnAddress,
                  let prefix = Int(parts[1].trimmingCharacters(in: .whitespaces)),
                  prefix >= 0, prefix <= (address.contains(":") ? 128 : 32)
            else { return "Invalid network: \(token)" }
        }
        return nil
    }
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
