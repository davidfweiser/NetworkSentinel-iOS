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
    let isMonitoring: Bool?
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
