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
    var id: String { "\(protocolName)-\(local)-\(remote)-\(pid ?? 0)" }
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
    var id: String { "\(time)-\(sourceIp)-\(title)-\(level)" }
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
    var id: String { "\(protocolName)-\(port)-\(pid ?? 0)" }
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
    var id: String { "\(name)-\(target)-\(direction)" }
    let name: String
    let kind: String?
    let target: String
    let direction: String?
    let protocolName: String?
    let enabled: Bool?
    let action: String?
    let description: String?

    enum CodingKeys: String, CodingKey {
        case name, kind, target, direction
        case protocolName = "protocol"
        case enabled, action, description
    }
}

struct AllowlistEntry: Codable, Identifiable {
    var id: String { "\(kind)-\(value)" }
    let kind: String
    let value: String
    let detail: String?
}

struct ActivityPoint: Codable, Identifiable {
    var id: String { time }
    let time: String
    let connections: Int?
    let threats: Int?
    let hosts: Int?
}

struct ActionResponse: Codable {
    let ok: Bool
    let message: String?
}

// MARK: - Threat helpers

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
