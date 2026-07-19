import Foundation
import UserNotifications

/// Local notifications + dedupe for new Critical threats.
@MainActor
final class CriticalAlertService {
    static let shared = CriticalAlertService()

    private let defaultsKey = "networksentinel.seenCriticalThreatIds"
    private var seenIds: Set<String>
    private var primedServers: Set<String> = []

    var notificationsAuthorized = false

    private init() {
        if let arr = UserDefaults.standard.array(forKey: defaultsKey) as? [String] {
            seenIds = Set(arr)
        } else {
            seenIds = []
        }
    }

    func requestPermission() async {
        let center = UNUserNotificationCenter.current()
        do {
            let granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
            notificationsAuthorized = granted
        } catch {
            notificationsAuthorized = false
        }
        let settings = await center.notificationSettings()
        notificationsAuthorized = settings.authorizationStatus == .authorized
            || settings.authorizationStatus == .provisional
    }

    /// First snapshot for a server: mark existing criticals as seen (no spam).
    func prime(serverId: UUID, threats: [ThreatInfo]) {
        let key = serverId.uuidString
        guard !primedServers.contains(key) else { return }
        primedServers.insert(key)
        for t in criticalThreats(from: threats) {
            seenIds.insert(threatKey(serverId: serverId, threat: t))
        }
        persist()
    }

    /// Returns newly seen critical threats (not previously notified).
    func newCriticalThreats(serverId: UUID, threats: [ThreatInfo]) -> [ThreatInfo] {
        prime(serverId: serverId, threats: threats)

        var fresh: [ThreatInfo] = []
        for t in criticalThreats(from: threats) {
            let id = threatKey(serverId: serverId, threat: t)
            if !seenIds.contains(id) {
                seenIds.insert(id)
                fresh.append(t)
            }
        }
        if !fresh.isEmpty {
            persist()
        }
        return fresh
    }

    func notify(serverName: String, threats: [ThreatInfo]) {
        guard notificationsAuthorized, !threats.isEmpty else { return }

        let center = UNUserNotificationCenter.current()
        for (index, t) in threats.prefix(5).enumerated() {
            let content = UNMutableNotificationContent()
            content.title = "Critical — \(serverName)"
            content.subtitle = t.sourceIp
            content.body = t.title
            if let detail = t.detail, !detail.isEmpty {
                content.body = "\(t.title)\n\(detail)"
            }
            content.sound = .default
            content.interruptionLevel = .timeSensitive
            content.userInfo = [
                "sourceIp": t.sourceIp,
                "title": t.title
            ]

            let request = UNNotificationRequest(
                identifier: "critical-\(UUID().uuidString)-\(index)",
                content: content,
                trigger: nil // deliver immediately
            )
            center.add(request)
        }

        if threats.count > 5 {
            let content = UNMutableNotificationContent()
            content.title = "Critical — \(serverName)"
            content.body = "+\(threats.count - 5) more critical alerts"
            content.sound = .default
            content.interruptionLevel = .timeSensitive
            center.add(UNNotificationRequest(
                identifier: "critical-more-\(UUID().uuidString)",
                content: content,
                trigger: nil
            ))
        }
    }

    func resetPrime(for serverId: UUID) {
        primedServers.remove(serverId.uuidString)
    }

    private func criticalThreats(from threats: [ThreatInfo]) -> [ThreatInfo] {
        threats.filter {
            ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .critical
        }
    }

    private func threatKey(serverId: UUID, threat: ThreatInfo) -> String {
        "\(serverId.uuidString)|\(threat.id)"
    }

    private func persist() {
        // Cap stored IDs so UserDefaults does not grow forever
        let trimmed = Array(seenIds.suffix(500))
        seenIds = Set(trimmed)
        UserDefaults.standard.set(trimmed, forKey: defaultsKey)
    }
}
