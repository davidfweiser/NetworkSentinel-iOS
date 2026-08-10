import Foundation
import UserNotifications

/// Local notifications + dedupe for new Critical threats.
@MainActor
final class CriticalAlertService {
    static let shared = CriticalAlertService()

    private let defaultsKey = "networksentinel.seenCriticalThreatIds"
    private let knownServersKey = "networksentinel.primedServerIds"

    /// Threats already notified about, kept across launches. `seenOrder` is the same set
    /// in insertion order so trimming drops the oldest rather than an arbitrary 500.
    private var seenIds: Set<String>
    private var seenOrder: [String]
    /// Servers a first snapshot has already been taken of, kept across launches. A server
    /// listed here has history, so a cold start catches up on it instead of going quiet.
    private var knownServers: Set<String>
    /// Servers primed during this launch — the once-per-launch guard.
    private var primedThisLaunch: Set<String> = []

    /// How far back a cold start replays Criticals it never notified about. Long enough to
    /// cover a night asleep, short enough that opening the app after a week does not
    /// resurrect a stale incident as a fresh warning.
    private let catchUpWindow: TimeInterval = 24 * 60 * 60
    private let maxSeenIds = 500

    var notificationsAuthorized = false

    private init() {
        let defaults = UserDefaults.standard
        seenOrder = defaults.array(forKey: defaultsKey) as? [String] ?? []
        seenIds = Set(seenOrder)
        knownServers = Set(defaults.array(forKey: knownServersKey) as? [String] ?? [])
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

    /// First snapshot of a server this launch — decide what counts as history.
    ///
    /// First contact with a server: everything it already lists is backlog, and none of it
    /// is worth a notification. Every launch after that: a Critical this app never saw
    /// (it landed while the app was force-quit, or between background wake-ups) still
    /// alerts, provided it is recent. Older ones are marked seen quietly.
    func prime(serverId: UUID, threats: [ThreatInfo], now: Date = .now) {
        let key = serverId.uuidString
        guard !primedThisLaunch.contains(key) else { return }
        primedThisLaunch.insert(key)

        let firstContact = !knownServers.contains(key)
        for t in criticalThreats(from: threats) where firstContact || !isRecent(t, now: now) {
            markSeen(threatKey(serverId: serverId, threat: t))
        }
        knownServers.insert(key)
        persist()
    }

    /// Returns newly seen critical threats (not previously notified).
    func newCriticalThreats(serverId: UUID, threats: [ThreatInfo]) -> [ThreatInfo] {
        prime(serverId: serverId, threats: threats)

        var fresh: [ThreatInfo] = []
        for t in criticalThreats(from: threats) {
            let id = threatKey(serverId: serverId, threat: t)
            if !seenIds.contains(id) {
                markSeen(id)
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
            // Web 0.6.3+ leads with the verdict, and a lock screen is exactly where it
            // earns its place: this is the one moment the console is not in front of you,
            // so a warning that names an address without saying whether anything stopped
            // it is a question you have to go and answer under pressure.
            let verdict = t.blockVerdict
            content.title = verdict.map { "\($0.alertPrefix) · Critical — \(serverName)" }
                ?? "Critical — \(serverName)"
            // Host-local detectors (0.4+) report loopback rather than a peer; the threat
            // type says far more on a lock screen than "127.0.0.1" does.
            content.subtitle = t.isBlockable ? t.sourceIp : (t.type ?? t.sourceIp)
            content.body = t.title
            if let detail = t.detail, !detail.isEmpty {
                content.body = "\(t.title)\n\(detail)"
            }
            // The gate that stopped it, or the rule now in force — the server's own words.
            if verdict != nil, let status = t.blockStatus, !status.isEmpty {
                content.body = "\(content.body)\n\(status)"
            }
            content.sound = .default
            content.interruptionLevel = .timeSensitive
            content.userInfo = [
                "sourceIp": t.sourceIp,
                "title": t.title,
                "blocked": t.blocked ?? false
            ]

            let request = UNNotificationRequest(
                identifier: "critical-\(UUID().uuidString)-\(index)",
                content: content,
                trigger: nil // deliver immediately
            )
            center.add(request)
        }

        let overflow = threats.dropFirst(5)
        if !overflow.isEmpty {
            let content = UNMutableNotificationContent()
            content.title = "Critical — \(serverName)"
            content.body = "+\(overflow.count) more critical alerts"
            // The same tally the server puts on a multi-threat popup. Counted over the
            // ones that named a blockable address: "2 of 3" is only meaningful against
            // the threats blocking could ever have applied to.
            let known = overflow.filter { $0.blockVerdict != nil }
            if !known.isEmpty {
                let n = known.filter { $0.blockVerdict?.isBlocked == true }.count
                content.body += n == known.count
                    ? " — all blocked"
                    : " — \(n) of \(known.count) blocked"
            }
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
        primedThisLaunch.remove(serverId.uuidString)
    }

    private func criticalThreats(from threats: [ThreatInfo]) -> [ThreatInfo] {
        threats.filter {
            ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .critical
        }
    }

    /// Whether a threat is recent enough for a cold start to still warn about it.
    /// `ts` arrived in web 0.3.5; older servers send only `time` (`HH:mm:ss`), which
    /// carries no date, so age is unknowable there and the quiet path wins.
    private func isRecent(_ threat: ThreatInfo, now: Date) -> Bool {
        guard let ts = threat.ts, let at = Self.parseTimestamp(ts) else { return false }
        return now.timeIntervalSince(at) <= catchUpWindow
    }

    /// Parses the server's ISO-8601 `ts`. .NET's round-trip format carries 7 fractional
    /// digits — more than ISO8601DateFormatter accepts — so retry against a 3-digit form.
    static func parseTimestamp(_ raw: String) -> Date? {
        if let d = isoWithFraction.date(from: raw) { return d }
        if let d = isoPlain.date(from: raw) { return d }

        // 2026-07-30T18:28:14.1234567-05:00 → 2026-07-30T18:28:14.123-05:00
        guard let dot = raw.firstIndex(of: ".") else { return nil }
        let afterDot = raw[raw.index(after: dot)...]
        guard let endOfDigits = afterDot.firstIndex(where: { !$0.isNumber }) else { return nil }
        let trimmed = String(raw[..<dot])
            + "."
            + String(afterDot[..<endOfDigits].prefix(3))
            + String(afterDot[endOfDigits...])
        return isoWithFraction.date(from: trimmed)
    }

    private static let isoWithFraction: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let isoPlain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    private func threatKey(serverId: UUID, threat: ThreatInfo) -> String {
        "\(serverId.uuidString)|\(threat.id)"
    }

    private func markSeen(_ id: String) {
        guard seenIds.insert(id).inserted else { return }
        seenOrder.append(id)
    }

    private func persist() {
        // Cap stored IDs so UserDefaults does not grow forever. Evicting the oldest keeps
        // recent threats reliably deduped — dropping arbitrary ones would let a Critical
        // that is still on the server's list alert a second time.
        if seenOrder.count > maxSeenIds {
            let excess = seenOrder.count - maxSeenIds
            seenIds.subtract(seenOrder.prefix(excess))
            seenOrder.removeFirst(excess)
        }
        let defaults = UserDefaults.standard
        defaults.set(seenOrder, forKey: defaultsKey)
        defaults.set(Array(knownServers), forKey: knownServersKey)
    }
}
