import BackgroundTasks
import Foundation
import Observation
import SwiftUI
import UIKit

/// High-level UI gate for master-password auth.
enum AuthPhase: Equatable {
    /// Checking server reachability / whether password is configured.
    case checking
    /// First-time server: create master password.
    case setup
    /// Master password required before any data is shown.
    case login
    /// Session valid — main app.
    case authenticated
    /// Server unreachable or other error before auth.
    case unreachable(String)
}

@MainActor
@Observable
final class AppModel {
    let store = ServerStore()
    private let api = APIClient()

    var state: ServerState?
    /// The firewall scan from `/api/hostfirewall`, on servers that keep it off `/api/state`.
    /// Nil until something asks for it — it is never part of the poll.
    var hostScan: HostFirewallScan?
    /// True once the server has answered 404: it has no separate scan endpoint, so whatever
    /// `/api/state` carries is all there is.
    var hostScanUnsupported = false
    var hostScanLoading = false
    /// Why the scan could not be read, kept apart from `lastError` so a slow `netsh` does not
    /// raise a banner over the whole app.
    var hostScanError: String?
    /// The filtering resolver's refusals — `GET /api/dns-blocked`, read on demand. Kept here
    /// rather than in the view so the rail's badge and the screen read the same list, and so
    /// switching server clears it with everything else.
    var dnsBlocked: [DnsBlockedEntry] = []
    /// The server's own sentence about that read: how many, or why there are none. Shown
    /// verbatim — "the query log is switched off in AdGuard" is a diagnosis the app cannot
    /// make for itself.
    var dnsBlockedMessage: String?
    /// False when the server answered `ok: false` — a resolver that is unreachable, refusing
    /// the credentials, or answering something unparseable.
    var dnsBlockedOk = true
    var dnsBlockedLoading = false
    /// True once the route has answered 404: this console predates Blocked Sites.
    var dnsBlockedUnsupported = false
    /// How many refusals to ask for. The console offers exactly these four.
    var dnsBlockedLimit = 100
    static let dnsBlockedLimits = [50, 100, 250, 500]

    var isLoading = false
    var isRefreshing = false
    var lastError: String?
    var statusBanner: String?
    /// Back-compat flags used by AuthView copy.
    var needsAuth = false
    var needsSetup = false
    var isAuthenticated = false
    /// Primary gate for RootView — never show dashboard until `.authenticated`.
    var authPhase: AuthPhase = .checking
    var pollTask: Task<Void, Never>?
    var pollInterval: TimeInterval = 2.5
    /// When true, try Keychain password once after status check.
    var allowAutoLogin = true
    /// In-app critical alert (popup) awaiting user acknowledgment.
    var pendingCriticalAlert: CriticalAlertPayload?
    /// Holds the in-app Critical banner back until this time. Acting on a threat means the
    /// user is already working the list; the poll right after a block reliably turns up the
    /// next unseen Critical, and letting it slam a banner over the confirmation reads as
    /// "your block did nothing". Notifications and the Dashboard attention card are
    /// unaffected — only the banner waits its turn.
    private var criticalBannerQuietUntil: Date?
    /// Long enough to cover the action's own refresh and read the result, short enough that
    /// a genuinely new incident is not sat on.
    private let criticalBannerCooldown: TimeInterval = 20
    /// User preference: local notifications + in-app popups for Critical threats.
    /// Device-only — the server's own `criticalAlertsEnabled` (web ≥ 0.3.5) is separate.
    var criticalAlertsEnabled: Bool {
        get { UserDefaults.standard.object(forKey: "networksentinel.criticalAlerts") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "networksentinel.criticalAlerts") }
    }
    /// True when app is in foreground (for choosing popup vs notification emphasis).
    var isAppActive = true
    /// Extended background execution after leaving the app (minutes, not continuous).
    private var uiBackgroundTask: UIBackgroundTaskIdentifier = .invalid
    /// Last time a system background poll finished (for UI).
    var lastBackgroundPollAt: Date?

    /// Servers this phone has put to sleep, by id.
    ///
    /// The server reports one `isMonitoring` flag and treats `sleep` and `pause` as the
    /// same call, so which of the two stopped it is only knowable here. Persisted: coming
    /// back from a relaunch polling a console you deliberately parked would undo the point.
    private(set) var sleepingServerIds: Set<UUID> = []
    private static let sleepingKey = "networksentinel.sleepingServers"

    /// Foreground poll while awake — the console's **Page refresh speed**, which is a
    /// per-client setting there (it lives in that browser's storage, not on the server) and
    /// so is a per-device one here. Persisted: a phone on a metered connection should not
    /// have to re-choose ten seconds every launch.
    var awakePollInterval: TimeInterval = 2.5 {
        didSet {
            guard awakePollInterval != oldValue else { return }
            UserDefaults.standard.set(awakePollInterval, forKey: Self.pollIntervalKey)
            guard !isAsleep else { return }
            pollInterval = awakePollInterval
            if pollTask != nil { restartPolling() }
        }
    }
    private static let pollIntervalKey = "networksentinel.pollInterval"
    /// The four the console offers, and the only values the picker will write.
    static let pollIntervalChoices: [TimeInterval] = [1, 2.5, 5, 10]
    /// Foreground poll while asleep. A sleeping server observes nothing, so there is no new
    /// data to draw — but the heartbeat has to stay, or a wake from the web console or
    /// another device would never reach this phone. Same 30s the web console drops to.
    private let sleepPollInterval: TimeInterval = 30

    var server: ServerProfile? { store.selectedServer }

    init() {
        let stored = UserDefaults.standard.stringArray(forKey: Self.sleepingKey) ?? []
        sleepingServerIds = Set(stored.compactMap(UUID.init(uuidString:)))
        // `object(forKey:)` rather than `double(forKey:)`: an unset key reads as 0, which
        // would be a poll loop with no sleep in it at all.
        if let saved = UserDefaults.standard.object(forKey: Self.pollIntervalKey) as? Double,
           Self.pollIntervalChoices.contains(saved) {
            awakePollInterval = saved
            pollInterval = saved
        }
    }

    // MARK: - Derived state for the UI

    /// True when this phone has the selected server asleep.
    var isAsleep: Bool {
        guard let server else { return false }
        return sleepingServerIds.contains(server.id)
    }

    func isAsleep(_ server: ServerProfile) -> Bool { sleepingServerIds.contains(server.id) }

    private func setSleeping(_ asleep: Bool, for id: UUID) {
        if asleep {
            sleepingServerIds.insert(id)
        } else {
            sleepingServerIds.remove(id)
        }
        UserDefaults.standard.set(sleepingServerIds.map(\.uuidString), forKey: Self.sleepingKey)
    }

    /// Highest severity the server is currently reporting. Drives the app's tint and the
    /// ambient background, so the whole surface reads as calm or alarmed at a glance.
    var liveSeverity: ThreatSeverity {
        // Asleep, every threat still on screen is history — the server stopped watching.
        // Pulsing the whole app red over it would read as a live incident.
        guard !isAsleep else { return .none }
        return (state?.threats ?? []).reduce(ThreatSeverity.none) {
            Swift.max($0, ThreatSeverity.from(level: $1.level, levelNum: $1.levelNum))
        }
    }

    /// Current connections as a share of the window's peak, 0…1.
    var activityLoad: Double {
        let values = (state?.activity ?? []).map { $0.connections ?? 0 }
        guard let peak = values.max(), peak > 0, let now = values.last else { return 0 }
        return min(Double(now) / Double(peak), 1)
    }

    /// The one thing most worth acting on right now, if anything is. Newest High+ threat.
    var attentionThreat: ThreatInfo? {
        (state?.threats ?? []).first {
            ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .high
        }
    }

    /// How many other High+ threats are queued behind `attentionThreat`.
    var attentionBacklog: Int {
        let n = (state?.threats ?? []).count {
            ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .high
        }
        return max(0, n - 1)
    }

    // MARK: - Lifecycle

    func onAppear() {
        evaluateInitialAuthGate()
        startPolling()
        BackgroundRefresh.schedule()
        Task {
            await CriticalAlertService.shared.requestPermission()
        }
    }

    func onDisappear() {
        // Do not stop polling here — sheets can trigger disappear.
        // Scene phase controls background behavior.
    }

    /// Foreground / background transitions from SwiftUI scenePhase.
    func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .active:
            isAppActive = true
            endUIBackgroundTask()
            if pollTask == nil { startPolling() }
            BackgroundRefresh.schedule()
            Task { await CriticalAlertService.shared.requestPermission() }
        case .inactive:
            isAppActive = false
        case .background:
            isAppActive = false
            beginUIBackgroundTask()
            BackgroundRefresh.schedule(earliest: 15 * 60)
            // Keep a few more poll cycles while iOS still allows background time.
            if pollTask == nil { startPolling() }
        @unknown default:
            break
        }
    }

    private func beginUIBackgroundTask() {
        endUIBackgroundTask()
        uiBackgroundTask = UIApplication.shared.beginBackgroundTask(withName: "NetworkSentinelPoll") { [weak self] in
            // Delivered on the main thread at the deadline. The task must be ended
            // before this handler returns — deferring to a queued Task risks the
            // watchdog killing the app first.
            MainActor.assumeIsolated {
                self?.stopPolling()
                self?.endUIBackgroundTask()
            }
        }
    }

    private func endUIBackgroundTask() {
        guard uiBackgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(uiBackgroundTask)
        uiBackgroundTask = .invalid
    }

    // MARK: - Background poll (all servers → Critical notifications)

    /// Called by BGAppRefreshTask. Polls every saved server that has a session or remembered password.
    func handleBackgroundRefresh(_ task: BGAppRefreshTask) async {
        BackgroundRefresh.schedule(earliest: 15 * 60)

        let work = Task { @MainActor in
            await self.pollAllServersForAlerts()
        }
        task.expirationHandler = {
            work.cancel()
        }
        _ = await work.result
        lastBackgroundPollAt = .now
        task.setTaskCompleted(success: !work.isCancelled)
    }

    /// Poll all configured servers for Critical threats (notifications only).
    func pollAllServersForAlerts() async {
        guard criticalAlertsEnabled else { return }
        await CriticalAlertService.shared.requestPermission()

        for server in store.servers {
            if Task.isCancelled { break }
            await pollServerForAlerts(server)
        }
    }

    private func pollServerForAlerts(_ server: ServerProfile) async {
        do {
            let (hasSession, token) = try await ensureBackgroundSession(for: server)
            guard hasSession else { return }
            let s = try await api.fetchState(baseURL: server.baseURL, token: token)

            // Update live UI only for the selected server.
            if store.selectedServerId == server.id || store.selectedServer?.id == server.id {
                if isAppActive {
                    applyState(s, server: server)
                } else {
                    state = s
                    processCriticalThreats(from: s, server: server)
                }
            } else {
                processCriticalThreats(from: s, server: server)
            }
        } catch {
            // Best-effort background poll; ignore per-server failures.
        }
    }

    /// Makes sure a session usable for `fetchState` exists, logging in with the remembered
    /// password if needed. The token is nil for a cookie-only login — same-process requests
    /// still work through the jar, so `hasSession` is the flag that matters.
    private func ensureBackgroundSession(
        for server: ServerProfile
    ) async throws -> (hasSession: Bool, token: String?) {
        if let token = store.sessionToken(for: server.id) {
            return (true, token)
        }
        guard let password = store.rememberedPassword(for: server.id) else {
            return (false, nil)
        }
        let (resp, token) = try await api.login(baseURL: server.baseURL, password: password)
        guard resp.ok else { return (false, nil) }
        if let token {
            store.setSessionToken(token, for: server.id)
        }
        return (true, token)
    }

    /// Immediately require master password unless we already have a stored session token
    /// (still validated on next refresh). Never open the main UI optimistically.
    private func evaluateInitialAuthGate() {
        evaluateAuthAfterServerChange()
    }

    /// Call after add / edit / select / delete so UI re-gates on master password correctly.
    func evaluateAuthAfterServerChange() {
        state = nil
        lastError = nil
        isAuthenticated = false
        pendingCriticalAlert = nil
        // The scan is per-server state: carrying it across a switch would show one
        // machine's firewall under another's name, and a stale `hostScanUnsupported`
        // would suppress the fetch on a server that does have the endpoint.
        hostScan = nil
        hostScanUnsupported = false
        hostScanError = nil
        // Same reasoning for the resolver's refusals: they belong to one console's resolver,
        // and `dnsBlockedUnsupported` carried across would hide the page on a server that has it.
        dnsBlocked = []
        dnsBlockedMessage = nil
        dnsBlockedOk = true
        dnsBlockedUnsupported = false
        guard let server else {
            authPhase = .checking
            needsAuth = false
            needsSetup = false
            return
        }
        CriticalAlertService.shared.resetPrime(for: server.id)
        if store.sessionToken(for: server.id) != nil {
            authPhase = .checking
            needsAuth = false
            needsSetup = false
        } else {
            // Assume login until status proves setup or we authenticate.
            authPhase = .login
            needsAuth = true
            needsSetup = false
        }
        allowAutoLogin = true
    }

    func selectServer(_ id: UUID) {
        store.select(id)
        state = nil
        lastError = nil
        isAuthenticated = false
        needsAuth = false
        needsSetup = false
        pendingCriticalAlert = nil
        allowAutoLogin = true
        evaluateInitialAuthGate()
        // Sleep is per-server: switching to a parked console must not keep the 2.5s poll.
        pollInterval = isAsleep ? sleepPollInterval : awakePollInterval
        restartPolling()
    }

    func dismissCriticalAlert() {
        pendingCriticalAlert = nil
    }

    private var isCriticalBannerQuiet: Bool {
        guard let until = criticalBannerQuietUntil else { return false }
        return Date.now < until
    }

    /// Apply server state and fire critical alerts for new Critical threats.
    func applyState(_ s: ServerState, server: ServerProfile) {
        state = s
        isAuthenticated = true
        needsAuth = false
        needsSetup = false
        authPhase = .authenticated
        lastError = nil
        store.markConnected(server.id)
        // A console can be woken from the web UI, another device, or a service restart —
        // sleep is runtime state the server does not persist. Monitoring running again is
        // the only proof that matters, so it clears the flag wherever the wake came from.
        if s.settings?.isMonitoring == true || s.stats?.isMonitoring == true {
            setSleeping(false, for: server.id)
        }
        syncSleepMode()
        processCriticalThreats(from: s, server: server)
    }

    private func processCriticalThreats(from s: ServerState, server: ServerProfile) {
        guard criticalAlertsEnabled else { return }
        // A sleeping console detects nothing, so whatever is still in its list is history.
        // Alerting on it would make Sleep a source of alarms instead of quiet.
        guard !isAsleep(server) else { return }
        let threats = s.threats ?? []
        let fresh = CriticalAlertService.shared.newCriticalThreats(
            serverId: server.id,
            threats: threats
        )
        guard !fresh.isEmpty else { return }

        // Always post a system notification (banner when backgrounded / locked).
        CriticalAlertService.shared.notify(serverName: server.name, threats: fresh)

        // In-app popup while using the app (queue first new critical).
        if isAppActive, !isCriticalBannerQuiet {
            let t = fresh[0]
            pendingCriticalAlert = CriticalAlertPayload(
                serverName: server.name,
                threat: t,
                extraCount: max(0, fresh.count - 1)
            )
        }
    }

    // MARK: - Polling

    func startPolling() {
        stopPolling()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh(silent: true)
                let interval = self?.pollInterval ?? 2.5
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func restartPolling() {
        startPolling()
    }

    /// Match the poll rate to the console's state. Every state update funnels through
    /// `applyState`, so this is also where the app learns it is asleep — including a sleep
    /// triggered from the web console or a second device.
    private func syncSleepMode() {
        let wanted = isAsleep ? sleepPollInterval : awakePollInterval
        guard pollInterval != wanted else { return }
        pollInterval = wanted
        // The loop is already sleeping for the old interval; restart so the new rate takes
        // effect now rather than up to 30 seconds late.
        if pollTask != nil { restartPolling() }
    }

    // MARK: - Refresh / auth

    func refresh(silent: Bool = false) async {
        guard let server else {
            state = nil
            isAuthenticated = false
            authPhase = .checking
            return
        }

        // While waiting for the user to type a password, only probe auth status
        // (do not spam /api/state with 401s).
        if case .login = authPhase, store.sessionToken(for: server.id) == nil {
            await probeAuthStatus(server: server, silent: silent)
            return
        }
        if case .setup = authPhase {
            await probeAuthStatus(server: server, silent: silent)
            return
        }

        if !silent {
            isLoading = true
        } else {
            isRefreshing = true
        }
        defer {
            isLoading = false
            isRefreshing = false
        }

        do {
            let token = store.sessionToken(for: server.id)

            // Prefer stored Bearer token; otherwise cookie jar from this process's login.
            let s = try await api.fetchState(baseURL: server.baseURL, token: token)
            applyState(s, server: server)
        } catch APIError.unauthorized(let msg) {
            store.setSessionToken(nil, for: server.id)
            isAuthenticated = false
            state = nil
            needsAuth = true
            needsSetup = false
            authPhase = .login

            if allowAutoLogin, let pw = store.rememberedPassword(for: server.id) {
                do {
                    try await performLogin(password: pw, remember: true)
                } catch {
                    allowAutoLogin = false
                    lastError = msg ?? error.localizedDescription
                }
            } else {
                lastError = msg ?? "Master password required."
            }
        } catch {
            // Keep authenticated UI if we already have data; otherwise surface error.
            if !isAuthenticated {
                authPhase = .unreachable(error.localizedDescription)
            }
            lastError = error.localizedDescription
        }
    }

    /// Reach server and decide setup vs login vs session still valid.
    private func probeAuthStatus(server: ServerProfile, silent: Bool) async {
        if !silent { isLoading = true }
        defer { if !silent { isLoading = false } }

        do {
            let token = store.sessionToken(for: server.id)
            let status = try await api.authStatus(baseURL: server.baseURL, token: token)

            if status.authenticated {
                // Session cookie or Bearer still valid — pull protected state.
                needsAuth = false
                needsSetup = false
                lastError = nil
                do {
                    let s = try await api.fetchState(baseURL: server.baseURL, token: token)
                    applyState(s, server: server)
                } catch APIError.unauthorized {
                    store.setSessionToken(nil, for: server.id)
                    isAuthenticated = false
                    authPhase = .login
                    needsAuth = true
                }
                return
            }

            if !status.configured {
                needsSetup = true
                needsAuth = false
                isAuthenticated = false
                authPhase = .setup
                lastError = nil
                return
            }

            // Configured master password — user must sign in (or auto-login once).
            needsSetup = false
            needsAuth = true
            isAuthenticated = false
            authPhase = .login

            if allowAutoLogin, let pw = store.rememberedPassword(for: server.id) {
                do {
                    try await performLogin(password: pw, remember: true)
                } catch {
                    allowAutoLogin = false
                    lastError = error.localizedDescription
                }
            } else {
                lastError = nil
            }
        } catch APIError.unauthorized {
            store.setSessionToken(nil, for: server.id)
            needsAuth = true
            needsSetup = false
            isAuthenticated = false
            authPhase = .login
        } catch {
            // If we were mid-login, keep the password form; show connection error.
            if authPhase != .login && authPhase != .setup {
                authPhase = .unreachable(error.localizedDescription)
            }
            lastError = error.localizedDescription
        }
    }

    func performLogin(password: String, remember: Bool) async throws {
        guard let server else { throw APIError.invalidURL }
        let (resp, token) = try await api.login(baseURL: server.baseURL, password: password)
        guard resp.ok else {
            throw APIError.serverMessage(resp.message ?? "Incorrect master password.")
        }

        if let token {
            store.setSessionToken(token, for: server.id)
        }
        if remember {
            store.setRememberedPassword(password, for: server.id)
        } else {
            store.setRememberedPassword(nil, for: server.id)
        }

        // Verify session can read protected data (Bearer and/or cookie jar).
        let s = try await api.fetchState(
            baseURL: server.baseURL,
            token: store.sessionToken(for: server.id) ?? token
        )
        allowAutoLogin = true
        applyState(s, server: server)
    }

    func performSetup(password: String, confirm: String, remember: Bool) async throws {
        guard let server else { throw APIError.invalidURL }
        let (resp, token) = try await api.setup(baseURL: server.baseURL, password: password, confirm: confirm)
        guard resp.ok else {
            throw APIError.serverMessage(resp.message ?? "Setup failed")
        }

        if let token {
            store.setSessionToken(token, for: server.id)
        }
        store.setRememberedPassword(remember ? password : nil, for: server.id)

        let s = try await api.fetchState(
            baseURL: server.baseURL,
            token: store.sessionToken(for: server.id) ?? token
        )
        applyState(s, server: server)
    }

    /// Change the server's master password (web ≥ 0.3.3).
    /// The server keeps this session and revokes all others, so we stay signed in —
    /// but a remembered password would go stale and break background auto-login, so
    /// re-store it here whenever one exists.
    func changeMasterPassword(current: String, new: String, confirm: String) async throws {
        guard let server else { throw APIError.invalidURL }
        let resp = try await api.changePassword(
            baseURL: server.baseURL,
            token: store.sessionToken(for: server.id),
            current: current,
            new: new,
            confirm: confirm
        )
        if store.rememberedPassword(for: server.id) != nil {
            store.setRememberedPassword(new, for: server.id)
        }
        statusBanner = resp.message ?? "Master password updated."
        await refresh(silent: true)
    }

    func logout() async {
        guard let server else { return }
        let token = store.sessionToken(for: server.id)
        try? await api.logout(baseURL: server.baseURL, token: token)
        store.setSessionToken(nil, for: server.id)
        store.setRememberedPassword(nil, for: server.id)
        isAuthenticated = false
        needsAuth = true
        needsSetup = false
        authPhase = .login
        allowAutoLogin = false
        state = nil
        lastError = nil
    }

    // MARK: - Actions

    /// Actions taken *at* a threat, from the Critical banner or the attention card. These
    /// start the banner cooldown; a settings toggle or an allowlist refresh does not.
    private static let threatActions: Set<String> = ["block", "unblock", "clear_threats"]

    @discardableResult
    func runAction(
        _ action: String,
        ip: String? = nil,
        value: String? = nil,
        kind: String? = nil,
        fieldName: String? = nil,
        direction: String? = nil,
        rule: FirewallRuleDraft? = nil,
        replacing: String? = nil,
        ruleKey: String? = nil
    ) async -> Bool {
        guard let resp = await sendAction(
            action,
            ip: ip,
            value: value,
            kind: kind,
            fieldName: fieldName,
            direction: direction,
            rule: rule,
            replacing: replacing,
            ruleKey: ruleKey
        ) else { return false }
        return await applyActionResult(resp)
    }

    /// Raw `/api/action` call. Returns the server's reply, or nil when the request itself
    /// failed — auth and transport errors are already reported to the UI here. Kept
    /// separate from `applyActionResult` so a caller can look at the reply before it turns
    /// into a banner, which is what the sleep/wake fallback needs.
    private func sendAction(
        _ action: String,
        ip: String? = nil,
        value: String? = nil,
        kind: String? = nil,
        fieldName: String? = nil,
        direction: String? = nil,
        rule: FirewallRuleDraft? = nil,
        replacing: String? = nil,
        ruleKey: String? = nil
    ) async -> ActionResponse? {
        guard let server else { return nil }
        // Set before the request, not after: a successful action refreshes, and that
        // refresh is the one most likely to surface the next Critical.
        if Self.threatActions.contains(action) {
            criticalBannerQuietUntil = .now + criticalBannerCooldown
        }
        do {
            return try await api.action(
                baseURL: server.baseURL,
                token: store.sessionToken(for: server.id),
                action: action,
                ip: ip,
                value: value,
                kind: kind,
                fieldName: fieldName,
                direction: direction,
                rule: rule,
                replacing: replacing,
                ruleKey: ruleKey
            )
        } catch APIError.unauthorized {
            store.setSessionToken(nil, for: server.id)
            needsAuth = true
            isAuthenticated = false
            authPhase = .login
            allowAutoLogin = false
            state = nil
            lastError = "Session expired. Enter the master password again."
            return nil
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    /// Surface an action's reply and pull fresh state when it worked.
    private func applyActionResult(_ resp: ActionResponse) async -> Bool {
        statusBanner = resp.message
        guard resp.ok else {
            lastError = resp.message
            return false
        }
        await refresh(silent: true)
        return true
    }

    func block(ip: String) async { _ = await runAction("block", ip: ip) }
    func unblock(ip: String) async { _ = await runAction("unblock", ip: ip) }

    // MARK: Blocking a tunnel peer
    //
    // 0.6's prevention engine screens CGNAT (100.64/10) out of auto-block entirely, because
    // that range carries Tailscale and most WireGuard tunnels and dropping it is only ever
    // a self-inflicted outage. A *manual* block still goes through — a hostile tunnel peer
    // is real — so the desktop puts a confirmation in front of it, and so does this.

    /// The address a confirmation is currently being asked about, if any.
    var pendingTunnelBlockIP: String?

    /// Every Block button in the app goes through here, so the confirmation lives in one
    /// place instead of in each of the six views that offer one.
    func requestBlock(ip: String) async {
        if IPScope.of(ip) == .carrierGradeNAT {
            pendingTunnelBlockIP = ip
            return
        }
        await block(ip: ip)
    }

    /// Proceed with a block the user has just confirmed. Takes the address explicitly:
    /// dismissing the dialog clears `pendingTunnelBlockIP`, and reading it back inside the
    /// confirm handler would race that.
    func confirmTunnelBlock(_ ip: String) async {
        pendingTunnelBlockIP = nil
        await block(ip: ip)
    }

    func cancelPendingTunnelBlock() { pendingTunnelBlockIP = nil }
    func clearThreats() async { _ = await runAction("clear_threats") }
    func toggleMonitor() async { _ = await runAction("toggle_monitor") }
    func toggleAutoblock() async { _ = await runAction("toggle_autoblock") }
    func setMinLevel(_ level: String) async { _ = await runAction("set_min_level", value: level) }
    func refreshAllowlist() async { _ = await runAction("refresh_allowlist") }
    func restoreAllowlisted() async { _ = await runAction("restore_allowlisted") }
    func addAllowlist(_ value: String) async { _ = await runAction("add_allowlist", value: value) }
    func removeAllowlist(_ value: String, kind: String) async {
        _ = await runAction("remove_allowlist", value: value, kind: kind)
    }

    // MARK: Sleep / wake
    //
    // The web console's header Sleep ⇄ Wake button. Sleeping stops every watcher the
    // server owns — connections, ports, auth log, closed-port probes, ARP, startup items,
    // exfiltration, honeypot, and on 0.6 the DNS, WireGuard, Suricata and conntrack feeds —
    // so asleep means nothing is observed rather than a frozen dashboard. Firewall blocks
    // stay in force: sleeping stops watching, it must never unblock an address the machine
    // is already protected from.
    //
    // On the wire this is the same monitor state Pause sets, so what makes Sleep a
    // different thing is that the client parks too — dimmed data, a 30s heartbeat, no
    // Critical alerts — exactly as the browser does.

    func sleepConsole() async {
        guard let server else { return }
        // Commit only once the server confirms: parking the app over a console that is
        // still watching would hide live traffic behind an "Asleep" banner.
        guard await runMonitorAction(primary: "sleep", fallback: "pause") else { return }
        setSleeping(true, for: server.id)
        syncSleepMode()
    }

    func wakeConsole() async {
        guard let server else { return }
        guard await runMonitorAction(primary: "wake", fallback: "resume") else { return }
        setSleeping(false, for: server.id)
        syncSleepMode()
    }

    func toggleSleep() async {
        if isAsleep {
            await wakeConsole()
        } else {
            await sleepConsole()
        }
    }

    /// Web ≥ 0.5.1 names this control `sleep`/`wake`; every 0.3–0.5.0 server drives the
    /// same state under `pause`/`resume`. Try the current name and fall back on the older
    /// one, so an un-upgraded server gets a working button instead of "Unknown action".
    private func runMonitorAction(primary: String, fallback: String) async -> Bool {
        guard var resp = await sendAction(primary) else { return false }
        if !resp.ok, resp.isUnknownAction, let older = await sendAction(fallback) {
            resp = older
        }
        return await applyActionResult(resp)
    }

    /// Web 0.3+: `set_setting` with name + true/false value.
    func setSetting(_ key: String, enabled: Bool) async {
        _ = await runAction("set_setting", value: enabled ? "true" : "false", fieldName: key)
    }

    /// Web 0.4+: `set_setting` for the free-text and numeric settings.
    func setSetting(_ key: String, value: String) async {
        _ = await runAction("set_setting", value: value, fieldName: key)
    }

    func setBlockInbound(_ on: Bool) async { await setSetting("blockInbound", enabled: on) }
    func setBlockOutbound(_ on: Bool) async { await setSetting("blockOutbound", enabled: on) }
    func setGeoLookup(_ on: Bool) async { await setSetting("geoLookupEnabled", enabled: on) }
    /// Web 0.3.3+: watch system auth logs for failed SSH/PAM logons.
    func setAuthLogMonitor(_ on: Bool) async { await setSetting("authLogMonitorEnabled", enabled: on) }
    /// Web 0.3.4+: firewall SYN logging to catch scans of closed ports. Needs elevation on the server.
    func setProbeLog(_ on: Bool) async { await setSetting("probeLogEnabled", enabled: on) }
    /// Web 0.3.5+: Critical warnings on the server itself (desktop notification in the
    /// GUI, tab badge + browser notification in the web console). Separate from this
    /// device's notifications, which stay under `criticalAlertsEnabled`.
    func setServerCriticalAlerts(_ on: Bool) async { await setSetting("criticalAlertsEnabled", enabled: on) }
    func setAllowlistRemoteFeed(_ on: Bool) async { await setSetting("allowlistUseRemoteFeed", enabled: on) }
    func setAutoBlockEnabled(_ on: Bool) async { await setSetting("autoBlockEnabled", enabled: on) }

    // MARK: Intrusion detection (web 0.4+)

    func setThreatIntel(_ on: Bool) async { await setSetting("threatIntelEnabled", enabled: on) }
    func setProcessReputation(_ on: Bool) async { await setSetting("processReputationEnabled", enabled: on) }
    func setNewListenerAlerts(_ on: Bool) async { await setSetting("newListenerAlertsEnabled", enabled: on) }
    func setArpWatch(_ on: Bool) async { await setSetting("arpWatchEnabled", enabled: on) }
    func setExfilMonitor(_ on: Bool) async { await setSetting("exfilMonitorEnabled", enabled: on) }
    func setHoneypot(_ on: Bool) async { await setSetting("honeypotEnabled", enabled: on) }

    /// The persistence watcher answers to `launchItemWatchEnabled` on macOS and
    /// `persistenceWatchEnabled` on Linux and Windows. Writing the name the server did not
    /// publish comes back as `Unknown setting`, which reads as a toggle that does nothing,
    /// so the key is taken from the state the server just sent rather than assumed.
    func setStartupItemWatch(_ on: Bool) async {
        guard let key = state?.settings?.startupWatchSettingKey else { return }
        await setSetting(key, enabled: on)
    }

    /// Outbound megabytes to one host per 10 minutes. The server rejects anything under 10.
    func setExfilThreshold(_ megabytes: Int) async {
        await setSetting("exfilMbPer10Min", value: "\(megabytes)")
    }

    /// Comma-separated decoy TCP ports. The server rejects an unparseable list, and
    /// refuses its own console port, so its message is worth surfacing verbatim.
    func setHoneypotPorts(_ ports: String) async {
        await setSetting("honeypotPorts", value: ports.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Empty string turns webhook alerts off.
    func setWebhookURL(_ url: String) async {
        await setSetting("webhookUrl", value: url.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Minutes before an auto-created block rule expires. 0 = permanent until removed.
    func setAutoBlockExpiry(minutes: Int) async {
        await setSetting("autoBlockExpiryMinutes", value: "\(minutes)")
    }

    // MARK: Prevention, DNS, VPN and signatures (web 0.6+)

    /// Dry run walks every auto-block gate and reports what it would have dropped without
    /// writing a rule. Where a new detection source belongs before it is allowed to enforce.
    func setPreventionDryRun(_ on: Bool) async { await setSetting("preventionDryRun", enabled: on) }

    /// Conntrack `NEW` events, so an inbound connection triggers a snapshot instead of
    /// waiting out the poll interval. Needs root on the server; without it the status says so.
    func setConntrackEvents(_ on: Bool) async { await setSetting("conntrackEventsEnabled", enabled: on) }

    func setDnsHygiene(_ on: Bool) async { await setSetting("dnsHygieneEnabled", enabled: on) }

    /// Comma-separated resolver IPs. Empty is allowed and means "no approved resolvers",
    /// which the server reports back — DoH cannot be told from web traffic without this list.
    func setDnsApprovedResolvers(_ resolvers: String) async {
        await setSetting("dnsApprovedResolvers", value: resolvers.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    // MARK: DNS filtering (web 0.7.15+)
    //
    // The switch stops a connection being attempted at all, which nothing else in this app
    // does — so unlike every other toggle here, its failures matter. The server talks to the
    // resolver synchronously and answers with what happened ("the resolver rejected the
    // credentials", "no answer within 6s"), and `runAction` already surfaces that verbatim.

    /// Filtering on or off *at the resolver*, not the resolver itself: stopping the service
    /// would take name resolution away from every tunnel client at once, which is an outage
    /// rather than "filtering off".
    func setDnsFilterEnabled(_ on: Bool) async { await setSetting("dnsFilterEnabled", enabled: on) }

    /// Admin API of the filtering resolver. The server normalises what a person would type —
    /// `10.8.0.1`, `10.8.0.1:3000`, `http://10.8.0.1:3000/` — and refuses what it cannot use.
    /// Empty clears it, which unconfigures the switch and takes Blocked Sites away with it.
    func setDnsFilterUrl(_ url: String) async {
        await setSetting("dnsFilterUrl", value: url.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Empty means the resolver needs no login.
    func setDnsFilterUsername(_ user: String) async {
        await setSetting("dnsFilterUsername", value: user.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Write-only, like the DuckDNS token: the server sends back only whether one is stored.
    /// Empty removes it. Not trimmed — a password's leading space is part of the password.
    func setDnsFilterPassword(_ password: String) async {
        await setSetting("dnsFilterPassword", value: password)
    }

    func setWireGuardMonitor(_ on: Bool) async { await setSetting("wireGuardMonitorEnabled", enabled: on) }

    /// Megabytes per peer per 10 minutes. 0 turns per-peer transfer alerts off, which is
    /// the server's default — a peer streaming video moves gigabytes legitimately.
    func setWireGuardPeerThreshold(_ megabytes: Int) async {
        await setSetting("wireGuardPeerMbPer10Min", value: "\(megabytes)")
    }

    func setSuricata(_ on: Bool) async { await setSetting("suricataEnabled", enabled: on) }

    /// Absolute path to Suricata's `eve.json`. Empty restores the server's own default.
    func setSuricataEvePath(_ path: String) async {
        await setSetting("suricataEvePath", value: path.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// 1–4, counting down as Suricata does: a lower number accepts fewer, more severe alerts.
    func setSuricataMaxSeverity(_ severity: Int) async {
        await setSetting("suricataMaxSeverity", value: "\(severity)")
    }

    /// Comma-separated signature ids to mute. Empty un-mutes everything.
    func setSuricataIgnoredSids(_ sids: String) async {
        await setSetting("suricataIgnoredSids", value: sids.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    // MARK: Remote access (web 0.5+)
    //
    // TLS endpoints are bound when the console starts, so everything here is saved now and
    // served after the next restart. `httpsActive` is the only field that says what is
    // actually being served, which is why the UI leads with it rather than with the toggle.

    func setHttpsEnabled(_ on: Bool) async { await setSetting("httpsEnabled", enabled: on) }
    func setHttpsRedirect(_ on: Bool) async { await setSetting("httpsRedirect", enabled: on) }
    /// Web 0.7.6+. Drops the plain-HTTP listener entirely, so the master password can only
    /// cross the wire encrypted. The server refuses this while HTTPS is off or its
    /// certificate will not load — deliberately, so a bad certificate cannot lock the
    /// console out — and the refusal is worth surfacing verbatim.
    func setHttpsOnly(_ on: Bool) async { await setSetting("httpsOnly", enabled: on) }
    /// Passed through as typed. The server owns the rules — 1–65535, and never the port
    /// already serving this console — and its refusal says which one you broke.
    func setHttpsPort(_ port: String) async {
        await setSetting("httpsPort", value: port.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// The server checks the file exists and tries to load the pair, so its reply is worth
    /// surfacing verbatim — a path that only fails at restart means no console at all.
    func setTlsCertPath(_ path: String) async {
        await setSetting("tlsCertPath", value: path.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func setTlsKeyPath(_ path: String) async {
        await setSetting("tlsKeyPath", value: path.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func setDuckDnsEnabled(_ on: Bool) async { await setSetting("duckDnsEnabled", enabled: on) }

    func setDuckDnsDomain(_ domain: String) async {
        await setSetting("duckDnsDomain", value: domain.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Write-only: the server never sends a stored token back, only whether one exists.
    /// Empty clears it.
    func setDuckDnsToken(_ token: String) async {
        await setSetting("duckDnsToken", value: token.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func setAcmeEmail(_ email: String) async {
        await setSetting("acmeEmail", value: email.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Starts Let's Encrypt issuance through DuckDNS. It waits on DNS propagation and runs
    /// for minutes, so the action only reports that it started — progress arrives in
    /// `certIssueBusy` / `certIssueMessage` on the next state poll.
    func issueCertificate() async { _ = await runAction("issue_cert") }

    /// Web 0.3+: block a local port (TCP/UDP, direction).
    func blockPort(_ port: Int, protocol proto: String = "TCP", direction: String = "Inbound") async {
        _ = await runAction(
            "block_port",
            value: "\(port)",
            kind: proto,
            direction: direction
        )
    }

    func unblockPort(_ port: Int, protocol proto: String = "TCP") async {
        _ = await runAction("unblock_port", value: "\(port)", kind: proto)
    }

    func removeRule(named name: String) async {
        _ = await runAction("remove_rule", value: name, fieldName: name)
    }

    // MARK: Firewall configuration (web 0.7+)

    /// Adds a rule, or replaces an existing one when the form was opened on one.
    ///
    /// Which of `replacing` and `ruleKey` carries the original is not a style choice. A rule
    /// this app wrote is replaced by name, through its own ledger. A rule UFW wrote has no
    /// ledger entry and no unique name, so the server takes its whole shape as `key`, deletes
    /// it where it lives, and writes these values as a new rule — UFW has no in-place edit,
    /// and writing the replacement on top would leave both in force.
    ///
    /// Returns whether it took, because this one has a form behind it: a rule the server
    /// refuses must leave the sheet open with the reason on it, not dismiss as though it
    /// had been written. Every other action in this file can discard the result because a
    /// banner is the whole of its feedback.
    @discardableResult
    func saveConfigRule(
        _ rule: FirewallRuleDraft,
        replacing: String? = nil,
        ruleKey: String? = nil
    ) async -> Bool {
        let ok = await runAction("save_config_rule", rule: rule, replacing: replacing, ruleKey: ruleKey)
        await reloadHostScanAfterWrite()
        return ok
    }

    // MARK: Host firewall (web 0.7.4+)

    /// Removes a rule the host owns — UFW's, Docker's, anyone's — by its shape.
    ///
    /// `remove_rule` cannot do this: it looks the name up in this app's ledger, and a UFW
    /// rule was never in it. The server routes the delete back out the way the rule went in,
    /// `ufw delete` or `nft delete rule … handle`, and refuses a shape that matches more than
    /// one rule rather than removing an arbitrary one of them.
    func deleteHostRule(key: String) async {
        _ = await runAction("delete_host_rule", ruleKey: key)
        await reloadHostScanAfterWrite()
    }

    // MARK: The scan on its own endpoint (Windows 0.7.4+)

    /// What the Firewall Config screen should draw, from whichever place this server put it.
    var configRules: [ConfigRuleInfo] {
        state?.configRules ?? hostScan?.configRules ?? []
    }

    var hostFirewall: HostFirewallInfo? {
        state?.hostFirewall ?? hostScan?.hostFirewall
    }

    var hostListeners: [HostListener] {
        state?.listeners ?? hostScan?.listeners ?? []
    }

    /// True when this server has a Firewall Config page at all — either in the poll or on the
    /// endpoint. False only once the endpoint has answered 404 with no `configRules` in state.
    var hasFirewallConfig: Bool {
        state?.configRules != nil || hostScan != nil
    }

    /// Fetches the scan if this server keeps it off `/api/state` and it has not been read yet.
    /// Called when the screen appears; cheap and silent when there is nothing to do.
    func ensureHostFirewall() async {
        guard state?.configRules == nil, hostScan == nil, !hostScanUnsupported, !hostScanLoading
        else { return }
        await loadHostFirewall()
    }

    /// Reads `/api/hostfirewall`. `rescan` makes the server re-read the firewall itself rather
    /// than answer from its cache — the same distinction the web console draws between opening
    /// the page and pressing Rescan.
    func loadHostFirewall(rescan: Bool = false) async {
        guard let server, !hostScanLoading else { return }
        hostScanLoading = true
        hostScanError = nil
        defer { hostScanLoading = false }
        do {
            let scan = try await api.fetchHostFirewall(
                baseURL: server.baseURL,
                token: store.sessionToken(for: server.id),
                rescan: rescan
            )
            if let scan {
                hostScan = scan
                hostScanUnsupported = false
            } else {
                // 404: this server has no such route. Whatever /api/state carried is all there is.
                hostScanUnsupported = true
            }
        } catch APIError.unauthorized {
            // The poll owns re-authentication; this one just says it could not read.
            hostScanError = "Session expired — the firewall scan was not read."
        } catch {
            hostScanError = error.localizedDescription
        }
    }

    // MARK: Blocked Sites (web 0.7.15+)

    /// Whether this console has a filtering resolver behind it, which is what decides
    /// whether Blocked Sites is offered at all. The server publishes the answer rather than
    /// the app inferring it from the URL field: a resolver address that fails to normalise
    /// is stored as empty, and only the server knows that.
    var hasDnsFilter: Bool { state?.settings?.dnsFilterConfigured == true }

    /// Reads the refusals. Called when the screen appears, when the limit changes, and on
    /// pull-to-refresh — never on the poll, because the resolver serving that log is what
    /// every tunnel client resolves through.
    ///
    /// A server that answers `ok: false` has still answered: its message says whether the
    /// resolver was unreachable, refused the credentials, or simply has an empty log. That
    /// is kept and shown; only a 404 means the console has no such page.
    func loadDnsBlocked() async {
        guard let server, !dnsBlockedLoading else { return }
        dnsBlockedLoading = true
        defer { dnsBlockedLoading = false }
        do {
            let reply = try await api.fetchDnsBlocked(
                baseURL: server.baseURL,
                token: store.sessionToken(for: server.id),
                limit: dnsBlockedLimit
            )
            guard let reply else {
                dnsBlockedUnsupported = true
                dnsBlocked = []
                dnsBlockedMessage = nil
                return
            }
            dnsBlockedUnsupported = false
            dnsBlockedOk = reply.ok ?? false
            dnsBlockedMessage = reply.message
            dnsBlocked = reply.entries ?? []
        } catch APIError.unauthorized {
            // The poll owns re-authentication; this one only says it could not read.
            dnsBlockedOk = false
            dnsBlockedMessage = "Session expired — the resolver's log was not read."
        } catch {
            dnsBlockedOk = false
            dnsBlockedMessage = error.localizedDescription
        }
    }

    /// Changes how many refusals to ask for and re-reads. Same four the console offers.
    func setDnsBlockedLimit(_ limit: Int) async {
        guard limit != dnsBlockedLimit else { return }
        dnsBlockedLimit = limit
        await loadDnsBlocked()
    }

    /// Re-reads the scan after a write, but only for a server that serves it separately —
    /// where it rides in `/api/state` the next poll already carries the change.
    private func reloadHostScanAfterWrite() async {
        guard hostScan != nil else { return }
        await loadHostFirewall()
    }

    /// Re-reads ufw/nft/iptables/ss on the server.
    ///
    /// The scan is cached behind `/api/state` — the poll would otherwise shell out four times
    /// every few seconds — so a pull-to-refresh on the Firewall Config screen returns the same
    /// list until this is called. Every write invalidates the cache server-side; this is for
    /// the case where something changed the firewall out from under the app.
    func rescanFirewall() async {
        // Where the scan has its own endpoint, rescanning *is* re-fetching it with the flag
        // set; the action verb belongs to the servers that cache it behind /api/state.
        if hostScan != nil {
            await loadHostFirewall(rescan: true)
        } else {
            _ = await runAction("rescan_firewall")
        }
    }

    /// Bandwidth accounting on the host's interfaces. Off by default on the server, and
    /// switching it on starts the counters from nothing rather than backfilling.
    func setTrafficMeter(_ on: Bool) async { await setSetting("trafficMeterEnabled", enabled: on) }

    func removeAllRules() async {
        _ = await runAction("remove_all_rules")
    }

    func authorizeFirewall() async {
        _ = await runAction("authorize")
    }
}
