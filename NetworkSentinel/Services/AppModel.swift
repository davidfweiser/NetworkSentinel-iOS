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
    /// User preference: local notifications + in-app popups for Critical threats.
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

    var server: ServerProfile? { store.selectedServer }

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
            Task { @MainActor in
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
            guard let token = try await ensureSessionToken(for: server) else { return }
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

    /// Returns a valid session token, logging in with remembered password if needed.
    private func ensureSessionToken(for server: ServerProfile) async throws -> String? {
        if let token = store.sessionToken(for: server.id) {
            return token
        }
        guard let password = store.rememberedPassword(for: server.id) else {
            return nil
        }
        let (resp, token) = try await api.login(baseURL: server.baseURL, password: password)
        guard resp.ok else { return nil }
        if let token {
            store.setSessionToken(token, for: server.id)
            return token
        }
        // Cookie-only session; try status without stored token.
        return store.sessionToken(for: server.id)
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
        restartPolling()
    }

    func dismissCriticalAlert() {
        pendingCriticalAlert = nil
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
        processCriticalThreats(from: s, server: server)
    }

    private func processCriticalThreats(from s: ServerState, server: ServerProfile) {
        guard criticalAlertsEnabled else { return }
        let threats = s.threats ?? []
        let fresh = CriticalAlertService.shared.newCriticalThreats(
            serverId: server.id,
            threats: threats
        )
        guard !fresh.isEmpty else { return }

        // Always post a system notification (banner when backgrounded / locked).
        CriticalAlertService.shared.notify(serverName: server.name, threats: fresh)

        // In-app popup while using the app (queue first new critical).
        if isAppActive {
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

    func performSetup(password: String, confirm: String) async throws {
        guard let server else { throw APIError.invalidURL }
        let (resp, token) = try await api.setup(baseURL: server.baseURL, password: password, confirm: confirm)
        guard resp.ok else {
            throw APIError.serverMessage(resp.message ?? "Setup failed")
        }

        if let token {
            store.setSessionToken(token, for: server.id)
        }
        store.setRememberedPassword(password, for: server.id)

        let s = try await api.fetchState(
            baseURL: server.baseURL,
            token: store.sessionToken(for: server.id) ?? token
        )
        applyState(s, server: server)
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

    @discardableResult
    func runAction(
        _ action: String,
        ip: String? = nil,
        value: String? = nil,
        kind: String? = nil,
        fieldName: String? = nil,
        direction: String? = nil
    ) async -> Bool {
        guard let server else { return false }
        do {
            let resp = try await api.action(
                baseURL: server.baseURL,
                token: store.sessionToken(for: server.id),
                action: action,
                ip: ip,
                value: value,
                kind: kind,
                fieldName: fieldName,
                direction: direction
            )
            statusBanner = resp.message
            if !resp.ok {
                lastError = resp.message
                return false
            }
            await refresh(silent: true)
            return true
        } catch APIError.unauthorized {
            store.setSessionToken(nil, for: server.id)
            needsAuth = true
            isAuthenticated = false
            authPhase = .login
            allowAutoLogin = false
            state = nil
            lastError = "Session expired. Enter the master password again."
            return false
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    func block(ip: String) async { _ = await runAction("block", ip: ip) }
    func unblock(ip: String) async { _ = await runAction("unblock", ip: ip) }
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

    /// Web 0.3+: `set_setting` with name + true/false value.
    func setSetting(_ key: String, enabled: Bool) async {
        _ = await runAction("set_setting", value: enabled ? "true" : "false", fieldName: key)
    }

    func setBlockInbound(_ on: Bool) async { await setSetting("blockInbound", enabled: on) }
    func setBlockOutbound(_ on: Bool) async { await setSetting("blockOutbound", enabled: on) }
    func setGeoLookup(_ on: Bool) async { await setSetting("geoLookupEnabled", enabled: on) }
    func setAllowlistRemoteFeed(_ on: Bool) async { await setSetting("allowlistUseRemoteFeed", enabled: on) }
    func setAutoBlockEnabled(_ on: Bool) async { await setSetting("autoBlockEnabled", enabled: on) }

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

    func removeAllRules() async {
        _ = await runAction("remove_all_rules")
    }

    func authorizeFirewall() async {
        _ = await runAction("authorize")
    }
}
