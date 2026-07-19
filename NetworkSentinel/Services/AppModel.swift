import Foundation
import Observation
import SwiftUI

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

    var server: ServerProfile? { store.selectedServer }

    // MARK: - Lifecycle

    func onAppear() {
        evaluateInitialAuthGate()
        startPolling()
    }

    func onDisappear() {
        stopPolling()
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
        guard let server else {
            authPhase = .checking
            needsAuth = false
            needsSetup = false
            return
        }
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
        allowAutoLogin = true
        evaluateInitialAuthGate()
        restartPolling()
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
            state = s
            isAuthenticated = true
            needsAuth = false
            needsSetup = false
            authPhase = .authenticated
            lastError = nil
            store.markConnected(server.id)
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
                    state = s
                    isAuthenticated = true
                    authPhase = .authenticated
                    store.markConnected(server.id)
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
        state = s
        isAuthenticated = true
        needsAuth = false
        needsSetup = false
        authPhase = .authenticated
        lastError = nil
        allowAutoLogin = true
        store.markConnected(server.id)
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
        state = s
        isAuthenticated = true
        needsAuth = false
        needsSetup = false
        authPhase = .authenticated
        lastError = nil
        store.markConnected(server.id)
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
        _ name: String,
        ip: String? = nil,
        value: String? = nil,
        kind: String? = nil
    ) async -> Bool {
        guard let server else { return false }
        do {
            let resp = try await api.action(
                baseURL: server.baseURL,
                token: store.sessionToken(for: server.id),
                name: name,
                ip: ip,
                value: value,
                kind: kind
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
}
