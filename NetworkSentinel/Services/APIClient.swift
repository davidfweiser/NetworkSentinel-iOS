import Foundation

enum APIError: LocalizedError {
    case invalidURL
    case http(Int, String?)
    case decoding(Error)
    case network(Error)
    case unauthorized(String?)
    case serverMessage(String)
    case missingSession

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid server URL."
        case .http(let code, let msg): return msg ?? "HTTP \(code)"
        case .decoding(let e): return "Bad response: \(e.localizedDescription)"
        case .network(let e): return e.localizedDescription
        case .unauthorized(let m): return m ?? "Authentication required."
        case .serverMessage(let m): return m
        case .missingSession: return "Signed in, but no session token was returned. Try again."
        }
    }
}

/// Talks to a Network Sentinel web UI (`-w` / `--web`).
/// Auth: captures `ns_session` from the cookie jar (iOS strips Set-Cookie from headers)
/// and re-sends it as `Authorization: Bearer` + Cookie on later requests.
actor APIClient {
    private let session: URLSession
    private let cookieStorage: HTTPCookieStorage
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    init() {
        let storage = HTTPCookieStorage()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 40
        config.httpCookieAcceptPolicy = .always
        config.httpShouldSetCookies = true
        config.httpCookieStorage = storage
        cookieStorage = storage
        session = URLSession(configuration: config)
        decoder = JSONDecoder()
        encoder = JSONEncoder()
    }

    // MARK: - Auth

    func authStatus(baseURL: String, token: String? = nil) async throws -> AuthStatus {
        let url = try url(base: baseURL, path: "/api/auth/status")
        let (data, response) = try await session.data(for: request(url: url, method: "GET", token: token))
        try throwIfNeeded(response: response, data: data)
        return try decode(data)
    }

    /// Login with master password.
    /// Returns session token when we can capture `ns_session` (for Keychain + Bearer).
    /// Token may be nil if iOS only keeps the cookie in the jar — same-process requests still work.
    func login(baseURL: String, password: String) async throws -> (AuthResponse, String?) {
        let url = try url(base: baseURL, path: "/api/auth/login")
        var req = request(url: url, method: "POST")
        req.httpBody = try encoder.encode(["password": password])
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await session.data(for: req)
        try throwIfNeeded(response: response, data: data)
        let body: AuthResponse = try decode(data)
        guard body.ok else {
            throw APIError.serverMessage(body.message ?? "Incorrect master password.")
        }

        let token = extractSessionToken(from: response, baseURL: baseURL)
            ?? sessionTokenFromJar(baseURL: baseURL)
            ?? anyNsSessionCookie()
        return (body, token)
    }

    func setup(baseURL: String, password: String, confirm: String) async throws -> (AuthResponse, String?) {
        let url = try url(base: baseURL, path: "/api/auth/setup")
        var req = request(url: url, method: "POST")
        req.httpBody = try encoder.encode(["password": password, "confirm": confirm])
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await session.data(for: req)
        try throwIfNeeded(response: response, data: data)
        let body: AuthResponse = try decode(data)
        guard body.ok else {
            throw APIError.serverMessage(body.message ?? "Setup failed")
        }

        let token = extractSessionToken(from: response, baseURL: baseURL)
            ?? sessionTokenFromJar(baseURL: baseURL)
            ?? anyNsSessionCookie()
        return (body, token)
    }

    /// Change the master password (web ≥ 0.3.3, `POST /api/auth/change-password`).
    /// The server keeps the calling session alive and revokes every other one, so the
    /// app's token stays valid — but any remembered password must be re-stored by the caller.
    func changePassword(
        baseURL: String,
        token: String?,
        current: String,
        new: String,
        confirm: String
    ) async throws -> AuthResponse {
        let url = try url(base: baseURL, path: "/api/auth/change-password")
        var req = request(url: url, method: "POST", token: token)
        req.httpBody = try encoder.encode([
            "currentPassword": current,
            "newPassword": new,
            "confirm": confirm
        ])
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await session.data(for: req)
        if let http = response as? HTTPURLResponse, http.statusCode == 401 {
            let msg = (try? decoder.decode(AuthResponse.self, from: data))?.message
            throw APIError.unauthorized(msg)
        }
        // Validation failures come back as HTTP 400 + `{ ok: false, message }`.
        if let http = response as? HTTPURLResponse, http.statusCode == 400,
           let failed = try? decoder.decode(AuthResponse.self, from: data) {
            throw APIError.serverMessage(failed.message ?? "Could not change the master password.")
        }
        // Servers older than web 0.3.2 have no such route — say so instead of "HTTP 404".
        if let http = response as? HTTPURLResponse, http.statusCode == 404 {
            throw APIError.serverMessage(
                "This server is too old to change the master password from the app. Update Network Sentinel to 0.3.2 or newer."
            )
        }
        try throwIfNeeded(response: response, data: data)
        let body: AuthResponse = try decode(data)
        guard body.ok else {
            throw APIError.serverMessage(body.message ?? "Could not change the master password.")
        }
        return body
    }

    func logout(baseURL: String, token: String?) async throws {
        let url = try url(base: baseURL, path: "/api/auth/logout")
        var req = request(url: url, method: "POST", token: token)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (_, _) = try await session.data(for: req)
        clearCookies(for: baseURL)
    }

    // MARK: - State & actions

    func fetchState(baseURL: String, token: String?) async throws -> ServerState {
        let url = try url(base: baseURL, path: "/api/state")
        let req = request(url: url, method: "GET", token: token)
        let (data, response) = try await session.data(for: req)
        if let http = response as? HTTPURLResponse, http.statusCode == 401 {
            let msg = (try? decoder.decode(AuthResponse.self, from: data))?.message
            throw APIError.unauthorized(msg)
        }
        try throwIfNeeded(response: response, data: data)
        return try decode(data)
    }

    /// POST `/api/action` — matches Network Sentinel web 0.3+ `ActionRequest`
    /// (`action`, `ip`, `value`, `name`, `kind`, `direction`), plus the 0.7+ config-rule
    /// fields (`label`, `ruleAction`, `protocol`, `ports`, `addresses`, `replace`) and the
    /// 0.7.4+ `key`.
    ///
    /// A rule carries six fields at once, which is why 0.7 gave them their own slots rather
    /// than overloading `value`/`kind` — the server says as much in its own DTO.
    func action(
        baseURL: String,
        token: String?,
        action: String,
        ip: String? = nil,
        value: String? = nil,
        kind: String? = nil,
        fieldName: String? = nil,
        direction: String? = nil,
        rule: FirewallRuleDraft? = nil,
        replacing: String? = nil,
        ruleKey: String? = nil
    ) async throws -> ActionResponse {
        let url = try url(base: baseURL, path: "/api/action")
        var body: [String: String] = ["action": action]
        if let ip, !ip.isEmpty { body["ip"] = ip }
        // Sent even when empty: clearing the 0.4+ webhook URL is how it is switched off,
        // and an omitted `value` would read as "no change" rather than "set to nothing".
        if let value { body["value"] = value }
        if let kind, !kind.isEmpty { body["kind"] = kind }
        if let fieldName, !fieldName.isEmpty { body["name"] = fieldName }
        if let direction, !direction.isEmpty { body["direction"] = direction }

        if let rule {
            body["label"] = rule.label.trimmingCharacters(in: .whitespacesAndNewlines)
            body["ruleAction"] = rule.action.rawValue
            body["direction"] = rule.direction.rawValue
            body["protocol"] = rule.protocolName
            // Both sent even when empty — empty means "every port" and "every address" to
            // the server, which is a rule shape, not a missing field.
            body["ports"] = rule.ports.trimmingCharacters(in: .whitespacesAndNewlines)
            body["addresses"] = rule.addresses.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        // Only on an edit. Omitted, the server adds a rule instead of replacing one.
        if let replacing, !replacing.isEmpty { body["replace"] = replacing }
        // The whole-shape identity of a scanned host rule — web 0.7.4+. `delete_host_rule`
        // takes it alone; `save_config_rule` takes it when the rule being edited belongs to
        // UFW rather than to this app, and the server then removes the original where it
        // lives before writing the replacement.
        if let ruleKey, !ruleKey.isEmpty { body["key"] = ruleKey }

        var req = request(url: url, method: "POST", token: token)
        req.httpBody = try encoder.encode(body)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await session.data(for: req)
        if let http = response as? HTTPURLResponse, http.statusCode == 401 {
            let msg = (try? decoder.decode(AuthResponse.self, from: data))?.message
            throw APIError.unauthorized(msg)
        }
        // Web returns HTTP 400 with `{ ok: false, message }` for failed actions
        // (unknown action, missing elevation, protected rule, …). Treat as a normal body.
        if let http = response as? HTTPURLResponse, http.statusCode == 400,
           let failed = try? decoder.decode(ActionResponse.self, from: data) {
            return failed
        }
        try throwIfNeeded(response: response, data: data)
        return try decode(data)
    }

    // MARK: - Helpers

    private func url(base: String, path: String) throws -> URL {
        let normalized = ServerProfile.normalizeURL(base)
        guard let baseURL = URL(string: normalized) else { throw APIError.invalidURL }
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
            throw APIError.invalidURL
        }
        return url
    }

    private func request(url: URL, method: String, token: String? = nil) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("NetworkSentinel-iOS/1.0", forHTTPHeaderField: "User-Agent")
        if let token, !token.isEmpty {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.setValue("ns_session=\(token)", forHTTPHeaderField: "Cookie")
        }
        return req
    }

    private func extractSessionToken(from response: URLResponse, baseURL: String) -> String? {
        guard let http = response as? HTTPURLResponse else { return nil }

        if let cookies = http.value(forHTTPHeaderField: "Set-Cookie"),
           let token = parseCookie(cookies, name: "ns_session") {
            return token
        }
        for (key, value) in http.allHeaderFields {
            guard String(describing: key).lowercased() == "set-cookie" else { continue }
            if let s = value as? String, let token = parseCookie(s, name: "ns_session") {
                return token
            }
        }

        // Prefer cookie storage (what iOS actually keeps)
        if let token = sessionTokenFromJar(baseURL: baseURL) {
            return token
        }
        if let url = http.url {
            if let c = cookieStorage.cookies(for: url)?.first(where: { $0.name == "ns_session" }) {
                return c.value
            }
        }
        return nil
    }

    private func sessionTokenFromJar(baseURL: String) -> String? {
        guard let base = URL(string: ServerProfile.normalizeURL(baseURL)) else { return nil }
        if let c = cookieStorage.cookies(for: base)?.first(where: { $0.name == "ns_session" }) {
            return c.value
        }
        // Match by host/port if path differs
        let host = base.host
        let port = base.port
        return cookieStorage.cookies?.first(where: { cookie in
            cookie.name == "ns_session"
                && (host == nil || cookie.domain.contains(host!) || cookie.domain == host)
                && (port == nil || cookie.portList?.contains(NSNumber(value: port!)) != false || cookie.portList == nil)
        })?.value
    }

    private func anyNsSessionCookie() -> String? {
        cookieStorage.cookies?.first(where: { $0.name == "ns_session" })?.value
    }

    private func clearCookies(for baseURL: String) {
        guard let base = URL(string: ServerProfile.normalizeURL(baseURL)) else { return }
        cookieStorage.cookies(for: base)?.forEach { cookieStorage.deleteCookie($0) }
        cookieStorage.cookies?.filter { $0.name == "ns_session" }.forEach { cookieStorage.deleteCookie($0) }
    }

    private func parseCookie(_ header: String, name: String) -> String? {
        let parts = header.split(separator: ";")
        for part in parts {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if kv.count == 2, kv[0] == name {
                return kv[1]
            }
        }
        return nil
    }

    private func throwIfNeeded(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else { return }
        if (200...299).contains(http.statusCode) { return }
        if http.statusCode == 401 {
            let msg = (try? decoder.decode(AuthResponse.self, from: data))?.message
            throw APIError.unauthorized(msg)
        }
        let msg = (try? decoder.decode(AuthResponse.self, from: data))?.message
            ?? String(data: data, encoding: .utf8)
        throw APIError.http(http.statusCode, msg)
    }

    private func decode<T: Decodable>(_ data: Data) throws -> T {
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw APIError.decoding(error)
        }
    }
}
