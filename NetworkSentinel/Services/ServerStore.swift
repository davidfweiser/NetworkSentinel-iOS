import Foundation
import Observation

@Observable
final class ServerStore {
    private let defaultsKey = "networksentinel.servers"
    private let selectedKey = "networksentinel.selectedServer"

    var servers: [ServerProfile] = []
    var selectedServerId: UUID?

    var selectedServer: ServerProfile? {
        guard let id = selectedServerId else { return servers.first }
        return servers.first(where: { $0.id == id }) ?? servers.first
    }

    init() {
        load()
    }

    func load() {
        if let data = UserDefaults.standard.data(forKey: defaultsKey),
           let decoded = try? JSONDecoder().decode([ServerProfile].self, from: data) {
            servers = decoded
        }
        if let s = UserDefaults.standard.string(forKey: selectedKey),
           let id = UUID(uuidString: s) {
            selectedServerId = id
        } else {
            selectedServerId = servers.first?.id
        }
    }

    func save() {
        if let data = try? JSONEncoder().encode(servers) {
            UserDefaults.standard.set(data, forKey: defaultsKey)
        }
        if let id = selectedServerId {
            UserDefaults.standard.set(id.uuidString, forKey: selectedKey)
        }
    }

    @discardableResult
    func add(name: String, baseURL: String) -> ServerProfile {
        let profile = ServerProfile(name: name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                    ? "Server"
                                    : name.trimmingCharacters(in: .whitespacesAndNewlines),
                                    baseURL: baseURL)
        servers.append(profile)
        selectedServerId = profile.id
        save()
        return profile
    }

    func update(_ profile: ServerProfile) {
        guard let i = servers.firstIndex(where: { $0.id == profile.id }) else { return }
        servers[i] = profile
        save()
    }

    func delete(_ id: UUID) {
        servers.removeAll { $0.id == id }
        KeychainStore.delete(account: KeychainStore.sessionAccount(serverId: id))
        KeychainStore.delete(account: KeychainStore.passwordAccount(serverId: id))
        if selectedServerId == id {
            selectedServerId = servers.first?.id
        }
        save()
    }

    func select(_ id: UUID) {
        selectedServerId = id
        save()
    }

    func markConnected(_ id: UUID) {
        guard let i = servers.firstIndex(where: { $0.id == id }) else { return }
        servers[i].lastConnectedAt = .now
        save()
    }

    // Session token
    func sessionToken(for id: UUID) -> String? {
        KeychainStore.get(account: KeychainStore.sessionAccount(serverId: id))
    }

    func setSessionToken(_ token: String?, for id: UUID) {
        let account = KeychainStore.sessionAccount(serverId: id)
        if let token, !token.isEmpty {
            KeychainStore.set(token, account: account)
        } else {
            KeychainStore.delete(account: account)
        }
    }

    func rememberedPassword(for id: UUID) -> String? {
        KeychainStore.get(account: KeychainStore.passwordAccount(serverId: id))
    }

    func setRememberedPassword(_ password: String?, for id: UUID) {
        let account = KeychainStore.passwordAccount(serverId: id)
        if let password, !password.isEmpty {
            KeychainStore.set(password, account: account)
        } else {
            KeychainStore.delete(account: account)
        }
    }
}
