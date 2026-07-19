import SwiftUI

struct MoreView: View {
    @Environment(AppModel.self) private var model
    @State private var showServers = false
    @State private var showEditServer = false
    @State private var allowlistValue = ""
    @State private var showAddAllowlist = false

    var body: some View {
        NavigationStack {
            List {
                Section("Server") {
                    Button {
                        showServers = true
                    } label: {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(model.server?.name ?? "No server")
                                    .foregroundStyle(NSTheme.text)
                                Text(model.server?.displayHost ?? "—")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(NSTheme.muted)
                            }
                        } icon: {
                            Image(systemName: "server.rack")
                                .foregroundStyle(NSTheme.accent)
                        }
                    }
                    .listRowBackground(NSTheme.card)

                    Button {
                        showEditServer = true
                    } label: {
                        Label("Edit this server", systemImage: "pencil")
                    }
                    .listRowBackground(NSTheme.card)
                    .disabled(model.server == nil)

                    Button(role: .destructive) {
                        Task { await model.logout() }
                    } label: {
                        Label("Sign out", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                    .listRowBackground(NSTheme.card)
                }

                Section("Ports") {
                    if let ports = model.state?.ports, !ports.isEmpty {
                        ForEach(ports) { p in
                            HStack {
                                Text(p.protocolName.uppercased())
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(NSTheme.accent)
                                    .frame(width: 36, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(p.endpoint ?? ":\(p.port)")
                                        .font(.subheadline.monospaced())
                                        .foregroundStyle(NSTheme.text)
                                    Text([p.process, p.hint].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · "))
                                        .font(.caption)
                                        .foregroundStyle(NSTheme.muted)
                                        .lineLimit(1)
                                }
                            }
                            .listRowBackground(NSTheme.card)
                        }
                    } else {
                        Text("No listeners")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.card)
                    }
                }

                Section {
                    if let rules = model.state?.firewallRules, !rules.isEmpty {
                        ForEach(rules) { r in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(r.target)
                                        .font(.subheadline.monospaced().weight(.semibold))
                                        .foregroundStyle(NSTheme.text)
                                    Spacer()
                                    Text(r.action ?? "block")
                                        .font(.caption2.weight(.bold))
                                        .foregroundStyle(NSTheme.danger)
                                }
                                Text([r.direction, r.kind, r.protocolName].compactMap { $0 }.joined(separator: " · "))
                                    .font(.caption)
                                    .foregroundStyle(NSTheme.muted)
                                if let d = r.description, !d.isEmpty {
                                    Text(d)
                                        .font(.caption2)
                                        .foregroundStyle(NSTheme.muted)
                                        .lineLimit(2)
                                }
                            }
                            .listRowBackground(NSTheme.card)
                            .swipeActions {
                                Button {
                                    Task { await model.unblock(ip: r.target) }
                                } label: {
                                    Label("Unblock", systemImage: "lock.open")
                                }
                                .tint(NSTheme.success)
                            }
                        }
                    } else {
                        Text("No managed firewall rules")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.card)
                    }
                } header: {
                    Text("Firewall rules")
                } footer: {
                    if let priv = model.state?.firewall?.privilegeText {
                        Text(priv)
                    }
                }

                Section {
                    if let entries = model.state?.allowlist, !entries.isEmpty {
                        ForEach(entries) { e in
                            HStack {
                                Text(e.kind)
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(NSTheme.success)
                                    .frame(width: 56, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(e.value)
                                        .font(.subheadline.monospaced())
                                        .foregroundStyle(NSTheme.text)
                                    if let d = e.detail, !d.isEmpty {
                                        Text(d)
                                            .font(.caption2)
                                            .foregroundStyle(NSTheme.muted)
                                            .lineLimit(1)
                                    }
                                }
                            }
                            .listRowBackground(NSTheme.card)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    Task { await model.removeAllowlist(e.value, kind: e.kind) }
                                } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                            }
                        }
                    } else {
                        Text("Allowlist empty")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.card)
                    }

                    Button {
                        showAddAllowlist = true
                    } label: {
                        Label("Add domain or IP", systemImage: "plus.circle")
                    }
                    .listRowBackground(NSTheme.card)

                    Button {
                        Task { await model.refreshAllowlist() }
                    } label: {
                        Label("Refresh allowlist", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .listRowBackground(NSTheme.card)

                    Button {
                        Task { await model.restoreAllowlisted() }
                    } label: {
                        Label("Restore good sites", systemImage: "arrow.uturn.backward.circle")
                    }
                    .listRowBackground(NSTheme.card)
                } header: {
                    Text("Allowlist")
                } footer: {
                    if let s = model.state?.allowlistStatus {
                        Text(s)
                    }
                }

                Section("About") {
                    LabeledContent("App", value: "Network Sentinel iOS")
                        .listRowBackground(NSTheme.card)
                    LabeledContent("Server version", value: model.state?.version ?? "—")
                        .listRowBackground(NSTheme.card)
                    LabeledContent("Poll interval", value: "\(Int(model.pollInterval * 10) / 10)s")
                        .listRowBackground(NSTheme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(NSTheme.bg.ignoresSafeArea())
            .navigationTitle("More")
            .sheet(isPresented: $showServers) {
                NavigationStack {
                    ServersListView()
                        .toolbar {
                            ToolbarItem(placement: .topBarTrailing) {
                                Button("Done") { showServers = false }
                            }
                        }
                }
                .preferredColorScheme(.dark)
            }
            .sheet(isPresented: $showEditServer) {
                if let server = model.server {
                    ServerEditorView(mode: .edit(server))
                        .preferredColorScheme(.dark)
                }
            }
            .alert("Add to allowlist", isPresented: $showAddAllowlist) {
                TextField("domain or IP", text: $allowlistValue)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Add") {
                    let v = allowlistValue.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !v.isEmpty else { return }
                    Task {
                        await model.addAllowlist(v)
                        allowlistValue = ""
                    }
                }
                Button("Cancel", role: .cancel) { allowlistValue = "" }
            } message: {
                Text("Trusted domains/IPs are never auto-blocked.")
            }
            .refreshable { await model.refresh(silent: false) }
        }
    }
}
