import SwiftUI

struct MoreView: View {
    @Environment(AppModel.self) private var model
    @State private var showServers = false
    @State private var showEditServer = false
    @State private var showChangePassword = false
    @State private var allowlistValue = ""
    @State private var showAddAllowlist = false
    @State private var showBlockPort = false
    @State private var blockPortText = ""
    @State private var confirmRemoveAll = false
    @State private var showWebhook = false
    @State private var webhookDraft = ""

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
                    .listRowBackground(NSTheme.row)

                    Button {
                        showEditServer = true
                    } label: {
                        Label("Edit this server", systemImage: "pencil")
                    }
                    .listRowBackground(NSTheme.row)
                    .disabled(model.server == nil)

                    Button {
                        showChangePassword = true
                    } label: {
                        Label("Change master password", systemImage: "key.horizontal")
                    }
                    .listRowBackground(NSTheme.row)
                    .disabled(model.server == nil)

                    Button(role: .destructive) {
                        Task { await model.logout() }
                    } label: {
                        Label("Sign out", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                    .listRowBackground(NSTheme.row)
                }

                Section {
                    Toggle(isOn: Binding(
                        get: { model.criticalAlertsEnabled },
                        set: { model.criticalAlertsEnabled = $0 }
                    )) {
                        Label("Critical alerts on this device", systemImage: "bell.badge.fill")
                    }
                    .listRowBackground(NSTheme.row)
                    .tint(NSTheme.danger)

                    Button {
                        Task { await CriticalAlertService.shared.requestPermission() }
                    } label: {
                        Label("Notification permission", systemImage: "bell")
                    }
                    .listRowBackground(NSTheme.row)

                    if let at = model.lastBackgroundPollAt {
                        LabeledContent("Last background poll") {
                            Text(at, style: .relative)
                                .foregroundStyle(NSTheme.muted)
                        }
                        .listRowBackground(NSTheme.row)
                    }
                } header: {
                    Text("Alerts")
                } footer: {
                    Text("Foreground: polls every few seconds. Background: continues briefly after you leave, then iOS wakes the app periodically (Background App Refresh). Turn on Background App Refresh in Settings → Network Sentinel. Use “Remember password” so background login works.")
                }

                // Web 0.4+ — the server's own outbound alerting. This is the one alert
                // path that survives the phone being asleep or the app force-quit, so it
                // sits next to the device alerts it backs up rather than in Detection.
                if let webhook = model.state?.settings?.webhookUrl {
                    Section {
                        Button {
                            webhookDraft = webhook
                            showWebhook = true
                        } label: {
                            Label {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Webhook URL")
                                        .foregroundStyle(NSTheme.text)
                                    Text(webhook.isEmpty ? "Off" : webhook)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(webhook.isEmpty ? NSTheme.muted : NSTheme.cyan)
                                        .lineLimit(2)
                                }
                            } icon: {
                                Image(systemName: "arrow.up.forward.app")
                                    .foregroundStyle(NSTheme.accent)
                            }
                        }
                        .listRowBackground(NSTheme.row)
                    } header: {
                        Text("Server webhook")
                    } footer: {
                        let status = model.state?.settings?.webhookStatus ?? ""
                        Text(
                            webhook.isEmpty || status.isEmpty
                                ? "The server POSTs Critical threats to this URL. ntfy, Slack and Discord are formatted automatically; anything else receives generic JSON. Unlike this device’s alerts, it keeps working when the phone is asleep."
                                : status
                        )
                    }
                }

                Section {
                    if let ports = model.state?.ports, !ports.isEmpty {
                        ForEach(ports.uniquedRows()) { row in
                            let p = row.value
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
                                Spacer(minLength: 8)
                                Button("Block") {
                                    Task {
                                        await model.blockPort(
                                            p.port,
                                            protocol: p.protocolName.uppercased(),
                                            direction: "Inbound"
                                        )
                                    }
                                }
                                .font(.caption.weight(.bold))
                                .foregroundStyle(NSTheme.danger)
                            }
                            .listRowBackground(NSTheme.row)
                            .swipeActions {
                                Button {
                                    Task {
                                        await model.blockPort(
                                            p.port,
                                            protocol: p.protocolName.uppercased(),
                                            direction: "Inbound"
                                        )
                                    }
                                } label: {
                                    Label("Block port", systemImage: "hand.raised.fill")
                                }
                                .tint(NSTheme.danger)
                            }
                        }
                    } else {
                        Text("No listeners")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.row)
                    }

                    Button {
                        blockPortText = ""
                        showBlockPort = true
                    } label: {
                        Label("Block port…", systemImage: "plus.circle")
                    }
                    .listRowBackground(NSTheme.row)
                } header: {
                    Text("Ports")
                } footer: {
                    Text("Block port uses the web 0.3+ API. Do not block the console’s own listen port.")
                }

                Section {
                    if let rules = model.state?.firewallRules, !rules.isEmpty {
                        ForEach(rules.uniquedRows()) { row in
                            let r = row.value
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(r.displayAddress)
                                        .font(.subheadline.monospaced().weight(.semibold))
                                        .foregroundStyle(NSTheme.text)
                                        .lineLimit(1)
                                    Spacer()
                                    if r.isProtectedRule {
                                        Text("PROTECTED")
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundStyle(NSTheme.warning)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(NSTheme.warning.opacity(0.15), in: Capsule())
                                    }
                                    Text(r.action ?? "block")
                                        .font(.caption2.weight(.bold))
                                        .foregroundStyle(NSTheme.danger)
                                }
                                if r.target != r.displayAddress {
                                    Text(r.target)
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(NSTheme.muted)
                                        .lineLimit(1)
                                }
                                Text(
                                    [r.direction, r.kind, r.protocolName, r.ports]
                                        .compactMap { $0 }
                                        .filter { !$0.isEmpty }
                                        .joined(separator: " · ")
                                )
                                .font(.caption)
                                .foregroundStyle(NSTheme.muted)
                                if let d = r.description, !d.isEmpty {
                                    Text(d)
                                        .font(.caption2)
                                        .foregroundStyle(NSTheme.muted)
                                        .lineLimit(2)
                                }
                            }
                            .listRowBackground(NSTheme.row)
                            .swipeActions(edge: .trailing, allowsFullSwipe: !r.isProtectedRule) {
                                if !r.isProtectedRule {
                                    Button(role: .destructive) {
                                        Task { await model.removeRule(named: r.name) }
                                    } label: {
                                        Label("Remove", systemImage: "trash")
                                    }
                                    // IP-style unblock when address looks like an IP
                                    if looksLikeIP(r.displayAddress) {
                                        Button {
                                            Task { await model.unblock(ip: r.displayAddress) }
                                        } label: {
                                            Label("Unblock", systemImage: "lock.open")
                                        }
                                        .tint(NSTheme.success)
                                    }
                                }
                            }
                        }
                    } else {
                        Text("No managed firewall rules")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.row)
                    }

                    Button {
                        Task { await model.authorizeFirewall() }
                    } label: {
                        Label("Authorize firewall", systemImage: "lock.open")
                    }
                    .listRowBackground(NSTheme.row)

                    Button(role: .destructive) {
                        confirmRemoveAll = true
                    } label: {
                        Label("Remove all managed rules", systemImage: "trash")
                    }
                    .listRowBackground(NSTheme.row)
                } header: {
                    Text("Firewall rules")
                } footer: {
                    if let priv = model.state?.firewall?.privilegeText {
                        Text(priv)
                    }
                }

                Section {
                    if let entries = model.state?.allowlist, !entries.isEmpty {
                        ForEach(entries.uniquedRows()) { row in
                            let e = row.value
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
                            .listRowBackground(NSTheme.row)
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
                            .listRowBackground(NSTheme.row)
                    }

                    Button {
                        showAddAllowlist = true
                    } label: {
                        Label("Add domain or IP", systemImage: "plus.circle")
                    }
                    .listRowBackground(NSTheme.row)

                    Button {
                        Task { await model.refreshAllowlist() }
                    } label: {
                        Label("Refresh allowlist", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .listRowBackground(NSTheme.row)

                    Button {
                        Task { await model.restoreAllowlisted() }
                    } label: {
                        Label("Restore good sites", systemImage: "arrow.uturn.backward.circle")
                    }
                    .listRowBackground(NSTheme.row)
                } header: {
                    Text("Allowlist")
                } footer: {
                    if let s = model.state?.allowlistStatus {
                        Text(s)
                    }
                }

                Section("About") {
                    LabeledContent("App", value: "Network Sentinel iOS")
                        .listRowBackground(NSTheme.row)
                    LabeledContent("Server version", value: model.state?.version ?? "—")
                        .listRowBackground(NSTheme.row)
                    LabeledContent("Poll interval", value: "\(Int(model.pollInterval * 10) / 10)s")
                        .listRowBackground(NSTheme.row)
                }
            }
            .scrollContentBackground(.hidden)
            .background { AmbientField() }
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
            .sheet(isPresented: $showChangePassword) {
                ChangePasswordView()
                    .preferredColorScheme(.dark)
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
            .alert("Webhook URL", isPresented: $showWebhook) {
                TextField("https://ntfy.sh/your-topic", text: $webhookDraft)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Save") {
                    Task { await model.setWebhookURL(webhookDraft) }
                }
                Button("Turn off", role: .destructive) {
                    Task { await model.setWebhookURL("") }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Where the server posts Critical threats. Leave empty to switch webhook alerts off.")
            }
            .alert("Block port", isPresented: $showBlockPort) {
                TextField("Port number", text: $blockPortText)
                    .keyboardType(.numberPad)
                Button("Block TCP inbound") {
                    submitBlockPort(proto: "TCP", direction: "Inbound")
                }
                Button("Block UDP inbound") {
                    submitBlockPort(proto: "UDP", direction: "Inbound")
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Enter a port 1–65535. Do not block the web console port.")
            }
            .confirmationDialog(
                "Remove all Network Sentinel firewall rules?",
                isPresented: $confirmRemoveAll,
                titleVisibility: .visible
            ) {
                Button("Remove all", role: .destructive) {
                    Task { await model.removeAllRules() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Deletes managed IP/port rules. The web console’s protected allow rule is left alone when possible.")
            }
            .refreshable { await model.refresh(silent: false) }
        }
    }

    private func submitBlockPort(proto: String, direction: String) {
        let trimmed = blockPortText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(trimmed), (1...65535).contains(port) else {
            model.lastError = "Enter a valid port (1–65535)."
            return
        }
        Task { await model.blockPort(port, protocol: proto, direction: direction) }
    }

    private func looksLikeIP(_ s: String) -> Bool {
        // Simple check — enough to enable Unblock swipe for IP rules.
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.contains(":") { return t.contains(".") == false } // rough IPv6
        let parts = t.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { Int($0) != nil }
    }
}
