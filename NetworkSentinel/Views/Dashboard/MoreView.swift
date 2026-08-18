import SwiftUI

struct MoreView: View {
    /// Switches to the Firewall tab. The screen lives there now, so this list points at it
    /// rather than pushing a second copy onto its own stack — the same shape Status uses to
    /// hand the Threats tab a tap.
    var onOpenFirewall: () -> Void = {}

    @Environment(AppModel.self) private var model
    @State private var showServers = false
    @State private var showEditServer = false
    @State private var showChangePassword = false
    @State private var allowlistValue = ""
    @State private var showAddAllowlist = false
    @State private var showBlockPort = false
    @State private var blockPortText = ""
    @State private var showBlockIP = false
    @State private var blockIPText = ""
    @State private var pendingRuleRemoval: FirewallRuleGroup?
    @State private var confirmRemoveAll = false
    @State private var showWebhook = false
    @State private var webhookDraft = ""
    @State private var textEdit: TextSettingEdit?
    @State private var textEditDraft = ""

    private var settings: SettingsInfo? { model.state?.settings }

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

                // The web console keeps the same control in two places — the header button
                // and Settings → Live monitoring — because the tab you are on when you
                // want it is rarely the one holding it. Same reasoning here.
                Section {
                    Button {
                        Task { await model.toggleSleep() }
                    } label: {
                        Label(
                            model.isAsleep ? "Wake console" : "Put console to sleep",
                            systemImage: model.isAsleep ? "sun.max.fill" : "moon.zzz.fill"
                        )
                    }
                    .listRowBackground(NSTheme.row)
                    .disabled(model.server == nil)
                } header: {
                    Text("Monitoring")
                } footer: {
                    Text(model.isAsleep
                         ? "Asleep: every watcher on the server is stopped, and this app drops to a 30-second heartbeat so a wake from the web console still reaches you. Firewall blocks stay in force."
                         : "Sleep stops everything the server watches — connections, listening ports, auth log, port-scan probes, ARP, startup items, exfiltration, honeypot, and on 0.6 servers the DNS, WireGuard, Suricata and kernel-event feeds too — and quiets this app until you wake it. Firewall blocks stay in force: sleeping stops watching, it never unblocks anything.")
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

                remoteAccessSections

                Section {
                    if let ports = model.state?.ports, !ports.isEmpty {
                        let blockedPorts = (model.state?.firewallRules ?? []).blockedPortKeys()
                        ForEach(ports.uniquedRows()) { row in
                            let p = row.value
                            let proto = p.protocolName.uppercased()
                            let isBlocked = blockedPorts.contains("\(proto)/\(p.port)")
                            HStack {
                                Text(proto)
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
                                // A port already carrying a managed rule needs the opposite
                                // button: Block there did nothing but re-write the same rule.
                                if isBlocked {
                                    Text("BLOCKED")
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundStyle(NSTheme.danger)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(NSTheme.danger.opacity(0.15), in: Capsule())
                                    Button("Unblock") {
                                        Task { await model.unblockPort(p.port, protocol: proto) }
                                    }
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(NSTheme.success)
                                } else {
                                    Button("Block") {
                                        Task {
                                            await model.blockPort(
                                                p.port,
                                                protocol: proto,
                                                direction: "Inbound"
                                            )
                                        }
                                    }
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(NSTheme.danger)
                                }
                            }
                            .listRowBackground(NSTheme.row)
                            .swipeActions {
                                if isBlocked {
                                    Button {
                                        Task { await model.unblockPort(p.port, protocol: proto) }
                                    } label: {
                                        Label("Unblock port", systemImage: "lock.open")
                                    }
                                    .tint(NSTheme.success)
                                } else {
                                    Button {
                                        Task {
                                            await model.blockPort(
                                                p.port,
                                                protocol: proto,
                                                direction: "Inbound"
                                            )
                                        }
                                    } label: {
                                        Label("Block port", systemImage: "hand.raised.fill")
                                    }
                                    .tint(NSTheme.danger)
                                }
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
                    Text("Block port uses the web 0.3+ API. Do not block the console’s own listen port. A blocked port that has stopped listening drops off this list — lift it under Firewall rules.")
                }

                firewallRulesSection

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
            .alert("Block an IP", isPresented: $showBlockIP) {
                TextField("IP address", text: $blockIPText)
                    .keyboardType(.numbersAndPunctuation)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Block", role: .destructive) {
                    let ip = blockIPText.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !ip.isEmpty else { return }
                    Task {
                        await model.requestBlock(ip: ip)
                        blockIPText = ""
                    }
                }
                Button("Cancel", role: .cancel) { blockIPText = "" }
            } message: {
                Text("Writes an inbound and outbound block rule on the server, the same as the web console’s Block IP.")
            }
            .confirmationDialog(
                "Remove this firewall rule?",
                isPresented: Binding(
                    get: { pendingRuleRemoval != nil },
                    set: { if !$0 { pendingRuleRemoval = nil } }
                ),
                titleVisibility: .visible
            ) {
                if let group = pendingRuleRemoval {
                    Button("Remove \(group.primary.displayAddress)", role: .destructive) {
                        Task { await model.removeRule(named: group.primary.name) }
                        pendingRuleRemoval = nil
                    }
                    Button("Cancel", role: .cancel) { pendingRuleRemoval = nil }
                }
            } message: {
                Text("Lifts the block: the server deletes the inbound and outbound rules together and holds auto-block off this target for 24 hours.")
            }
            .nsTextSettingAlert($textEdit, draft: $textEditDraft)
            .refreshable { await model.refresh(silent: false) }
        }
    }

    // MARK: - Firewall rules
    //
    // The web console's Firewall tab, mirrored: one row per block, with the Remove button
    // on the row rather than behind a swipe. Swipe-only removal was why blocking looked
    // one-way from the phone — the Block buttons were the only firewall control on screen.

    @ViewBuilder
    private var firewallRulesSection: some View {
        Section {
            // Blocks are written as an -In/-Out pair, so the raw list shows each one twice
            // and removing either half clears both. Group them the way the web console does.
            let groups = (model.state?.firewallRules ?? []).groupedByBlock()
            if groups.isEmpty {
                Text("No managed firewall rules")
                    .foregroundStyle(NSTheme.muted)
                    .listRowBackground(NSTheme.row)
            } else {
                ForEach(groups) { group in
                    firewallRuleRow(group)
                }
            }

            Button {
                blockIPText = ""
                showBlockIP = true
            } label: {
                Label("Block IP…", systemImage: "plus.circle")
            }
            .listRowBackground(NSTheme.row)

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
            VStack(alignment: .leading, spacing: 4) {
                Text("Each row is one block. Remove deletes its inbound and outbound rules together and keeps auto-block from putting the same target back for 24 hours.")
                if let priv = model.state?.firewall?.privilegeText {
                    Text(priv)
                }
            }
        }

        // Web 0.7+. The whole host firewall has its own tab now, so this is a signpost
        // rather than a second way in: two navigation paths to one screen is how the same
        // list ends up open twice on a phone, once pushed and once rooted.
        //
        // It stays a separate thing from the section above and always was: that one is the
        // blocks the engine and this app minted, this is every rule the firewall evaluates,
        // and folding them together is what would make a permissive rule above a block
        // invisible.
        if let configRules = model.state?.configRules {
            Section {
                Button {
                    onOpenFirewall()
                } label: {
                    HStack {
                        Label("Firewall Config", systemImage: "shield.lefthalf.filled")
                        Spacer(minLength: 8)
                        Text("\(configRules.count)")
                            .font(.caption.monospaced())
                            .foregroundStyle(NSTheme.muted)
                        Image(systemName: "arrow.up.forward.app")
                            .font(.caption)
                            .foregroundStyle(NSTheme.muted)
                    }
                }
                .listRowBackground(NSTheme.row)
            } footer: {
                Text("Every rule the firewall evaluates, in the order it evaluates them — engine blocks first, then rules you configure — is on the Firewall tab, with the listening sockets under it. Add, edit and remove them there.")
            }
        }
    }

    @ViewBuilder
    private func firewallRuleRow(_ group: FirewallRuleGroup) -> some View {
        let rule = group.primary
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(rule.displayAddress)
                    .font(.subheadline.monospaced().weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)
                Spacer(minLength: 8)
                if group.isProtected {
                    ruleChip("PROTECTED", color: NSTheme.warning)
                }
                Text(rule.action ?? "Block")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(NSTheme.danger)
            }

            if rule.target != rule.displayAddress {
                Text(rule.target)
                    .font(.caption2.monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
            }

            // Directions come from the pair, so a block missing its outbound half is
            // visible here instead of silently reading as fully blocked.
            HStack(spacing: 6) {
                ForEach(Array(group.directions.enumerated()), id: \.offset) { _, direction in
                    ruleChip(direction, color: NSTheme.accent)
                }
                ruleChip(group.isEnabled ? "On" : "Off",
                         color: group.isEnabled ? NSTheme.success : NSTheme.muted)
                Text(
                    [rule.kind, rule.protocolName, rule.ports]
                        .compactMap { $0 }
                        .filter { !$0.isEmpty && $0 != "Any" }
                        .joined(separator: " · ")
                )
                .font(.caption)
                .foregroundStyle(NSTheme.muted)
                .lineLimit(1)
            }

            if let detail = rule.description, !detail.isEmpty {
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(2)
            }

            HStack {
                Text(group.id)
                    .font(.system(size: 10).monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
                Spacer(minLength: 8)
                if group.isProtected {
                    // Removing this one from here would cut the app off from the console.
                    Text("this console")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                } else {
                    Button("Remove") { pendingRuleRemoval = group }
                        .font(.caption.weight(.bold))
                        .foregroundStyle(NSTheme.success)
                        .buttonStyle(.borderless)
                }
            }
        }
        .listRowBackground(NSTheme.row)
        .swipeActions(edge: .trailing, allowsFullSwipe: !group.isProtected) {
            if !group.isProtected {
                Button(role: .destructive) {
                    pendingRuleRemoval = group
                } label: {
                    Label("Remove", systemImage: "trash")
                }
            }
        }
    }

    private func ruleChip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
    }

    // MARK: - Remote access (web 0.5+)
    //
    // How this phone reaches the console, which is why it lives in More rather than on the
    // Dashboard with the detectors. Kestrel binds its endpoints at startup, so every field
    // here is saved now and served after the next restart — `httpsActive` is the only one
    // that says what is actually on the wire, so the section leads with it.
    //
    // Grouped into one member so the List keeps room under ViewBuilder's ten-child limit.

    @ViewBuilder
    private var remoteAccessSections: some View {
        httpsSection
        duckDnsSection
    }

    @ViewBuilder
    private var httpsSection: some View {
        if let enabled = settings?.httpsEnabled {
            let active = settings?.httpsActive ?? false
            Section {
                LabeledContent("This connection") {
                    Text(active ? "HTTPS" : "Plain HTTP")
                        .foregroundStyle(active ? NSTheme.success : NSTheme.warning)
                }
                .listRowBackground(NSTheme.row)

                Toggle(isOn: Binding(
                    get: { enabled },
                    set: { on in Task { await model.setHttpsEnabled(on) } }
                )) {
                    Label("Serve HTTPS", systemImage: "lock.fill")
                }
                .listRowBackground(NSTheme.row)
                .tint(NSTheme.accent)

                if let port = settings?.httpsPort {
                    numericSettingRow(
                        title: "HTTPS port",
                        value: "\(port)",
                        edit: TextSettingEdit(
                            id: "httpsPort",
                            title: "HTTPS port",
                            placeholder: "18766",
                            message: "1–65535, and not the port already serving this console.",
                            keyboard: .numberPad,
                            apply: { await model.setHttpsPort($0) }
                        )
                    )
                }

                if let redirect = settings?.httpsRedirect {
                    Toggle(isOn: Binding(
                        get: { redirect },
                        set: { on in Task { await model.setHttpsRedirect(on) } }
                    )) {
                        Label("Redirect HTTP to HTTPS", systemImage: "arrow.turn.up.right")
                    }
                    .listRowBackground(NSTheme.row)
                    .tint(NSTheme.accent)
                }

                // The server loads the pair as soon as it is saved, so a bad path is
                // reported now rather than as a console that fails to come back up.
                pathSettingRow(
                    title: "Certificate",
                    value: settings?.tlsCertPath,
                    edit: TextSettingEdit(
                        id: "tlsCertPath",
                        title: "Certificate path",
                        placeholder: "/etc/letsencrypt/live/host/fullchain.pem",
                        message: "Absolute path on the server. HTTPS cannot start without it.",
                        keyboard: .URL,
                        apply: { await model.setTlsCertPath($0) }
                    )
                )

                pathSettingRow(
                    title: "Private key",
                    value: settings?.tlsKeyPath,
                    edit: TextSettingEdit(
                        id: "tlsKeyPath",
                        title: "Private key path",
                        placeholder: "/etc/letsencrypt/live/host/privkey.pem",
                        message: "Absolute path on the server. Leave empty when the certificate file already carries the key.",
                        keyboard: .URL,
                        apply: { await model.setTlsKeyPath($0) }
                    )
                )
            } header: {
                Text("Remote access")
            } footer: {
                Text(settings?.httpsStatus?.isEmpty == false
                     ? settings!.httpsStatus!
                     : "TLS endpoints are bound when the console starts, so changes here take effect after you restart it.")
            }
        }
    }

    @ViewBuilder
    private var duckDnsSection: some View {
        if let enabled = settings?.duckDnsEnabled {
            let busy = settings?.certIssueBusy ?? false
            Section {
                Toggle(isOn: Binding(
                    get: { enabled },
                    set: { on in Task { await model.setDuckDnsEnabled(on) } }
                )) {
                    Label("Keep DuckDNS updated", systemImage: "globe.badge.chevron.backward")
                }
                .listRowBackground(NSTheme.row)
                .tint(NSTheme.accent)

                pathSettingRow(
                    title: "Subdomain",
                    value: settings?.duckDnsDomain.map { $0.isEmpty ? "" : "\($0).duckdns.org" },
                    draft: settings?.duckDnsDomain,
                    edit: TextSettingEdit(
                        id: "duckDnsDomain",
                        title: "DuckDNS subdomain",
                        placeholder: "myhost",
                        message: "The label only, e.g. myhost — the .duckdns.org part is added for you.",
                        keyboard: .URL,
                        apply: { await model.setDuckDnsDomain($0) }
                    )
                )

                // Write-only: the server sends back whether a token is stored, never the
                // token, so there is nothing to pre-fill and nothing to leak to this phone.
                Button {
                    textEditDraft = ""
                    textEdit = TextSettingEdit(
                        id: "duckDnsToken",
                        title: "DuckDNS token",
                        placeholder: "token",
                        message: "The server never sends a stored token back, so this always starts empty. Save an empty field to clear it.",
                        apply: { await model.setDuckDnsToken($0) }
                    )
                } label: {
                    LabeledContent("Token") {
                        Text((settings?.duckDnsTokenSet ?? false) ? "Stored" : "Not set")
                            .foregroundStyle((settings?.duckDnsTokenSet ?? false) ? NSTheme.success : NSTheme.muted)
                    }
                }
                .listRowBackground(NSTheme.row)

                pathSettingRow(
                    title: "Let's Encrypt email",
                    value: settings?.acmeEmail,
                    edit: TextSettingEdit(
                        id: "acmeEmail",
                        title: "Let's Encrypt email",
                        placeholder: "you@example.com",
                        message: "Account address for expiry notices. Optional.",
                        keyboard: .emailAddress,
                        apply: { await model.setAcmeEmail($0) }
                    )
                )

                Button {
                    Task { await model.issueCertificate() }
                } label: {
                    HStack {
                        Label("Issue certificate", systemImage: "seal")
                        if busy {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .listRowBackground(NSTheme.row)
                .disabled(busy || model.server == nil)

                // Issuance waits on DNS propagation and runs for minutes, so its outcome
                // arrives in state rather than in the action's own reply — an action toast
                // would have vanished long before there was anything to say.
                if let message = settings?.certIssueMessage, !message.isEmpty {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle((settings?.certIssueOk ?? false) ? NSTheme.success : NSTheme.muted)
                        .listRowBackground(NSTheme.row)
                }
            } header: {
                Text("Dynamic DNS & certificate")
            } footer: {
                Text(settings?.duckDnsStatus?.isEmpty == false
                     ? settings!.duckDnsStatus!
                     : "Issuance proves control of the name through DuckDNS, so the subdomain and token have to be saved first.")
            }
        }
    }

    /// Row for a server path or name, showing what is stored and opening the editor.
    ///
    /// `draft` is what the field starts with, which is not always what the row displays —
    /// the DuckDNS row reads `myhost.duckdns.org` but the server takes the label alone.
    private func pathSettingRow(
        title: String,
        value: String?,
        draft: String? = nil,
        edit: TextSettingEdit
    ) -> some View {
        Button {
            // Pre-fill with what the server has: nobody retypes an absolute path.
            textEditDraft = draft ?? value ?? ""
            textEdit = edit
        } label: {
            LabeledContent(title) {
                Text(value?.isEmpty == false ? value! : "Not set")
                    .font(.caption.monospaced())
                    .foregroundStyle(value?.isEmpty == false ? NSTheme.cyan : NSTheme.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .listRowBackground(NSTheme.row)
    }

    private func numericSettingRow(title: String, value: String, edit: TextSettingEdit) -> some View {
        Button {
            textEditDraft = value
            textEdit = edit
        } label: {
            LabeledContent(title) {
                Text(value)
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.cyan)
            }
        }
        .listRowBackground(NSTheme.row)
    }

    private func submitBlockPort(proto: String, direction: String) {
        let trimmed = blockPortText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(trimmed), (1...65535).contains(port) else {
            model.lastError = "Enter a valid port (1–65535)."
            return
        }
        Task { await model.blockPort(port, protocol: proto, direction: direction) }
    }
}
