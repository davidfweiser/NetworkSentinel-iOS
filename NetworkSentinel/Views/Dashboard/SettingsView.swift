import SwiftUI

/// **Settings** — the console's last rail entry, with **Help** under it.
///
/// What this holds is what the console's Settings page holds and what only this app can hold:
/// which server it is talking to, how it alerts *this device*, the server's own webhook, and
/// remote access. The firewall lists that used to sit here moved to Firewall & Block, where
/// the console's rail and the desktop's menu have always kept them.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var showServers = false
    @State private var showEditServer = false
    @State private var showChangePassword = false
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
                    NavigationLink {
                        HelpView()
                    } label: {
                        Label("Help", systemImage: "questionmark.circle")
                    }
                    .listRowBackground(NSTheme.row)
                } footer: {
                    Text("What each section does, and what Sleep, elevation and the master password mean — the console's Help page, which sits under Settings there too.")
                }

                Section("About") {
                    LabeledContent("App", value: "Network Sentinel iOS")
                        .listRowBackground(NSTheme.row)
                    LabeledContent("Server version", value: model.state?.version ?? "—")
                        .listRowBackground(NSTheme.row)
                    LabeledContent("Poll interval", value: "\(model.pollInterval.formatted())s")
                        .listRowBackground(NSTheme.row)
                }
            }
            .scrollContentBackground(.hidden)
            .background { AmbientField() }
            .navigationTitle("Settings")
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
            .nsTextSettingAlert($textEdit, draft: $textEditDraft)
            .refreshable { await model.refresh(silent: false) }
        }
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

}
