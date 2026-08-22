import SwiftUI

/// **Settings** — the console's Settings page, entire.
///
/// It used to be a shorter thing: the server this app talks to, how it alerts *this device*,
/// the webhook and remote access, with the eighteen detector switches living on a Detection
/// screen of the app's own invention and the four enforcement switches on an Enforcement
/// sheet. Three screens, three groupings, none of them the console's.
///
/// The console has one page with ten groups, and every other front-end for this server —
/// the desktop window, the terminal UI — has the same ten. So does this now: Monitoring,
/// Intrusion detection, DNS hygiene, VPN, Signatures, Alerting, Remote access, Auto-block,
/// Allowlist, Danger zone, in that order, with the console's own titles and the console's own
/// sentence under each. Anything the browser can change on this server, this can change.
///
/// Two things are here that the console has no need of. **Server** is first, because a phone
/// talks to several consoles and a browser is already at one. And the filter box at the top
/// is a phone's answer to forty-odd rows that fit on a 1400px desktop in one screen and take
/// eleven scrolls here.
struct SettingsView: View {
    @Environment(AppModel.self) private var model

    @State private var query = ""
    @State private var showServers = false
    @State private var showEditServer = false
    @State private var showChangePassword = false
    @State private var showWireGuardPeers = false
    @State private var confirmRemoveAll = false
    @State private var textEdit: TextSettingEdit?
    @State private var textEditDraft = ""

    private var settings: SettingsInfo? { model.state?.settings }

    var body: some View {
        NavigationStack {
            ConsoleScreen(severity: model.liveSeverity, load: model.activityLoad) {
                ConsoleSearchField(text: $query, placeholder: "Filter settings…")

                if model.isAsleep {
                    SleepBanner { Task { await model.wakeConsole() } }
                }

                serverGroup
                stalledCallout
                monitoringGroup
                intrusionGroup
                dnsGroup
                dnsFilterGroup
                wireGuardGroup
                suricataGroup
                alertingGroup
                remoteAccessGroup
                autoBlockGroup
                allowlistGroup
                dangerZoneGroup
                aboutGroup

                if !query.isEmpty && !anyGroupMatches {
                    Text("No setting matches “\(query)”.")
                        .font(.system(size: 13))
                        .foregroundStyle(NSTheme.dim)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 28)
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .consoleRailToolbar()
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if let version = model.state?.version {
                        Text("v\(version)")
                            .font(.system(size: 12).monospaced())
                            .foregroundStyle(NSTheme.dim)
                    }
                }
            }
            .refreshable { await model.refresh(silent: false) }
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
            .sheet(isPresented: $showWireGuardPeers) {
                WireGuardPeersView(
                    peers: settings?.wireGuardPeers ?? [],
                    status: settings?.wireGuardStatus
                )
                .preferredColorScheme(.dark)
            }
            .confirmationDialog(
                "Remove every block rule?",
                isPresented: $confirmRemoveAll,
                titleVisibility: .visible
            ) {
                Button("Remove all rules", role: .destructive) {
                    Task { await model.removeAllRules() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Deletes every Network Sentinel block rule — the access rule for this console is kept — and stops auto-block from re-adding them for 24 hours.")
            }
            .nsTextSettingAlert($textEdit, draft: $textEditDraft)
        }
    }

    // MARK: - Server
    //
    // Not a console group: a browser is already at the console it is configuring, and this
    // app is not. Which server, and the credentials for it, come before anything the server
    // itself holds — every group below is meaningless until this one names a machine.

    @ViewBuilder
    private var serverGroup: some View {
        let rows = [
            row(
                "server.pick", "Server",
                "Which console this app is talking to. Everything below is that machine's own configuration, read from and written back to it.",
                control: AnyView(
                    Button {
                        showServers = true
                    } label: {
                        HStack(spacing: 6) {
                            Text(model.server?.displayHost ?? "None")
                                .font(.system(size: 13).monospaced())
                                .foregroundStyle(NSTheme.signal)
                                .lineLimit(1)
                                .truncationMode(.head)
                            Image(systemName: "chevron.up.chevron.down")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(NSTheme.dim)
                        }
                        .frame(minWidth: 96, maxWidth: 130, alignment: .trailing)
                    }
                    .buttonStyle(.plain)
                )
            ),
            row(
                "server.edit", "Address and name",
                "The host, port and any reverse-proxy subpath this app dials, and what to call it in the switcher.",
                control: AnyView(
                    Button("Edit") { showEditServer = true }
                        .buttonStyle(.console(.ghost, compact: true))
                        .disabled(model.server == nil)
                )
            ),
            row(
                "server.password", "Master password",
                "The one credential this console has. Changing it here changes it on the server, and signs every other browser and device out.",
                control: AnyView(
                    Button("Change") { showChangePassword = true }
                        .buttonStyle(.console(.ghost, compact: true))
                        .disabled(model.server == nil)
                )
            ),
            row(
                "server.signout", "Sign out",
                "Drops this device's session and forgets the saved password. The server keeps monitoring and keeps every block in force.",
                control: AnyView(
                    Button("Sign out") { Task { await model.logout() } }
                        .buttonStyle(.console(.danger, compact: true))
                )
            )
        ]
        group("Server", rows: rows)
    }

    // MARK: - On, but not running
    //
    // A detector switched on that the server cannot actually run reads as covered when it is
    // not — the worst state to leave unnamed, and worth interrupting the page for. The
    // console does not draw this because it appends each detector's status to its own row and
    // a desktop shows twenty rows at once; a phone shows three.

    @ViewBuilder
    private var stalledCallout: some View {
        if query.isEmpty, let stalled = Detector.all(settings: settings, model: model).first(where: \.isStalled) {
            HStack(alignment: .top, spacing: 11) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(NSTheme.warning)
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(stalled.title) is on, but not running")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(NSTheme.text)
                    if let status = stalled.status, !status.isEmpty {
                        Text(status)
                            .font(.system(size: 12))
                            .foregroundStyle(NSTheme.mutedOnTint)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 6)
                Button("Authorize") {
                    Task { await model.authorizeFirewall() }
                }
                .buttonStyle(.console(.wake, compact: true))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(NSTheme.warning.opacity(0.08), in: .rect(cornerRadius: 10))
            .overlay(
                RoundedRectangle(cornerRadius: 10).stroke(NSTheme.warning.opacity(0.45), lineWidth: 1)
            )
        }
    }

    // MARK: - Monitoring

    @ViewBuilder
    private var monitoringGroup: some View {
        let s = settings
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "monitoring", "Live monitoring",
                "Watch connections, listening ports, and threats in real time. Switching this off is the same as the Sleep button — every watcher stops until you wake it again. Firewall blocks stay in force either way.",
                // The console's own switch calls `toggleSleep`, not a setting: sleeping is
                // what "not monitoring" means on every front-end.
                isOn: s?.isMonitoring.map { $0 && !model.isAsleep }
            ) { _ in await model.toggleSleep() },

            row(
                "refresh", "Page refresh speed",
                "How often the live screens — Dashboard, Connections, Break-ins — update on this phone. A per-device choice, as it is per-browser in the console.",
                control: AnyView(
                    ConsoleSelect(
                        options: AppModel.pollIntervalChoices,
                        selection: Binding(
                            get: { model.awakePollInterval },
                            set: { model.awakePollInterval = $0 }
                        ),
                        label: Self.refreshLabel
                    )
                )
            ),

            toggleRow(
                "geoLookupEnabled", "Geo lookups",
                "Resolve country and city for remote IPs (ipwho.is, ipapi.co fallback — both over HTTPS).",
                isOn: s?.geoLookupEnabled
            ) { await model.setGeoLookup($0) },

            toggleRow(
                "authLogMonitorEnabled", "Auth-log monitoring",
                "Watch system auth logs for failed SSH/PAM logons and alert on brute-force bursts.",
                status: s?.authLogStatus, isOn: s?.authLogMonitorEnabled
            ) { await model.setAuthLogMonitor($0) },

            toggleRow(
                "probeLogEnabled", "Closed-port scan detection",
                "Install a rate-limited firewall SYN-log rule (needs elevation) and watch the kernel log — catches port scans of closed ports that never appear as connections.",
                status: s?.probeLogStatus, isOn: s?.probeLogEnabled
            ) { await model.setProbeLog($0) },

            toggleRow(
                "conntrackEventsEnabled", "Kernel flow events",
                "Sample the moment the kernel reports a new inbound flow instead of waiting out the poll interval — detection in well under a second instead of up to one full cycle. Needs root; falls back to timed polling otherwise.",
                status: s?.conntrackStatus, isOn: s?.conntrackEventsEnabled
            ) { await model.setConntrackEvents($0) },

            toggleRow(
                "trafficMeterEnabled", "Traffic metering",
                "Sample the interface byte counters for the dashboard's data-flow charts and the monthly in/out history. Physical interfaces only, so VPN and container traffic is counted once.",
                status: s?.trafficStatus, isOn: s?.trafficMeterEnabled
            ) { await model.setTrafficMeter($0) },

            toggleRow(
                "criticalAlertsEnabled", "Critical threat alerts",
                "Warn from the server itself when a Critical-level threat appears — a desktop notification from its GUI, a tab badge in its browser console. Separate from this phone's own alerts, below.",
                isOn: s?.criticalAlertsEnabled
            ) { await model.setServerCriticalAlerts($0) }
        ]
        group("Monitoring", rows: rows)
    }

    private static func refreshLabel(_ interval: TimeInterval) -> String {
        interval == 1 ? "1 second" : "\(interval.formatted()) seconds"
    }

    // MARK: - Intrusion detection

    @ViewBuilder
    private var intrusionGroup: some View {
        let s = settings
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "threatIntelEnabled", "Threat-intel blocklists",
                "Check remote IPs against FireHOL level1 and Spamhaus DROP — a match is an instant Critical alert.",
                status: s?.threatIntelStatus, isOn: s?.threatIntelEnabled
            ) { await model.setThreatIntel($0) },

            toggleRow(
                "newListenerAlertsEnabled", "New-listener alerts",
                "Alert when a new port starts listening after the baseline, or a known port changes owner process (backdoor signature).",
                isOn: s?.newListenerAlertsEnabled
            ) { await model.setNewListenerAlerts($0) },

            toggleRow(
                "processReputationEnabled", "Process reputation",
                "Flag system binaries no package owns, processes running only from memory, executables in temp/download folders, and shells with outbound connections (reverse-shell signature).",
                isOn: s?.processReputationEnabled
            ) { await model.setProcessReputation($0) },

            toggleRow(
                "arpWatchEnabled", "ARP / gateway watch",
                "Alert when the default gateway MAC address changes — the standard LAN man-in-the-middle opener.",
                status: s?.arpWatchStatus, isOn: s?.arpWatchEnabled
            ) { await model.setArpWatch($0) },

            // Named after what it actually watches on this host: systemd units and cron on
            // Linux, launch items on macOS. The server answers to only one of the two keys.
            toggleRow(
                "persistenceWatchEnabled", s?.startupWatchTitle ?? "Startup-item watch",
                "Watch systemd units, cron directories and autostart entries for new or modified startup items — how malware persists across reboots.",
                status: s?.startupWatchStatus, isOn: s?.startupWatchEnabled
            ) { await model.setStartupItemWatch($0) },

            toggleRow(
                "exfilMonitorEnabled", "Exfiltration monitor",
                "Alert when outbound traffic to one non-allowlisted public host exceeds the threshold within 10 minutes (per-socket byte counters).",
                status: s?.exfilStatus, isOn: s?.exfilMonitorEnabled
            ) { await model.setExfilMonitor($0) },

            s?.exfilMbPer10Min.map { mb in
                row(
                    "exfilMbPer10Min", "Exfiltration threshold (MB / 10 min)",
                    "Outbound megabytes to a single host before the alert fires. The server's floor is 10.",
                    control: AnyView(
                        ConsoleSelect(
                            options: Self.exfilChoices.contains(mb) ? Self.exfilChoices : [mb] + Self.exfilChoices,
                            selection: Binding(
                                get: { mb },
                                set: { v in Task { await model.setExfilThreshold(v) } }
                            ),
                            label: { "\($0) MB" }
                        )
                    )
                )
            },

            toggleRow(
                "honeypotEnabled", "Honeypot decoy ports",
                "Listen on decoy TCP ports nothing legitimate uses — any completed connection is a zero-false-positive Critical alert.",
                status: s?.honeypotStatus, isOn: s?.honeypotEnabled
            ) { await model.setHoneypot($0) },

            textRow(
                "honeypotPorts", "Decoy port list",
                "Comma-separated TCP ports to bind as decoys. Ports already in use are skipped.",
                value: s?.honeypotPorts,
                edit: TextSettingEdit(
                    id: "honeypotPorts",
                    title: "Decoy port list",
                    placeholder: "2323,3389,5900",
                    message: "Comma-separated TCP ports nothing legitimate uses. The server refuses its own console port.",
                    keyboard: .numbersAndPunctuation,
                    apply: { await model.setHoneypotPorts($0) }
                )
            )
        ]
        group("Intrusion detection", rows: rows)
    }

    private static let exfilChoices = [10, 50, 100, 250, 500, 1000, 2000]

    // MARK: - DNS hygiene

    @ViewBuilder
    private var dnsGroup: some View {
        let s = settings
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "dnsHygieneEnabled", "DNS hygiene monitoring",
                "Detect plaintext queries leaving the host, encrypted DNS silently falling back, queries to unapproved resolvers, VPN clients bypassing your resolver, and allowlisted domains moving networks.",
                status: s?.dnsHygieneStatus, isOn: s?.dnsHygieneEnabled
            ) { await model.setDnsHygiene($0) },

            textRow(
                "dnsApprovedResolvers", "Approved resolvers",
                "Comma-separated resolver IPs this host is meant to use. Queries anywhere else are flagged, and HTTPS to these addresses is counted as DoH instead of ordinary web traffic.",
                value: s?.dnsApprovedResolvers,
                edit: TextSettingEdit(
                    id: "dnsApprovedResolvers",
                    title: "Approved resolvers",
                    placeholder: "10.8.0.1, 127.0.0.53",
                    message: "Resolver IP addresses, separated by commas. Leave empty to report every plaintext query and recognise no DoH endpoint.",
                    keyboard: .numbersAndPunctuation,
                    apply: { await model.setDnsApprovedResolvers($0) }
                )
            )
        ]
        group(
            "DNS hygiene",
            note: "Almost nothing connects without resolving a name first, so DNS is where a compromise usually shows earliest — and it is a standard exfiltration channel the exfiltration monitor cannot see, since that counts TCP socket bytes and DNS is UDP. Reads kernel flow events, so it needs root. Port 53 is detected as plaintext and 853 as DoT; DoH is HTTPS and can only be recognised when you list the resolver below.",
            rows: rows
        )
    }

    // MARK: - DNS filtering
    //
    // Web 0.7.15, and the only group on this page whose switch stops a connection from ever
    // being attempted. Every other control here acts on a flow that already exists — and on a
    // VPN gateway a client's forwarded traffic never becomes a tracked connection at all, so
    // nothing else in this app can decide where a tunnel client goes. A resolver that refuses
    // to answer can.

    @ViewBuilder
    private var dnsFilterGroup: some View {
        let s = settings
        let passwordSet = s?.dnsFilterPasswordSet ?? false
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "dnsFilterEnabled", "DNS filtering",
                "Refuse known malware, phishing and tracking names at the resolver, before anything connects. This switches filtering, not the resolver — turning it off leaves DNS answering normally but unfiltered, so no client loses name resolution.",
                status: s?.dnsFilterStatus, isOn: s?.dnsFilterEnabled
            ) { await model.setDnsFilterEnabled($0) },

            textRow(
                "dnsFilterUrl", "Filtering resolver",
                "Admin API of the filtering resolver on this node. The server's setup script fills this in; clear it to leave the switch unconfigured — and to take Blocked Sites off the menu with it.",
                value: s?.dnsFilterUrl,
                placeholder: "Not configured",
                edit: TextSettingEdit(
                    id: "dnsFilterUrl",
                    title: "Filtering resolver",
                    placeholder: "10.8.0.1:3000",
                    message: "Address of the resolver's admin API — a host, a host:port, or a full URL. The server fills in the rest and refuses what it cannot use.",
                    keyboard: .URL,
                    apply: { await model.setDnsFilterUrl($0) }
                )
            ),

            textRow(
                "dnsFilterUsername", "Resolver user",
                "Admin user for that API — “admin” for an AdGuard Home the setup script installed. Leave empty if the resolver needs no login.",
                value: s?.dnsFilterUsername,
                placeholder: "No login",
                edit: TextSettingEdit(
                    id: "dnsFilterUsername",
                    title: "Resolver user",
                    placeholder: "admin",
                    message: "Admin user for the resolver's API. Empty means it needs no login at all.",
                    apply: { await model.setDnsFilterUsername($0) }
                )
            ),

            // The DuckDNS token's contract, for the same reason: the server never sends a
            // stored password back, so the field cannot be pre-filled, and an empty save is
            // how one is removed.
            (s?.dnsFilterUrl != nil) ? row(
                "dnsFilterPassword", "Resolver password",
                passwordSet
                    ? "Password for that user. One is saved — the server never sends it back, so the field always starts empty. Save an empty field to remove it."
                    : "Password for that user. Stored owner-only on the server and never sent back to this phone. No password saved yet.",
                control: AnyView(
                    Button(passwordSet ? "Stored" : "Set") {
                        textEditDraft = ""
                        textEdit = TextSettingEdit(
                            id: "dnsFilterPassword",
                            title: "Resolver password",
                            placeholder: "resolver admin password",
                            message: "The server never sends a stored password back, so this always starts empty. Save an empty field to clear it.",
                            apply: { await model.setDnsFilterPassword($0) }
                        )
                    }
                    .buttonStyle(.console(.ghost, compact: true))
                )
            ) : nil
        ]
        group(
            "DNS filtering",
            note: "The only control in this app that can stop a connection before it is attempted. Everything else acts on a flow that already exists — and on a VPN gateway a client's forwarded traffic never becomes a tracked connection at all, so nothing else here can block where a client goes. Set up by the server's own setup-dns-filter.sh. A name-based block: a client that dials a hard-coded address never asks, so it is never refused.",
            rows: rows
        )
    }

    // MARK: - VPN (WireGuard)

    @ViewBuilder
    private var wireGuardGroup: some View {
        let s = settings
        let peers = s?.wireGuardPeers ?? []
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "wireGuardMonitorEnabled", "WireGuard peer monitoring",
                "Watch peers for new keys, endpoint moves, and removals.",
                status: s?.wireGuardStatus, isOn: s?.wireGuardMonitorEnabled
            ) { await model.setWireGuardMonitor($0) },

            s?.wireGuardPeerMbPer10Min.map { mb in
                row(
                    "wireGuardPeerMbPer10Min", "Per-peer transfer notice (MB / 10 min)",
                    "Note it when this much data is sent to a single peer within 10 minutes. Recorded as an observation, not a threat — volume through a tunnel is the tunnel working, and a VPN user streaming video legitimately moves gigabytes. Off is the default. Forwarded tunnel traffic has no local socket, so this is the only place it is counted.",
                    control: AnyView(
                        ConsoleSelect(
                            options: Self.wireGuardChoices.contains(mb) ? Self.wireGuardChoices : [mb] + Self.wireGuardChoices,
                            selection: Binding(
                                get: { mb },
                                set: { v in Task { await model.setWireGuardPeerThreshold(v) } }
                            ),
                            label: { $0 == 0 ? "Off" : ($0 >= 1000 ? "\($0 / 1000) GB" : "\($0) MB") }
                        )
                    )
                )
            },

            (s?.wireGuardMonitorEnabled == true) ? row(
                "wireGuardPeers", "Peers",
                "Read-only. Revoking a peer is a WireGuard configuration change, not something a monitoring console should do behind your back.",
                control: AnyView(
                    Button(peers.isEmpty ? "None" : "\(peers.count)") {
                        showWireGuardPeers = true
                    }
                    .buttonStyle(.console(.ghost, compact: true))
                    .disabled(peers.isEmpty)
                )
            ) : nil
        ]
        group(
            "VPN (WireGuard)",
            note: "WireGuard uses one unconnected UDP socket, so its peers never appear as connections and nothing else in this app can see them. This reads WireGuard's own state instead. Needs root. Only public keys are read — the interface private key and peer preshared keys are discarded and never stored.",
            rows: rows
        )
    }

    private static let wireGuardChoices = [0, 500, 1000, 5000, 10000]

    // MARK: - Signatures (Suricata)

    @ViewBuilder
    private var suricataGroup: some View {
        let s = settings
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "suricataEnabled", "Suricata alert ingestion",
                "Read Suricata's EVE JSON and turn signature matches into threat events.",
                status: s?.suricataStatus, isOn: s?.suricataEnabled
            ) { await model.setSuricata($0) },

            textRow(
                "suricataEvePath", "EVE JSON path",
                "Absolute path to Suricata's eve.json (set eve-log to enabled in suricata.yaml).",
                value: s?.suricataEvePath,
                edit: TextSettingEdit(
                    id: "suricataEvePath",
                    title: "EVE JSON path",
                    placeholder: "/var/log/suricata/eve.json",
                    message: "Absolute path on the server. Leave empty to restore its own default.",
                    keyboard: .URL,
                    apply: { await model.setSuricataEvePath($0) }
                )
            ),

            s?.suricataMaxSeverity.map { sev in
                row(
                    "suricataMaxSeverity", "Maximum severity number",
                    "Suricata counts severity down — 1 is most severe. 3 keeps informational noise out; raise to 4 to see everything.",
                    control: AnyView(
                        ConsoleSelect(
                            options: [1, 2, 3, 4],
                            selection: Binding(
                                get: { min(max(sev, 1), 4) },
                                set: { v in Task { await model.setSuricataMaxSeverity(v) } }
                            ),
                            label: Self.suricataSeverityLabel
                        )
                    )
                )
            },

            textRow(
                "suricataIgnoredSids", "Muted signature IDs",
                "Comma-separated Suricata sids to ignore entirely — the per-rule mute for a known false positive.",
                value: s?.suricataIgnoredSids,
                edit: TextSettingEdit(
                    id: "suricataIgnoredSids",
                    title: "Muted signature IDs",
                    placeholder: "2001219,2010935",
                    message: "Comma-separated signature ids to drop. Leave empty to un-mute everything.",
                    keyboard: .numbersAndPunctuation,
                    apply: { await model.setSuricataIgnoredSids($0) }
                )
            )
        ]
        group(
            "Signatures (Suricata)",
            note: "Connection heuristics see who is talking and how often, never what is being said. Suricata inspects the payload — run it alongside Network Sentinel and its alerts appear here as threats, with auto-block, the allowlist and webhooks all applying as usual.",
            rows: rows
        )
    }

    private static func suricataSeverityLabel(_ severity: Int) -> String {
        switch severity {
        case 1: return "1 — Critical only"
        case 2: return "2 — High and above"
        case 3: return "3 — Medium and above"
        default: return "4 — Everything"
        }
    }

    // MARK: - Alerting
    //
    // The webhook is the server's own outbound alerting and the one path that survives this
    // phone being asleep or force-quit, so the device's own alert switches sit beside it
    // rather than in a section of their own.

    @ViewBuilder
    private var alertingGroup: some View {
        let s = settings
        let rows: [SettingRowSpec?] = [
            textRow(
                "webhookUrl", "Webhook URL",
                "POST Critical threats to a webhook — ntfy, Slack and Discord formats are detected automatically; anything else gets generic JSON. Empty is off.",
                status: (s?.webhookUrl?.isEmpty == false) ? s?.webhookStatus : nil,
                value: s?.webhookUrl,
                placeholder: "Off",
                edit: TextSettingEdit(
                    id: "webhookUrl",
                    title: "Webhook URL",
                    placeholder: "https://ntfy.sh/your-topic",
                    message: "Where the server posts Critical threats. Leave empty to switch webhook alerts off.",
                    keyboard: .URL,
                    apply: { await model.setWebhookURL($0) }
                )
            ),

            row(
                "deviceAlerts", "Critical alerts on this device",
                "Notify on this iPhone when a Critical threat appears. Foreground polling continues briefly after you leave the app, then iOS wakes it periodically — turn on Background App Refresh in iOS Settings, and use “Remember password” so the background login works.",
                control: AnyView(
                    ConsoleSwitch(isOn: Binding(
                        get: { model.criticalAlertsEnabled },
                        set: { model.criticalAlertsEnabled = $0 }
                    ))
                )
            ),

            row(
                "notifPermission", "Notification permission",
                model.lastBackgroundPollAt.map {
                    "iOS decides whether an alert reaches you. Last background poll: \($0.formatted(date: .omitted, time: .shortened))."
                } ?? "iOS decides whether an alert reaches you at all — grant permission once, here.",
                control: AnyView(
                    Button("Request") {
                        Task { await CriticalAlertService.shared.requestPermission() }
                    }
                    .buttonStyle(.console(.ghost, compact: true))
                )
            )
        ]
        group("Alerting", rows: rows)
    }

    // MARK: - Remote access
    //
    // Kestrel binds its endpoints at startup, so every field here is saved now and served
    // after the next restart. `httpsActive` is the only one that says what is actually on
    // the wire, which is why the group leads with it rather than with the toggle.

    @ViewBuilder
    private var remoteAccessGroup: some View {
        let s = settings
        let busy = s?.certIssueBusy ?? false
        let rows: [SettingRowSpec?] = [
            (s?.httpsEnabled != nil) ? row(
                "httpsActive", "This connection",
                "What this app is talking to the console over right now, as opposed to what is configured below.",
                control: AnyView(
                    Text((s?.httpsActive ?? false) ? "HTTPS" : "Plain HTTP")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle((s?.httpsActive ?? false) ? NSTheme.success : NSTheme.warning)
                )
            ) : nil,

            toggleRow(
                "httpsEnabled", "HTTPS",
                "Serve this console over TLS as well as plain HTTP. Needs a certificate below. Takes effect when the web console restarts.",
                isOn: s?.httpsEnabled
            ) { await model.setHttpsEnabled($0) },

            s?.httpsPort.map { port in
                textRowValue(
                    "httpsPort", "HTTPS port",
                    "TCP port for the TLS endpoint (ports below 1024 need root). Forward this port on your router if you want access from outside the LAN.",
                    value: "\(port)",
                    edit: TextSettingEdit(
                        id: "httpsPort",
                        title: "HTTPS port",
                        placeholder: "18443",
                        message: "1–65535, and not the port already serving this console.",
                        keyboard: .numberPad,
                        apply: { await model.setHttpsPort($0) }
                    )
                )
            },

            (s?.duckDnsEnabled != nil) ? row(
                "issueCert", "Issue certificate",
                "Get a free trusted Let's Encrypt certificate for the DuckDNS name below and fill in the two paths. Proves control through the saved token, so nothing needs to be reachable on port 80. Takes a few minutes waiting on DNS.",
                status: s?.certIssueMessage,
                statusIsWarning: (s?.certIssueMessage?.isEmpty == false) && !(s?.certIssueOk ?? false),
                control: AnyView(
                    Button(busy ? "Issuing…" : "Issue") {
                        Task { await model.issueCertificate() }
                    }
                    .buttonStyle(.console(.primary, compact: true))
                    .disabled(busy || model.server == nil)
                )
            ) : nil,

            textRow(
                "acmeEmail", "Let's Encrypt email",
                "Used only the first time, to register the account when acme.sh is installed. Optional.",
                value: s?.acmeEmail,
                edit: TextSettingEdit(
                    id: "acmeEmail",
                    title: "Let's Encrypt email",
                    placeholder: "you@example.com",
                    message: "Account address for expiry notices. Optional.",
                    keyboard: .emailAddress,
                    apply: { await model.setAcmeEmail($0) }
                )
            ),

            textRow(
                "tlsCertPath", "Certificate (PEM fullchain or .pfx)",
                "Filled in by Issue certificate; edit it if the certificate lives somewhere else.",
                value: s?.tlsCertPath,
                edit: TextSettingEdit(
                    id: "tlsCertPath",
                    title: "Certificate path",
                    placeholder: "/etc/networksentinel/fullchain.cer",
                    message: "Absolute path on the server. HTTPS cannot start without it.",
                    keyboard: .URL,
                    apply: { await model.setTlsCertPath($0) }
                )
            ),

            textRow(
                "tlsKeyPath", "Private key (PEM)",
                "Full path to the private key. Leave empty when the certificate is a .pfx bundle.",
                value: s?.tlsKeyPath,
                edit: TextSettingEdit(
                    id: "tlsKeyPath",
                    title: "Private key path",
                    placeholder: "/etc/networksentinel/privkey.key",
                    message: "Absolute path on the server. Leave empty when the certificate file already carries the key.",
                    keyboard: .URL,
                    apply: { await model.setTlsKeyPath($0) }
                )
            ),

            toggleRow(
                "httpsRedirect", "Redirect HTTP to HTTPS",
                "Requests that arrive by hostname get sent to the TLS port. Requests to a bare IP stay on HTTP — the certificate only covers the name.",
                isOn: s?.httpsRedirect
            ) { await model.setHttpsRedirect($0) },

            // Web 0.7.6. Absent on an older server, and the row is simply not drawn there —
            // the field's arrival is the version check.
            toggleRow(
                "httpsOnly", "HTTPS only (turn off plain HTTP)",
                "Skip the plain-HTTP listener entirely, so the master password can only cross the wire encrypted. Needs HTTPS on with a working certificate — if the certificate fails to load at startup, plain HTTP stays on so this console is not locked out. Takes effect when the web console restarts.",
                isOn: s?.httpsOnly
            ) { await model.setHttpsOnly($0) },

            toggleRow(
                "duckDnsEnabled", "DuckDNS dynamic DNS",
                "Keep a free duckdns.org hostname pointed at this machine so it stays reachable when your ISP changes your IP.",
                status: s?.duckDnsStatus, isOn: s?.duckDnsEnabled
            ) { await model.setDuckDnsEnabled($0) },

            textRow(
                "duckDnsDomain", "DuckDNS subdomain",
                "Just the label — “myhost” for myhost.duckdns.org.",
                value: s?.duckDnsDomain.map { $0.isEmpty ? "" : "\($0).duckdns.org" },
                draft: s?.duckDnsDomain,
                edit: TextSettingEdit(
                    id: "duckDnsDomain",
                    title: "DuckDNS subdomain",
                    placeholder: "myhost",
                    message: "The label only — the .duckdns.org part is added for you.",
                    keyboard: .URL,
                    apply: { await model.setDuckDnsDomain($0) }
                )
            ),

            (s?.duckDnsEnabled != nil) ? row(
                "duckDnsToken", "DuckDNS token",
                (s?.duckDnsTokenSet ?? false)
                    ? "Account token from duckdns.org. A token is saved — the server never sends it back, so the field always starts empty. Save an empty field to remove it."
                    : "Account token from duckdns.org. Stored owner-only on disk and never sent back to this phone. No token saved yet.",
                control: AnyView(
                    Button((s?.duckDnsTokenSet ?? false) ? "Stored" : "Set") {
                        textEditDraft = ""
                        textEdit = TextSettingEdit(
                            id: "duckDnsToken",
                            title: "DuckDNS token",
                            placeholder: "paste token",
                            message: "The server never sends a stored token back, so this always starts empty. Save an empty field to clear it.",
                            apply: { await model.setDuckDnsToken($0) }
                        )
                    }
                    .buttonStyle(.console(.ghost, compact: true))
                )
            ) : nil
        ]
        group(
            "Remote access",
            note: remoteAccessNote,
            rows: rows,
            footer: "Exposing this console to the internet gives anyone who guesses the master password control of this machine's firewall. Prefer a VPN or Tailscale; if you do forward a port, forward only the HTTPS one and use a long unique password."
        )
    }

    private var remoteAccessNote: String? {
        let https = settings?.httpsStatus ?? ""
        let duck = settings?.duckDnsStatus ?? ""
        if https.isEmpty && duck.isEmpty { return nil }
        if https.isEmpty { return duck }
        if duck.isEmpty { return https }
        return "\(https) · \(duck)"
    }

    // MARK: - Auto-block

    @ViewBuilder
    private var autoBlockGroup: some View {
        let s = settings
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "autoBlockEnabled", "Auto-block threats",
                "Automatically create firewall rules when threats are detected.",
                status: s?.autoBlockSummary, isOn: s?.autoBlockEnabled
            ) { await model.setAutoBlockEnabled($0) },

            toggleRow(
                "preventionDryRun", "Dry run",
                "Decide and report auto-blocks without writing any firewall rules. Blocking turns a false positive into an outage, so run a new detection source here first and watch what it would have dropped before arming it.",
                isOn: s?.preventionDryRun
            ) { await model.setPreventionDryRun($0) },

            s?.autoBlockMinLevel.map { level in
                row(
                    "autoBlockMinLevel", "Minimum severity",
                    "Only auto-block threats at or above this level.",
                    control: AnyView(
                        ConsoleSelect(
                            options: ["Medium", "High", "Critical"],
                            selection: Binding(
                                get: { ["Medium", "High", "Critical"].contains(level) ? level : "High" },
                                set: { v in Task { await model.setMinLevel(v) } }
                            ),
                            label: { $0 }
                        )
                    )
                )
            },

            toggleRow(
                "blockInbound", "Block inbound",
                "New block rules stop traffic coming in to this machine.",
                isOn: s?.blockInbound
            ) { await model.setBlockInbound($0) },

            toggleRow(
                "blockOutbound", "Block outbound",
                "New block rules stop traffic going out from this machine.",
                isOn: s?.blockOutbound
            ) { await model.setBlockOutbound($0) },

            s?.autoBlockExpiryMinutes.map { minutes in
                row(
                    "autoBlockExpiryMinutes", "Auto-block expiry (minutes)",
                    "Remove auto-created block rules after this many minutes. Never means they stand until you remove them. The address stops counting as blocked right away; the kernel rule is dropped by a background sweep once the server can elevate without a password prompt.",
                    control: AnyView(
                        ConsoleSelect(
                            options: Self.expiryChoices.contains(minutes) ? Self.expiryChoices : [minutes] + Self.expiryChoices,
                            selection: Binding(
                                get: { minutes },
                                set: { v in Task { await model.setAutoBlockExpiry(minutes: v) } }
                            ),
                            label: Self.expiryLabel
                        )
                    )
                )
            }
        ]
        group("Auto-block", rows: rows)
    }

    private static let expiryChoices = [0, 15, 60, 240, 720, 1440, 10080]

    private static func expiryLabel(_ minutes: Int) -> String {
        switch minutes {
        case 0: return "Never"
        case ..<60: return "\(minutes) min"
        case ..<1440: return "\(minutes / 60) h"
        default: return "\(minutes / 1440) d"
        }
    }

    // MARK: - Allowlist

    @ViewBuilder
    private var allowlistGroup: some View {
        let rows: [SettingRowSpec?] = [
            toggleRow(
                "allowlistUseRemoteFeed", "Remote allowlist feed",
                "Refresh the known-good domain/IP list from the online feed.",
                status: model.state?.allowlistStatus, isOn: settings?.allowlistUseRemoteFeed
            ) { await model.setAllowlistRemoteFeed($0) },

            row(
                "refreshAllowlist", "Refresh now",
                "Pull the feed immediately rather than waiting for the server's own schedule. The entries themselves live on the Allowlist page, under Firewall.",
                control: AnyView(
                    Button("Refresh") { Task { await model.refreshAllowlist() } }
                        .buttonStyle(.console(.ghost, compact: true))
                )
            )
        ]
        group("Allowlist", rows: rows)
    }

    // MARK: - Danger zone

    @ViewBuilder
    private var dangerZoneGroup: some View {
        let rows: [SettingRowSpec?] = [
            row(
                "removeAll", "Remove all firewall rules",
                "Deletes every Network Sentinel block rule — the access rule for this console is kept — and stops auto-block from re-adding them for 24h.",
                control: AnyView(
                    Button("Remove") { confirmRemoveAll = true }
                        .buttonStyle(.console(.remove, compact: true))
                        .disabled(model.server == nil)
                )
            )
        ]
        group("Danger zone", rows: rows)
    }

    // MARK: - About

    @ViewBuilder
    private var aboutGroup: some View {
        let rows: [SettingRowSpec?] = [
            row(
                "help", "Help",
                "What each screen does, and what Sleep, elevation and the master password mean — the console's Help page, which sits under Settings there too.",
                control: AnyView(
                    NavigationLink {
                        HelpView()
                    } label: {
                        Text("Open")
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(NSTheme.text)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .frame(minWidth: 72)
                            .background(Color.white.opacity(0.10), in: .rect(cornerRadius: 10))
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(NSTheme.border, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                )
            ),
            row(
                "about", "Versions",
                "This app, and the console it is talking to. The app tracks the web console's own version range; a setting missing from a group is one this server is too old to have.",
                control: AnyView(
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("app \(Self.appVersion)")
                            .font(.system(size: 12).monospaced())
                            .foregroundStyle(NSTheme.text2)
                        Text("web \(model.state?.version ?? "—")")
                            .font(.system(size: 12).monospaced())
                            .foregroundStyle(NSTheme.signal)
                    }
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                )
            )
        ]
        group("About", rows: rows)
    }

    private static var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? ""
        return b.isEmpty ? v : "\(v) (\(b))"
    }

    // MARK: - Row plumbing
    //
    // Forty-odd rows differing only in title, sentence and control. Built as data rather
    // than as view code so the filter box can drop one without every group needing to know
    // how, and so a group with nothing left in it removes its own heading.

    private struct SettingRowSpec: Identifiable {
        let id: String
        let title: String
        let detail: String
        var status: String?
        var statusIsWarning: Bool = false
        let control: AnyView
    }

    /// A switch row. Returns nil when the server did not send the field — which is the only
    /// version check this screen does: a setting a server does not report is one it does not
    /// have, and a switch that writes `Unknown setting` reads as a control that does nothing.
    private func toggleRow(
        _ id: String,
        _ title: String,
        _ detail: String,
        status: String? = nil,
        isOn: Bool?,
        apply: @escaping (Bool) async -> Void
    ) -> SettingRowSpec? {
        guard let isOn else { return nil }
        return SettingRowSpec(
            id: id,
            title: title,
            detail: detail,
            status: status,
            statusIsWarning: Self.statusReadsAsProblem(status, isOn: isOn),
            control: AnyView(
                ConsoleSwitch(isOn: Binding(
                    get: { isOn },
                    set: { v in Task { await apply(v) } }
                ))
            )
        )
    }

    private func row(
        _ id: String,
        _ title: String,
        _ detail: String,
        status: String? = nil,
        statusIsWarning: Bool = false,
        control: AnyView
    ) -> SettingRowSpec {
        SettingRowSpec(
            id: id,
            title: title,
            detail: detail,
            status: status,
            statusIsWarning: statusIsWarning,
            control: control
        )
    }

    /// A free-text server setting: what is stored, and the shared editor behind it.
    ///
    /// `draft` is what the editor starts with, which is not always what the row shows — the
    /// DuckDNS row reads `myhost.duckdns.org` and the server takes the label alone.
    private func textRow(
        _ id: String,
        _ title: String,
        _ detail: String,
        status: String? = nil,
        value: String?,
        draft: String? = nil,
        placeholder: String = "Not set",
        edit: TextSettingEdit
    ) -> SettingRowSpec? {
        guard let value else { return nil }
        return SettingRowSpec(
            id: id,
            title: title,
            detail: detail,
            status: status,
            control: AnyView(
                ConsoleValueControl(value: value, placeholder: placeholder) {
                    textEditDraft = draft ?? value
                    textEdit = edit
                }
            )
        )
    }

    /// The same, for a value the server sends as a number and this screen already has.
    private func textRowValue(
        _ id: String,
        _ title: String,
        _ detail: String,
        value: String,
        edit: TextSettingEdit
    ) -> SettingRowSpec {
        SettingRowSpec(
            id: id,
            title: title,
            detail: detail,
            control: AnyView(
                ConsoleValueControl(value: value) {
                    textEditDraft = value
                    textEdit = edit
                }
            )
        )
    }

    /// On, but the server says it is not actually running. Read off the server's own status
    /// sentence, in the server's own words — there is no separate field for it.
    private static func statusReadsAsProblem(_ status: String?, isOn: Bool) -> Bool {
        guard isOn, let status = status?.lowercased() else { return false }
        // "unreachable" is 0.7.15's: filtering switched on at a resolver the server cannot
        // reach is on-but-not-working, which is exactly what this colour is for.
        return status.contains("needs root")
            || status.contains("unreachable")
            || status.contains("not running")
            || status.contains("unavailable")
            || status.contains("needs elevation")
    }

    // MARK: - Groups

    @ViewBuilder
    private func group(
        _ title: String,
        note: String? = nil,
        rows: [SettingRowSpec?],
        footer: String? = nil
    ) -> some View {
        let visible = rows.compactMap { $0 }.filter(matches)
        if !visible.isEmpty {
            ConsoleSettingsGroup(title: title) {
                // The note explains why the group exists at all, so it is dropped while
                // filtering — a search result is a row, not a lecture.
                if let note, !note.isEmpty, query.isEmpty {
                    ConsoleNote(text: note)
                }
                ForEach(visible) { spec in
                    ConsoleSettingRow(
                        title: spec.title,
                        detail: spec.detail,
                        status: spec.status,
                        statusIsWarning: spec.statusIsWarning
                    ) {
                        spec.control
                    }
                }
                if let footer, !footer.isEmpty, query.isEmpty {
                    ConsoleNote(text: footer)
                }
            }
            .padding(.top, 8)
        }
    }

    private func matches(_ spec: SettingRowSpec) -> Bool {
        guard !query.isEmpty else { return true }
        let q = query.lowercased()
        return spec.title.lowercased().contains(q)
            || spec.detail.lowercased().contains(q)
            || spec.id.lowercased().contains(q)
            || (spec.status?.lowercased().contains(q) ?? false)
    }

    /// Whether the filter matched anything anywhere. Cheap to recompute — these are the same
    /// specs the groups build, and there are forty of them, not forty thousand.
    private var anyGroupMatches: Bool {
        let q = query.lowercased()
        return Self.searchCorpus(settings: settings).contains { $0.contains(q) }
    }

    /// Every row's searchable text, without its control. Kept apart from the groups so
    /// "nothing matched" can be answered without building forty AnyViews to find out.
    private static func searchCorpus(settings: SettingsInfo?) -> [String] {
        var corpus: [String] = [
            "server address name master password sign out",
            "monitoring live page refresh speed geo lookups auth-log closed-port scan kernel flow events traffic metering critical threat alerts",
            "intrusion detection threat-intel blocklists new-listener process reputation arp gateway startup-item exfiltration honeypot decoy port list",
            "dns hygiene approved resolvers",
            "vpn wireguard peer monitoring per-peer transfer peers",
            "signatures suricata eve json path maximum severity muted signature ids",
            "alerting webhook url critical alerts on this device notification permission",
            "remote access https port issue certificate private key redirect duckdns dynamic dns subdomain token",
            "auto-block threats dry run minimum severity block inbound outbound expiry",
            "allowlist remote feed refresh now",
            "danger zone remove all firewall rules",
            "about help versions"
        ]
        if settings?.httpsOnly != nil { corpus.append("https only turn off plain http") }
        if settings?.dnsFilterEnabled != nil {
            corpus.append("dns filtering filtering resolver adguard resolver user resolver password blocked sites")
        }
        return corpus
    }
}

// MARK: - The detector catalogue
//
// Kept for the Dashboard, which counts these to say how much of the machine is being watched
// without listing any of them. The switches themselves are rows in Intrusion detection and
// Monitoring above, where the console keeps them — this is a reading of the same settings,
// not a second place to change them.

/// One switchable thing the server watches with. Built from the settings payload rather than
/// hard-coded, so a detector a given server version does not report simply is not counted.
struct Detector: Identifiable {
    let id: String
    let title: String
    let status: String?
    let isOn: Bool

    /// On, but the server says it is not actually running. Read off the server's own status
    /// sentence — there is no separate field for it, and the wording is the server's own
    /// ("needs root", "not running", "unavailable"). A false negative here costs a callout;
    /// matching too eagerly would cry wolf on every detector that mentions permissions.
    var isStalled: Bool {
        guard isOn, let status = status?.lowercased() else { return false }
        return status.contains("needs root")
            || status.contains("not running")
            || status.contains("unavailable")
            || status.contains("needs elevation")
    }

    static func all(settings: SettingsInfo?, model: AppModel) -> [Detector] {
        guard let s = settings else { return [] }
        var items: [Detector] = []

        func add(_ id: String, _ title: String, _ status: String?, _ isOn: Bool?) {
            guard let isOn else { return }
            items.append(Detector(id: id, title: title, status: status, isOn: isOn))
        }

        add("intel", "Threat-intel blocklists", s.threatIntelStatus, s.threatIntelEnabled)
        add("listener", "New-listener alerts", nil, s.newListenerAlertsEnabled)
        add("process", "Process reputation", nil, s.processReputationEnabled)
        add("arp", "ARP / gateway watch", s.arpWatchStatus, s.arpWatchEnabled)
        add("startup", s.startupWatchTitle, s.startupWatchStatus, s.startupWatchEnabled)
        add("exfil", "Exfiltration monitor", s.exfilStatus, s.exfilMonitorEnabled)
        add("honeypot", "Honeypot decoy ports", s.honeypotStatus, s.honeypotEnabled)
        add("authlog", "Auth-log monitoring", s.authLogStatus, s.authLogMonitorEnabled)
        add("probelog", "Closed-port scan detection", s.probeLogStatus, s.probeLogEnabled)
        add("conntrack", "Kernel flow events", s.conntrackStatus, s.conntrackEventsEnabled)
        add("dns", "DNS hygiene", s.dnsHygieneStatus, s.dnsHygieneEnabled)
        add("wireguard", "WireGuard peers", s.wireGuardStatus, s.wireGuardMonitorEnabled)
        add("suricata", "Suricata signatures", s.suricataStatus, s.suricataEnabled)

        return items
    }
}
