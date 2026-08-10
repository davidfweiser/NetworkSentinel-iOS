import SwiftUI

/// Everything the server watches for, on one screen — design 2d.
///
/// These were six settings cards stacked under the Dashboard's two useful panels, which made
/// the screen you check in a hurry the same screen you configure once a month. Grouped by
/// what a detector actually looks at, searchable because there are eighteen of them, and
/// every row carries the server's own status line rather than a description written here:
/// "on" and "running" are different claims, and only the server can make the second.
///
/// Enforcement is deliberately not here. Auto-block, dry run, minimum level and rule expiry
/// change what blocking *does*, so they live on Status beside the block controls.
struct DetectionView: View {
    @Environment(AppModel.self) private var model

    @State private var query = ""
    @State private var textEdit: TextSettingEdit?
    @State private var textEditDraft = ""
    @State private var showWireGuardPeers = false

    private var settings: SettingsInfo? { model.state?.settings }
    private var detectors: [Detector] { Detector.all(settings: settings, model: model) }

    var body: some View {
        List {
            stalledCallout

            ForEach(DetectorGroup.allCases) { group in
                let items = detectors.filter { $0.group == group && matches($0) }
                if !items.isEmpty {
                    Section(group.title) {
                        ForEach(items) { detector in
                            detectorToggle(detector)
                            extras(for: detector)
                        }
                    }
                }
            }

            if detectors.contains(where: matches) {
                Section {
                    Text("Enforcement — auto-block, dry run, minimum level and rule expiry — lives on Status, with the block controls it changes.")
                        .font(.caption)
                        .foregroundStyle(NSTheme.muted)
                        .listRowBackground(Color.clear)
                }
            } else {
                Section {
                    Text(settings == nil
                         ? "Waiting for the server."
                         : "No detector matches “\(query)”.")
                        .foregroundStyle(NSTheme.muted)
                        .listRowBackground(NSTheme.row)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Detection")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $query, prompt: "Search detectors")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Text("\(detectors.count(where: \.isOn)) of \(detectors.count)")
                    .font(.system(size: 12).monospaced())
                    .foregroundStyle(NSTheme.muted)
            }
        }
        .refreshable { await model.refresh(silent: false) }
        .sheet(isPresented: $showWireGuardPeers) {
            WireGuardPeersView(
                peers: settings?.wireGuardPeers ?? [],
                status: settings?.wireGuardStatus
            )
            .preferredColorScheme(.dark)
        }
        .nsTextSettingAlert($textEdit, draft: $textEditDraft)
    }

    private func matches(_ detector: Detector) -> Bool {
        guard !query.isEmpty else { return true }
        let q = query.lowercased()
        return detector.title.lowercased().contains(q)
            || (detector.status?.lowercased().contains(q) ?? false)
            || detector.group.title.lowercased().contains(q)
    }

    // MARK: - On, but not running

    /// A detector switched on that the server cannot actually run reads as covered when it
    /// is not — the worst state to leave unnamed, and the one thing on this screen worth
    /// interrupting the list for.
    @ViewBuilder
    private var stalledCallout: some View {
        if let stalled = detectors.first(where: \.isStalled) {
            Section {
                HStack(alignment: .top, spacing: 11) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(NSTheme.warning)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(stalled.title) is on, but not running")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(NSTheme.text)
                        if let status = stalled.status, !status.isEmpty {
                            Text(status)
                                .font(.system(size: 11))
                                .foregroundStyle(NSTheme.mutedOnTint)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer(minLength: 6)
                    Button("Authorize") {
                        Task { await model.authorizeFirewall() }
                    }
                    .font(.caption.weight(.bold))
                    .buttonStyle(.glassProminent)
                    .tint(NSTheme.warning)
                }
                .padding(.vertical, 4)
                .listRowBackground(NSTheme.warning.opacity(0.14))
            }
        }
    }

    // MARK: - Rows

    private func detectorToggle(_ detector: Detector) -> some View {
        Toggle(isOn: Binding(
            get: { detector.isOn },
            set: { newValue in Task { await detector.apply(newValue) } }
        )) {
            VStack(alignment: .leading, spacing: 2) {
                Text(detector.title)
                    .font(.system(size: 15))
                    .foregroundStyle(NSTheme.text)
                if let status = detector.status, !status.isEmpty {
                    Text(status)
                        .font(.system(size: 11))
                        .foregroundStyle(detector.isStalled ? NSTheme.warning : NSTheme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .tint(NSTheme.accent)
        .padding(.vertical, 5)
        .listRowBackground(NSTheme.row)
    }

    /// The settings that only mean anything while their detector is on — a threshold, a
    /// path, a port list. They sit under the toggle they belong to rather than in a group of
    /// their own, which is where they were unfindable.
    @ViewBuilder
    private func extras(for detector: Detector) -> some View {
        switch detector.id {
        case "exfil":
            if let mb = settings?.exfilMbPer10Min {
                settingMenu(
                    title: "Threshold",
                    value: "\(mb) MB / 10 min",
                    options: Self.exfilOptions.map { ("\($0) MB", $0) }
                ) { await model.setExfilThreshold($0) }
            }

        case "honeypot":
            textSettingRow(
                title: "Decoy ports",
                subtitle: "Ports already in use are skipped.",
                value: settings?.honeypotPorts,
                edit: TextSettingEdit(
                    id: "honeypotPorts",
                    title: "Decoy ports",
                    placeholder: "2323,3389,5900",
                    message: "Comma-separated TCP ports nothing legitimate uses. Any completed connection to one is a Critical alert. The server refuses its own console port.",
                    keyboard: .numbersAndPunctuation,
                    apply: { await model.setHoneypotPorts($0) }
                )
            )

        case "dns":
            textSettingRow(
                title: "Approved resolvers",
                // Without this list a DoH setup looks like no DNS at all rather than like a
                // leak, which is the difference between quiet and wrong.
                subtitle: "DoH is HTTPS on 443 — it only counts as encrypted DNS when the destination is listed here.",
                value: settings?.dnsApprovedResolvers,
                edit: TextSettingEdit(
                    id: "dnsApprovedResolvers",
                    title: "Approved resolvers",
                    placeholder: "10.8.0.1, 127.0.0.53",
                    message: "Resolver IP addresses, separated by commas. Leave empty to report every plaintext query and recognise no DoH endpoint.",
                    keyboard: .numbersAndPunctuation,
                    apply: { await model.setDnsApprovedResolvers($0) }
                )
            )

        case "wireguard":
            if let mb = settings?.wireGuardPeerMbPer10Min {
                settingMenu(
                    title: "Per-peer transfer",
                    // Off by default on the server, and the reason matters: forwarded tunnel
                    // traffic has no local socket, so this is the only place it is counted —
                    // and a peer streaming video moves gigabytes.
                    subtitle: mb == 0
                        ? "Off. Forwarded tunnel traffic has no local socket, so nothing else counts it."
                        : nil,
                    value: mb == 0 ? "Off" : "\(mb) MB / 10 min",
                    options: Self.wireGuardThresholdOptions
                ) { await model.setWireGuardPeerThreshold($0) }
            }
            let peers = settings?.wireGuardPeers ?? []
            Button {
                showWireGuardPeers = true
            } label: {
                detailRowLabel(
                    title: "Peers",
                    subtitle: "Read-only — revoking a peer is a WireGuard config change.",
                    value: peers.isEmpty ? "None" : "\(peers.count)"
                )
            }
            .disabled(peers.isEmpty)
            .listRowBackground(NSTheme.row)

        case "suricata":
            textSettingRow(
                title: "EVE JSON path",
                subtitle: "Reading it needs group access or root on the server.",
                value: settings?.suricataEvePath,
                edit: TextSettingEdit(
                    id: "suricataEvePath",
                    title: "EVE JSON path",
                    placeholder: "/var/log/suricata/eve.json",
                    message: "Absolute path to Suricata's EVE log. Leave empty to restore the server's default.",
                    keyboard: .URL,
                    apply: { await model.setSuricataEvePath($0) }
                )
            )
            if let sev = settings?.suricataMaxSeverity {
                settingMenu(
                    title: "Maximum severity",
                    subtitle: "Suricata counts down — 1 is most severe, so a lower number is a quieter feed.",
                    value: Self.suricataSeverityLabel(sev),
                    options: Self.suricataSeverityOptions
                ) { await model.setSuricataMaxSeverity($0) }
            }
            textSettingRow(
                title: "Muted signatures",
                subtitle: "One noisy rule can otherwise bury every other alert.",
                value: settings?.suricataIgnoredSids,
                edit: TextSettingEdit(
                    id: "suricataIgnoredSids",
                    title: "Muted signatures",
                    placeholder: "2010935,2013028",
                    message: "Comma-separated Suricata signature ids to drop. Leave empty to un-mute everything.",
                    keyboard: .numbersAndPunctuation,
                    apply: { await model.setSuricataIgnoredSids($0) }
                )
            )

        default:
            EmptyView()
        }
    }

    private static let exfilOptions = [50, 100, 250, 500, 1000, 2000]

    private static let wireGuardThresholdOptions: [(label: String, value: Int)] = [
        ("Off", 0),
        ("500 MB", 500),
        ("1 GB", 1000),
        ("5 GB", 5000),
        ("10 GB", 10000)
    ]

    /// Suricata's own scale, mapped to the levels the rest of the app speaks.
    private static let suricataSeverityOptions: [(label: String, value: Int)] = [
        ("1 — Critical only", 1),
        ("2 — High and above", 2),
        ("3 — Medium and above", 3),
        ("4 — Everything", 4)
    ]

    private static func suricataSeverityLabel(_ severity: Int) -> String {
        suricataSeverityOptions.first { $0.value == severity }?.label ?? "\(severity)"
    }

    // MARK: - Shared row shapes

    private func settingMenu(
        title: String,
        subtitle: String? = nil,
        value: String,
        options: [(label: String, value: Int)],
        action: @escaping (Int) async -> Void
    ) -> some View {
        Menu {
            ForEach(options, id: \.value) { option in
                Button(option.label) {
                    Task { await action(option.value) }
                }
            }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline)
                        .foregroundStyle(NSTheme.text)
                    if let subtitle, !subtitle.isEmpty {
                        Text(subtitle)
                            .font(.caption2)
                            .foregroundStyle(NSTheme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 8)
                Text(value)
                    .font(.system(size: 12).monospaced())
                    .foregroundStyle(NSTheme.cyan)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
            }
            .padding(.vertical, 5)
        }
        .listRowBackground(NSTheme.row)
    }

    /// Row that opens the shared text editor, pre-filled with what the server currently has.
    private func textSettingRow(
        title: String,
        subtitle: String?,
        value: String?,
        edit: TextSettingEdit
    ) -> some View {
        Button {
            textEditDraft = value ?? ""
            textEdit = edit
        } label: {
            detailRowLabel(
                title: title,
                subtitle: subtitle,
                value: (value?.isEmpty == false) ? value! : "None"
            )
        }
        .listRowBackground(NSTheme.row)
    }

    private func detailRowLabel(title: String, subtitle: String?, value: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.text)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            Text(value)
                .font(.system(size: 12).monospaced())
                .foregroundStyle(NSTheme.cyan)
                .lineLimit(1)
                .truncationMode(.middle)
            Image(systemName: "chevron.right")
                .font(.caption2)
                .foregroundStyle(NSTheme.muted)
        }
        .padding(.vertical, 5)
    }
}

// MARK: - The catalogue

enum DetectorGroup: String, CaseIterable, Identifiable {
    case peers
    case machine
    case deep
    case server

    var id: String { rawValue }

    var title: String {
        switch self {
        case .peers: return "Peers and traffic"
        case .machine: return "This machine"
        case .deep: return "Deep inspection"
        case .server: return "Also on this server"
        }
    }
}

/// One switchable thing the server watches with. Built from the settings payload rather than
/// hard-coded, so a detector a given server version does not report simply is not listed —
/// the same gating the old settings cards did, kept in one place now that Status also needs
/// to count them.
struct Detector: Identifiable {
    let id: String
    let group: DetectorGroup
    let title: String
    let status: String?
    let isOn: Bool
    let apply: (Bool) async -> Void

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

        func add(
            _ id: String,
            _ group: DetectorGroup,
            _ title: String,
            _ status: String?,
            _ isOn: Bool?,
            _ apply: @escaping (Bool) async -> Void
        ) {
            guard let isOn else { return }
            items.append(Detector(id: id, group: group, title: title, status: status, isOn: isOn, apply: apply))
        }

        // Peers and traffic — what the machine is talking to.
        add("intel", .peers, "Threat-intel blocklists", s.threatIntelStatus, s.threatIntelEnabled) {
            await model.setThreatIntel($0)
        }
        add("exfil", .peers, "Exfiltration monitor", s.exfilStatus, s.exfilMonitorEnabled) {
            await model.setExfilMonitor($0)
        }
        // Not a detector in its own right: it changes *when* the existing heuristics get
        // their snapshot. It sits with them because that is what it affects.
        add(
            "conntrack",
            .peers,
            "Kernel flow events",
            s.conntrackStatus ?? "Takes a snapshot when a connection arrives instead of waiting out the poll interval. Needs root on the server.",
            s.conntrackEventsEnabled
        ) { await model.setConntrackEvents($0) }

        // This machine — what is happening on the host itself.
        add(
            "listener",
            .machine,
            "New-listener alerts",
            "A new open port, or a known port changing owner process.",
            s.newListenerAlertsEnabled
        ) { await model.setNewListenerAlerts($0) }
        add(
            "process",
            .machine,
            "Process reputation",
            "Unsigned or quarantined binaries talking to public hosts, and shells with outbound connections.",
            s.processReputationEnabled
        ) { await model.setProcessReputation($0) }
        add(
            "startup",
            .machine,
            s.startupWatchTitle,
            s.startupWatchStatus,
            s.startupWatchEnabled
        ) { await model.setStartupItemWatch($0) }
        add("arp", .machine, "ARP / gateway watch", s.arpWatchStatus, s.arpWatchEnabled) {
            await model.setArpWatch($0)
        }
        add("authlog", .machine, "Auth-log monitoring", s.authLogStatus, s.authLogMonitorEnabled) {
            await model.setAuthLogMonitor($0)
        }
        add("probelog", .machine, "Closed-port scan detection", s.probeLogStatus, s.probeLogEnabled) {
            await model.setProbeLog($0)
        }

        // Deep inspection — the feeds that see more than a socket table can.
        add("dns", .deep, "DNS hygiene", s.dnsHygieneStatus, s.dnsHygieneEnabled) {
            await model.setDnsHygiene($0)
        }
        add("wireguard", .deep, "WireGuard peers", s.wireGuardStatus, s.wireGuardMonitorEnabled) {
            await model.setWireGuardMonitor($0)
        }
        add("suricata", .deep, "Suricata signatures", s.suricataStatus, s.suricataEnabled) {
            await model.setSuricata($0)
        }
        add("honeypot", .deep, "Honeypot decoy ports", s.honeypotStatus, s.honeypotEnabled) {
            await model.setHoneypot($0)
        }

        // Server-side switches that are neither detectors nor enforcement, and would be
        // homeless otherwise.
        add("geo", .server, "Geo lookups", "Country and city for remote addresses.", s.geoLookupEnabled) {
            await model.setGeoLookup($0)
        }
        add(
            "allowfeed",
            .server,
            "Allowlist remote feed",
            "Keeps the trusted-domain list topped up from the server's feed.",
            s.allowlistUseRemoteFeed
        ) { await model.setAllowlistRemoteFeed($0) }
        add(
            "servercritical",
            .server,
            "Critical alerts on server",
            "Desktop and web-console warnings on the server itself. This iPhone's alerts live in More → Alerts.",
            s.criticalAlertsEnabled
        ) { await model.setServerCriticalAlerts($0) }

        return items
    }
}
