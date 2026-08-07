import SwiftUI

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @Binding var showServers: Bool

    @Namespace private var glassNamespace
    /// The free-text server settings all edit the same way — one row, one alert, one
    /// `set_setting` — so they share a single editor rather than a `@State` pair each.
    @State private var textEdit: TextSettingEdit?
    @State private var textEditDraft = ""
    @State private var showWireGuardPeers = false

    private var stats: StatsInfo? { model.state?.stats }
    private var settings: SettingsInfo? { model.state?.settings }
    private var monitoring: Bool { settings?.isMonitoring ?? stats?.isMonitoring ?? false }
    private var asleep: Bool { model.isAsleep }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    statusHeader
                    if asleep {
                        SleepBanner { Task { await model.wakeConsole() } }
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                    // Live readings dim while asleep; the controls below stay at full
                    // strength, because they hold the other way back to Wake — the same
                    // split the web console makes between its tables and Settings.
                    attentionCard.nsAsleepDimmed(asleep)
                    statsGrid.nsAsleepDimmed(asleep)
                    activityCard.nsAsleepDimmed(asleep)
                    controlsCard
                    settingsCards
                    recentThreats.nsAsleepDimmed(asleep)
                }
                .animation(.easeInOut(duration: 0.25), value: asleep)
                .padding(.horizontal, 16)
                .padding(.bottom, 28)
            }
            .background {
                AmbientField(severity: model.liveSeverity, load: model.activityLoad)
            }
            .scrollEdgeEffectStyle(.soft, for: .top)
            // The toolbar already names the server; a large title would cost a fifth of the
            // screen to repeat the tab label.
            .navigationTitle("Dashboard")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showServers = true } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "server.rack")
                            Text(model.server?.name ?? "Server")
                                .lineLimit(1)
                        }
                        .font(.subheadline.weight(.semibold))
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await model.refresh(silent: false) }
                    } label: {
                        if model.isLoading || model.isRefreshing {
                            ProgressView()
                        } else {
                            Image(systemName: "arrow.clockwise")
                        }
                    }
                }
            }
            .refreshable {
                await model.refresh(silent: false)
            }
            .sheet(isPresented: $showWireGuardPeers) {
                WireGuardPeersView(
                    peers: settings?.wireGuardPeers ?? [],
                    status: settings?.wireGuardStatus
                )
                .preferredColorScheme(.dark)
            }
            .nsTextSettingAlert($textEdit, draft: $textEditDraft)
        }
    }

    /// Every server-settings card, in the order the web console's own Settings tab puts
    /// them. Grouped into one member so the scroll body stays under ViewBuilder's ten-child
    /// limit — 0.6 added three of these on its own.
    @ViewBuilder
    private var settingsCards: some View {
        detectionCard
        intrusionCard
        dnsHygieneCard
        wireGuardCard
        suricataCard
    }

    // MARK: - Status

    private var statusHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                monitoringPill
                Spacer()
                if let clock = model.state?.clock {
                    Text(clock)
                        .font(.system(size: 12).monospaced())
                        .foregroundStyle(NSTheme.muted)
                        .contentTransition(.numericText())
                }
            }

            if let msg = model.state?.statusMessage, !msg.isEmpty {
                Text(msg)
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(3)
                    .contentTransition(.opacity)
            }

            HStack(spacing: 10) {
                Label(model.state?.firewall?.privilegeText ?? "Firewall unknown", systemImage: "lock.shield")
                    .font(.caption)
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
                Spacer()
                if let v = model.state?.version {
                    Text("v\(v)")
                        .font(.system(size: 10).monospaced())
                        .foregroundStyle(NSTheme.muted)
                }
            }

            if let err = model.lastError {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(NSTheme.danger)
                    .transition(.opacity)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        // Deliberately untinted: the attention card below carries the alarm colour, and two
        // stacked red panels read as noise rather than urgency.
        .nsCard()
    }

    /// The server stops the same way either way, so the wording is the only thing that
    /// tells you whether this phone parked itself along with it.
    private var monitoringLabel: String {
        if asleep { return "Asleep" }
        return monitoring ? "Monitoring" : "Paused"
    }

    private var monitoringPill: some View {
        let tint = monitoring ? NSTheme.success : NSTheme.warning
        return HStack(spacing: 6) {
            Circle()
                .fill(tint)
                .frame(width: 7, height: 7)
            Text(monitoringLabel)
                .font(.system(size: 11, weight: .semibold))
                .textCase(.uppercase)
                .tracking(0.6)
                .foregroundStyle(tint)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(tint.opacity(0.14), in: .capsule)
        .animation(.snappy, value: monitoring)
        .animation(.snappy, value: asleep)
    }

    // MARK: - Needs attention
    //
    // The whole point of the app in one card: the worst live threat and the button that
    // stops it, without scanning a list first. Absent when nothing is High or above.

    @ViewBuilder
    private var attentionCard: some View {
        if let t = model.attentionThreat {
            let severity = ThreatSeverity.from(level: t.level, levelNum: t.levelNum)
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Needs attention").nsEyebrow()
                    Spacer()
                    if model.attentionBacklog > 0 {
                        Text("+\(model.attentionBacklog) more")
                            .font(.caption2)
                            .foregroundStyle(NSTheme.muted)
                    }
                }

                Text(t.title)
                    .font(.headline)
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(2)

                if let detail = t.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(NSTheme.mutedOnTint)
                        .lineLimit(2)
                }

                HStack(spacing: 10) {
                    SeverityBadge(level: t.level, levelNum: t.levelNum)
                    // 0.4+ host-local detectors (new listener, launch item) report loopback
                    // rather than a peer, so lead with what was detected instead of an IP
                    // the user cannot act on.
                    Text(t.isBlockable ? t.sourceIp : (t.type ?? "This computer"))
                        .font(.system(size: 12).monospaced())
                        .foregroundStyle(NSTheme.cyan)
                        .lineLimit(1)
                    Spacer()
                    if t.isBlockable {
                        Button("Block") {
                            Task { await model.requestBlock(ip: t.sourceIp) }
                        }
                        .font(.subheadline.weight(.semibold))
                        .buttonStyle(.glassProminent)
                        .tint(severity.color)
                    } else {
                        // Nothing to firewall — the fix is on the server itself, so send
                        // the user to the full detail rather than to a failing action.
                        Text("On this host")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(NSTheme.mutedOnTint)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard(tint: severity.color)
            .transition(.asymmetric(
                insertion: .scale(scale: 0.96).combined(with: .opacity),
                removal: .opacity
            ))
            .animation(.spring(response: 0.4, dampingFraction: 0.8), value: t.id)
        }
    }

    // MARK: - Metrics

    private var statsGrid: some View {
        GlassEffectContainer(spacing: 12) {
            LazyVGrid(
                columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)],
                spacing: 12
            ) {
                StatTile(
                    title: "Connections",
                    value: stats?.activeConnections ?? 0,
                    icon: "arrow.left.arrow.right",
                    tint: NSTheme.accent
                )
                StatTile(
                    title: "Remote hosts",
                    value: stats?.remoteHosts ?? 0,
                    icon: "network",
                    tint: NSTheme.signal
                )
                StatTile(
                    title: "Threats today",
                    value: stats?.threatsToday ?? 0,
                    icon: "exclamationmark.triangle.fill",
                    tint: (stats?.highThreats ?? 0) > 0 ? NSTheme.danger : NSTheme.warning,
                    subtitle: (stats?.highThreats ?? 0) > 0 ? "\(stats?.highThreats ?? 0) high+" : nil
                )
                StatTile(
                    title: "Listening ports",
                    value: stats?.listeningPorts ?? 0,
                    icon: "antenna.radiowaves.left.and.right",
                    tint: NSTheme.success
                )
            }
        }
    }

    private var activityCard: some View {
        Group {
            if let activity = model.state?.activity, !activity.isEmpty {
                ActivityChart(points: activity)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Activity").nsEyebrow()
                    Text("Waiting for samples…")
                        .font(.subheadline)
                        .foregroundStyle(NSTheme.muted)
                        .frame(height: 108)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .nsCard()
    }

    // MARK: - Controls

    private var controlsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Controls").nsEyebrow()

            GlassEffectContainer(spacing: 10) {
                LazyVGrid(
                    columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)],
                    spacing: 10
                ) {
                    // Sleep leads, as it does in the web console header.
                    controlButton(
                        title: asleep ? "Wake" : "Sleep",
                        icon: asleep ? "sun.max.fill" : "moon.zzz.fill",
                        tint: asleep ? NSTheme.warning : NSTheme.accent
                    ) {
                        await model.toggleSleep()
                    }
                    .glassEffectID("sleep", in: glassNamespace)

                    // Asleep, Wake is the way back — a second button offering to un-stop
                    // the same monitor would just be two names for one thing.
                    if !asleep {
                        controlButton(
                            title: monitoring ? "Pause" : "Resume",
                            icon: monitoring ? "pause.fill" : "play.fill",
                            tint: monitoring ? NSTheme.warning : NSTheme.success
                        ) {
                            await model.toggleMonitor()
                        }
                        .glassEffectID("monitor", in: glassNamespace)
                    }

                    controlButton(
                        title: (settings?.autoBlockEnabled ?? false) ? "Auto-block on" : "Auto-block off",
                        icon: "hand.raised.fill",
                        tint: (settings?.autoBlockEnabled ?? false) ? NSTheme.danger : NSTheme.muted
                    ) {
                        await model.toggleAutoblock()
                    }
                    .glassEffectID("autoblock", in: glassNamespace)

                    Menu {
                        ForEach(["Medium", "High", "Critical"], id: \.self) { level in
                            Button(level) {
                                Task { await model.setMinLevel(level) }
                            }
                        }
                    } label: {
                        controlLabel(
                            title: "Min: \(settings?.autoBlockMinLevel ?? "High")",
                            icon: "slider.horizontal.3",
                            tint: NSTheme.accent
                        )
                    }
                    .buttonStyle(.glass)

                    controlButton(title: "Clear threats", icon: "trash", tint: NSTheme.muted) {
                        await model.clearThreats()
                    }
                }
            }

            // Web 0.4+ — auto-block rules can expire on their own. Presets rather than a
            // minutes field: nobody types "10080" on a phone to mean a week.
            if let expiry = settings?.autoBlockExpiryMinutes {
                Menu {
                    ForEach(Self.expiryOptions, id: \.minutes) { option in
                        Button(option.label) {
                            Task { await model.setAutoBlockExpiry(minutes: option.minutes) }
                        }
                    }
                } label: {
                    controlLabel(
                        title: "Block rules expire: \(Self.expiryLabel(expiry))",
                        icon: "timer",
                        tint: expiry > 0 ? NSTheme.signal : NSTheme.muted
                    )
                }
                .buttonStyle(.glass)
            }

            // Web 0.6+ — the single prevention engine can walk every gate and report what
            // it would have dropped without writing a rule. It belongs with the auto-block
            // controls it modifies, not in a detector list: it changes what blocking *does*.
            if let dryRun = settings?.preventionDryRun {
                settingToggle(
                    title: "Dry run",
                    subtitle: dryRun
                        ? "Auto-block reports what it would drop and writes no firewall rules."
                        : "Auto-block writes firewall rules. Turn dry run on before trusting a new detection source.",
                    isOn: dryRun
                ) { await model.setPreventionDryRun($0) }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .nsCard()
    }

    private static let expiryOptions: [(minutes: Int, label: String)] = [
        (0, "Never"),
        (60, "1 hour"),
        (360, "6 hours"),
        (1440, "24 hours"),
        (10080, "7 days")
    ]

    private static func expiryLabel(_ minutes: Int) -> String {
        if let known = expiryOptions.first(where: { $0.minutes == minutes }) { return known.label }
        if minutes % 1440 == 0 { return "\(minutes / 1440)d" }
        if minutes % 60 == 0 { return "\(minutes / 60)h" }
        return "\(minutes)m"
    }

    private func controlButton(
        title: String,
        icon: String,
        tint: Color = NSTheme.accent,
        action: @escaping () async -> Void
    ) -> some View {
        Button {
            Task { await action() }
        } label: {
            controlLabel(title: title, icon: icon, tint: tint)
        }
        .buttonStyle(.glass)
    }

    private func controlLabel(title: String, icon: String, tint: Color) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(tint)
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(NSTheme.text)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .contentTransition(.interpolate)
    }

    // MARK: - Detection settings

    /// Web 0.3+ exposes these via `set_setting`. The whole panel is gated so older servers
    /// never get unknown-action errors, and each row appears only once its server does.
    @ViewBuilder
    private var detectionCard: some View {
        if settings?.geoLookupEnabled != nil || settings?.allowlistUseRemoteFeed != nil {
            VStack(alignment: .leading, spacing: 4) {
                Text("Detection").nsEyebrow()
                    .padding(.bottom, 4)

                settingToggle(title: "Block inbound", isOn: settings?.blockInbound ?? true) {
                    await model.setBlockInbound($0)
                }
                settingToggle(title: "Block outbound", isOn: settings?.blockOutbound ?? false) {
                    await model.setBlockOutbound($0)
                }
                if settings?.geoLookupEnabled != nil {
                    settingToggle(title: "Geo lookups", isOn: settings?.geoLookupEnabled ?? true) {
                        await model.setGeoLookup($0)
                    }
                }
                if settings?.allowlistUseRemoteFeed != nil {
                    settingToggle(
                        title: "Allowlist remote feed",
                        isOn: settings?.allowlistUseRemoteFeed ?? true
                    ) { await model.setAllowlistRemoteFeed($0) }
                }
                // Web 0.3.3+ — auth-log brute-force detection.
                if settings?.authLogMonitorEnabled != nil {
                    settingToggle(
                        title: "Auth-log monitoring",
                        subtitle: settings?.authLogStatus,
                        isOn: settings?.authLogMonitorEnabled ?? false
                    ) { await model.setAuthLogMonitor($0) }
                }
                // Web 0.3.4+ — closed-port scan detection (needs elevation on the server).
                if settings?.probeLogEnabled != nil {
                    settingToggle(
                        title: "Closed-port scan detection",
                        subtitle: settings?.probeLogStatus,
                        isOn: settings?.probeLogEnabled ?? false
                    ) { await model.setProbeLog($0) }
                }
                // Web 0.3.5+ — Critical warnings on the server's own console.
                if settings?.criticalAlertsEnabled != nil {
                    settingToggle(
                        title: "Critical alerts on server",
                        subtitle: "Desktop and web-console warnings on the server itself. This iPhone's alerts live in More → Alerts.",
                        isOn: settings?.criticalAlertsEnabled ?? true
                    ) { await model.setServerCriticalAlerts($0) }
                }
                // Web 0.6+ — kernel flow events. Not a detector: it changes *when* the
                // existing heuristics get their snapshot, which is why it sits here rather
                // than with the intrusion suite.
                if let flow = settings?.conntrackEventsEnabled {
                    settingToggle(
                        title: "Kernel flow events",
                        subtitle: settings?.conntrackStatus
                            ?? "Takes a snapshot when a connection arrives instead of waiting out the poll interval. Needs root on the server.",
                        isOn: flow
                    ) { await model.setConntrackEvents($0) }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard()
        }
    }

    // MARK: - Intrusion detection (web 0.4+)

    /// The 0.4.0 detector suite. `threatIntelEnabled` stands in for the whole group —
    /// a server that reports one of these reports all of them — so one probe gates the
    /// card and nothing here is offered to a 0.3.x server that would reject it.
    @ViewBuilder
    private var intrusionCard: some View {
        if settings?.threatIntelEnabled != nil {
            VStack(alignment: .leading, spacing: 4) {
                Text("Intrusion detection").nsEyebrow()
                    .padding(.bottom, 4)

                settingToggle(
                    title: "Threat-intel blocklists",
                    subtitle: settings?.threatIntelStatus,
                    isOn: settings?.threatIntelEnabled ?? true
                ) { await model.setThreatIntel($0) }

                settingToggle(
                    title: "New-listener alerts",
                    subtitle: "A new open port, or a known port changing owner process.",
                    isOn: settings?.newListenerAlertsEnabled ?? true
                ) { await model.setNewListenerAlerts($0) }

                settingToggle(
                    title: "Process reputation",
                    subtitle: "Unsigned or quarantined binaries talking to public hosts, and shells with outbound connections.",
                    isOn: settings?.processReputationEnabled ?? true
                ) { await model.setProcessReputation($0) }

                settingToggle(
                    title: "ARP / gateway watch",
                    subtitle: settings?.arpWatchStatus,
                    isOn: settings?.arpWatchEnabled ?? true
                ) { await model.setArpWatch($0) }

                // macOS calls this launch items, Linux and Windows call it startup items;
                // it is one watcher under two setting names, and the server decides which.
                if let startupWatch = settings?.startupWatchEnabled {
                    settingToggle(
                        title: settings?.startupWatchTitle ?? "Startup-item watch",
                        subtitle: settings?.startupWatchStatus,
                        isOn: startupWatch
                    ) { await model.setStartupItemWatch($0) }
                }

                settingToggle(
                    title: "Exfiltration monitor",
                    subtitle: settings?.exfilStatus,
                    isOn: settings?.exfilMonitorEnabled ?? true
                ) { await model.setExfilMonitor($0) }

                if let mb = settings?.exfilMbPer10Min {
                    settingMenu(
                        title: "Exfil threshold",
                        value: "\(mb) MB / 10 min",
                        options: Self.exfilOptions.map { ("\($0) MB", $0) }
                    ) { await model.setExfilThreshold($0) }
                }

                settingToggle(
                    title: "Honeypot decoy ports",
                    subtitle: settings?.honeypotStatus,
                    isOn: settings?.honeypotEnabled ?? false
                ) { await model.setHoneypot($0) }

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
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard()
        }
    }

    private static let exfilOptions = [50, 100, 250, 500, 1000, 2000]

    // MARK: - DNS hygiene (web 0.6+)

    /// Almost nothing connects without resolving a name first, and DNS is UDP — the
    /// exfiltration monitor counts TCP socket bytes and cannot see it at all.
    @ViewBuilder
    private var dnsHygieneCard: some View {
        if let enabled = settings?.dnsHygieneEnabled {
            VStack(alignment: .leading, spacing: 4) {
                Text("DNS hygiene").nsEyebrow()
                    .padding(.bottom, 4)

                settingToggle(
                    title: "Monitor DNS",
                    subtitle: settings?.dnsHygieneStatus,
                    isOn: enabled
                ) { await model.setDnsHygiene($0) }

                textSettingRow(
                    title: "Approved resolvers",
                    // Without this list a DoH setup looks like no DNS at all rather than
                    // like a leak, which is the difference between quiet and wrong.
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
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard()
        }
    }

    // MARK: - WireGuard peers (web 0.6+)

    /// A tunnel is one unconnected UDP socket, so no VPN client ever becomes a tracked
    /// connection — nothing about a peer reaches the heuristics without this.
    @ViewBuilder
    private var wireGuardCard: some View {
        if let enabled = settings?.wireGuardMonitorEnabled {
            let peers = settings?.wireGuardPeers ?? []
            VStack(alignment: .leading, spacing: 4) {
                Text("VPN peers · WireGuard").nsEyebrow()
                    .padding(.bottom, 4)

                settingToggle(
                    title: "Monitor peers",
                    subtitle: settings?.wireGuardStatus,
                    isOn: enabled
                ) { await model.setWireGuardMonitor($0) }

                if let mb = settings?.wireGuardPeerMbPer10Min {
                    settingMenu(
                        title: "Per-peer transfer",
                        // Off by default on the server, and the reason matters: forwarded
                        // tunnel traffic has no local socket, so this is the only place it
                        // is counted — and a peer streaming video moves gigabytes.
                        subtitle: mb == 0
                            ? "Off. Forwarded tunnel traffic has no local socket, so nothing else counts it."
                            : nil,
                        value: mb == 0 ? "Off" : "\(mb) MB / 10 min",
                        options: Self.wireGuardThresholdOptions
                    ) { await model.setWireGuardPeerThreshold($0) }
                }

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
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard()
        }
    }

    private static let wireGuardThresholdOptions: [(label: String, value: Int)] = [
        ("Off", 0),
        ("500 MB", 500),
        ("1 GB", 1000),
        ("5 GB", 5000),
        ("10 GB", 10000)
    ]

    // MARK: - Suricata signatures (web 0.6+)

    /// The heuristics see who is talking and how often; they can never see what is being
    /// said. Suricata is the engine, the server is the manager, and this is its switch.
    @ViewBuilder
    private var suricataCard: some View {
        if let enabled = settings?.suricataEnabled {
            VStack(alignment: .leading, spacing: 4) {
                Text("Signatures · Suricata").nsEyebrow()
                    .padding(.bottom, 4)

                settingToggle(
                    title: "Ingest Suricata alerts",
                    subtitle: settings?.suricataStatus,
                    isOn: enabled
                ) { await model.setSuricata($0) }

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
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard()
        }
    }

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
        .padding(.vertical, 7)
    }

    /// Preset picker for a numeric server setting, styled to match `settingToggle` rows.
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
                    }
                }
                Spacer()
                Text(value)
                    .font(.system(size: 12).monospaced())
                    .foregroundStyle(NSTheme.cyan)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
            }
            .padding(.vertical, 7)
        }
    }

    private func settingToggle(
        title: String,
        subtitle: String? = nil,
        isOn: Bool,
        action: @escaping (Bool) async -> Void
    ) -> some View {
        Toggle(isOn: Binding(
            get: { isOn },
            set: { newValue in Task { await action(newValue) } }
        )) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.text)
                // Server-side status (which log is watched, or why it is unavailable).
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .tint(NSTheme.accent)
        .padding(.vertical, 7)
    }

    // MARK: - Recent threats

    private var recentThreats: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recent threats").nsEyebrow()
                Spacer()
                Text("\(model.state?.threats?.count ?? 0)")
                    .font(.readout(13, weight: .bold))
                    .foregroundStyle(NSTheme.muted)
                    .contentTransition(.numericText())
            }

            let items = Array((model.state?.threats ?? []).prefix(4)).uniquedRows()
            if items.isEmpty {
                Text("No threats right now.")
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.muted)
            } else {
                ForEach(items) { row in
                    let t = row.value
                    HStack(alignment: .top, spacing: 10) {
                        SeverityBadge(level: t.level, levelNum: t.levelNum)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(t.title)
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(NSTheme.text)
                                .lineLimit(2)
                            Text("\(t.sourceIp) · \(t.time)")
                                .font(.system(size: 11).monospaced())
                                .foregroundStyle(NSTheme.muted)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 3)
                    if row.id != items.last?.id {
                        Divider().overlay(NSTheme.border)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .nsCard()
        .animation(.snappy(duration: 0.3), value: model.state?.threats?.count ?? 0)
    }
}
