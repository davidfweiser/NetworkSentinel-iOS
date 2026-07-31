import SwiftUI

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @Binding var showServers: Bool

    private var stats: StatsInfo? { model.state?.stats }
    private var settings: SettingsInfo? { model.state?.settings }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    statusHeader
                    statsGrid
                    activityCard
                    controlsCard
                    recentThreats
                    openPortsPreview
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 28)
            }
            .background(NSTheme.gradient.ignoresSafeArea())
            .navigationTitle("Dashboard")
            .navigationBarTitleDisplayMode(.large)
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
        }
    }

    private var statusHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                monitoringPill
                Spacer()
                if let clock = model.state?.clock {
                    Text(clock)
                        .font(.caption.monospaced())
                        .foregroundStyle(NSTheme.muted)
                }
            }

            if let msg = model.state?.statusMessage, !msg.isEmpty {
                Text(msg)
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(3)
            }

            HStack(spacing: 12) {
                Label(model.state?.firewall?.privilegeText ?? "Firewall unknown", systemImage: "lock.shield")
                    .font(.caption)
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
                Spacer()
                if let v = model.state?.version {
                    Text("v\(v)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(NSTheme.muted)
                }
            }

            if let err = model.lastError {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(NSTheme.danger)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .nsCard()
    }

    private var monitoringPill: some View {
        let on = settings?.isMonitoring ?? stats?.isMonitoring ?? false
        return HStack(spacing: 6) {
            Circle()
                .fill(on ? NSTheme.success : NSTheme.warning)
                .frame(width: 8, height: 8)
            Text(on ? "Monitoring" : "Paused")
                .font(.caption.weight(.semibold))
                .foregroundStyle(on ? NSTheme.success : NSTheme.warning)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background((on ? NSTheme.success : NSTheme.warning).opacity(0.12), in: Capsule())
    }

    private var statsGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
            StatTile(
                title: "Connections",
                value: "\(stats?.activeConnections ?? 0)",
                icon: "arrow.left.arrow.right",
                tint: NSTheme.accent
            )
            StatTile(
                title: "Remote hosts",
                value: "\(stats?.remoteHosts ?? 0)",
                icon: "network",
                tint: NSTheme.cyan
            )
            StatTile(
                title: "Threats today",
                value: "\(stats?.threatsToday ?? 0)",
                icon: "exclamationmark.triangle.fill",
                tint: NSTheme.warning,
                subtitle: stats?.highThreats.map { "\($0) high+" }
            )
            StatTile(
                title: "Listening ports",
                value: "\(stats?.listeningPorts ?? 0)",
                icon: "antenna.radiowaves.left.and.right",
                tint: NSTheme.success
            )
        }
    }

    private var activityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Activity")
                    .font(.headline)
                    .foregroundStyle(NSTheme.text)
                Spacer()
                Text("Connections")
                    .font(.caption)
                    .foregroundStyle(NSTheme.muted)
            }

            if let activity = model.state?.activity, !activity.isEmpty {
                ActivitySparkline(points: activity)
                    .frame(height: 72)
                chartLegend(activity)
            } else {
                Text("Waiting for samples…")
                    .font(.caption)
                    .foregroundStyle(NSTheme.muted)
                    .frame(height: 72)
            }
        }
        .nsCard()
    }

    /// Mirrors the web console's chart-meta row so the marker colour has a key.
    private func chartLegend(_ activity: [ActivityPoint]) -> some View {
        let now = activity.last?.connections ?? 0
        let peak = activity.map { $0.connections ?? 0 }.max() ?? 0
        let threatTotal = activity.reduce(0) { $0 + ($1.threats ?? 0) }

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 14) {
                legendKey(
                    isBar: false,
                    color: NSTheme.cyan,
                    text: "Connections · now \(now) · peak \(peak)"
                )
                legendKey(
                    isBar: true,
                    color: NSTheme.threatMarker,
                    text: threatTotal > 0 ? "Threats · \(threatTotal) in window" : "Threats · none in window"
                )
                Spacer(minLength: 0)
            }

            HStack {
                Text(activity.first?.time ?? "")
                Spacer()
                Text(activity.last?.time ?? "")
            }
            .font(.caption2.monospaced())
            .foregroundStyle(NSTheme.muted)
        }
    }

    private func legendKey(isBar: Bool, color: Color, text: String) -> some View {
        HStack(spacing: 5) {
            if isBar {
                RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                    .fill(color.opacity(0.55))
                    .frame(width: 4, height: 11)
            } else {
                Circle()
                    .fill(color)
                    .frame(width: 7, height: 7)
            }
            Text(text)
                .font(.caption2)
                .foregroundStyle(NSTheme.muted)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
        }
    }

    private var controlsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Controls")
                .font(.headline)
                .foregroundStyle(NSTheme.text)

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                controlButton(
                    title: (settings?.isMonitoring ?? true) ? "Pause" : "Resume",
                    icon: (settings?.isMonitoring ?? true) ? "pause.fill" : "play.fill"
                ) {
                    await model.toggleMonitor()
                }

                controlButton(
                    title: (settings?.autoBlockEnabled ?? false) ? "Auto-block ON" : "Auto-block OFF",
                    icon: "hand.raised.fill",
                    tint: (settings?.autoBlockEnabled ?? false) ? NSTheme.danger : NSTheme.muted
                ) {
                    await model.toggleAutoblock()
                }

                Menu {
                    ForEach(["Medium", "High", "Critical"], id: \.self) { level in
                        Button(level) {
                            Task { await model.setMinLevel(level) }
                        }
                    }
                } label: {
                    controlLabel(
                        title: "Min: \(settings?.autoBlockMinLevel ?? "High")",
                        icon: "slider.horizontal.3"
                    )
                }

                controlButton(title: "Clear threats", icon: "trash") {
                    await model.clearThreats()
                }
            }

            // Web 0.3+ exposes geo / allowlist feed (and set_setting for all of these).
            // Gate the whole panel so older servers don't get unknown-action errors.
            if settings?.geoLookupEnabled != nil || settings?.allowlistUseRemoteFeed != nil {
                VStack(spacing: 0) {
                    settingToggle(
                        title: "Block inbound",
                        isOn: settings?.blockInbound ?? true
                    ) { await model.setBlockInbound($0) }
                    Divider().overlay(NSTheme.border)
                    settingToggle(
                        title: "Block outbound",
                        isOn: settings?.blockOutbound ?? false
                    ) { await model.setBlockOutbound($0) }
                    if settings?.geoLookupEnabled != nil {
                        Divider().overlay(NSTheme.border)
                        settingToggle(
                            title: "Geo lookups",
                            isOn: settings?.geoLookupEnabled ?? true
                        ) { await model.setGeoLookup($0) }
                    }
                    if settings?.allowlistUseRemoteFeed != nil {
                        Divider().overlay(NSTheme.border)
                        settingToggle(
                            title: "Allowlist remote feed",
                            isOn: settings?.allowlistUseRemoteFeed ?? true
                        ) { await model.setAllowlistRemoteFeed($0) }
                    }
                    // Web 0.3.3+ — auth-log brute-force detection.
                    if settings?.authLogMonitorEnabled != nil {
                        Divider().overlay(NSTheme.border)
                        settingToggle(
                            title: "Auth-log monitoring",
                            subtitle: settings?.authLogStatus,
                            isOn: settings?.authLogMonitorEnabled ?? false
                        ) { await model.setAuthLogMonitor($0) }
                    }
                    // Web 0.3.4+ — closed-port scan detection (needs elevation on the server).
                    if settings?.probeLogEnabled != nil {
                        Divider().overlay(NSTheme.border)
                        settingToggle(
                            title: "Closed-port scan detection",
                            subtitle: settings?.probeLogStatus,
                            isOn: settings?.probeLogEnabled ?? false
                        ) { await model.setProbeLog($0) }
                    }
                    // Web 0.3.5+ — Critical warnings on the server's own console.
                    if settings?.criticalAlertsEnabled != nil {
                        Divider().overlay(NSTheme.border)
                        settingToggle(
                            title: "Critical alerts on server",
                            subtitle: "Desktop notification and web-console tab badge on the server itself. This iPhone's alerts are in More → Alerts.",
                            isOn: settings?.criticalAlertsEnabled ?? true
                        ) { await model.setServerCriticalAlerts($0) }
                    }
                }
                .padding(.horizontal, 4)
                .padding(.vertical, 2)
                .background(NSTheme.cardElevated, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
        }
        .nsCard()
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
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private func controlButton(title: String, icon: String, tint: Color = NSTheme.accent, action: @escaping () async -> Void) -> some View {
        Button {
            Task { await action() }
        } label: {
            controlLabel(title: title, icon: icon, tint: tint)
        }
        .buttonStyle(.plain)
    }

    private func controlLabel(title: String, icon: String, tint: Color = NSTheme.accent) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(tint)
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(NSTheme.text)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(NSTheme.cardElevated, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private var recentThreats: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recent threats")
                    .font(.headline)
                    .foregroundStyle(NSTheme.text)
                Spacer()
                Text("\(model.state?.threats?.count ?? 0)")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(NSTheme.muted)
            }

            let items = Array((model.state?.threats ?? []).prefix(5)).uniquedRows()
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
                                .font(.caption.monospaced())
                                .foregroundStyle(NSTheme.muted)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 4)
                    if row.id != items.last?.id {
                        Divider().overlay(NSTheme.border)
                    }
                }
            }
        }
        .nsCard()
    }

    private var openPortsPreview: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Listening ports")
                .font(.headline)
                .foregroundStyle(NSTheme.text)

            let ports = Array((model.state?.ports ?? []).prefix(6)).uniquedRows()
            if ports.isEmpty {
                Text("No open listeners reported.")
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.muted)
            } else {
                ForEach(ports) { row in
                    let p = row.value
                    HStack {
                        Text("\(p.protocolName.uppercased())")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(NSTheme.accent)
                            .frame(width: 36, alignment: .leading)
                        Text(":\(p.port)")
                            .font(.subheadline.monospaced().weight(.semibold))
                            .foregroundStyle(NSTheme.text)
                        if let hint = p.hint, !hint.isEmpty {
                            Text(hint)
                                .font(.caption)
                                .foregroundStyle(NSTheme.muted)
                                .lineLimit(1)
                        }
                        Spacer()
                        Text(p.process ?? "—")
                            .font(.caption)
                            .foregroundStyle(NSTheme.muted)
                            .lineLimit(1)
                    }
                }
            }
        }
        .nsCard()
    }
}
