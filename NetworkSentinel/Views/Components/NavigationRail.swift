import SwiftUI

/// The console's navigation rail, on the phone.
///
/// The web console and the desktop window carry the same menu — ten entries, two of them
/// indented under Firewall & Block and one under Settings — and a five-slot tab bar can only
/// carry half of it. The app's answer used to be that the other five were somewhere sensible:
/// Open Ports and Allowlist a row inside the Firewall tab, Remote Computers a segment of the
/// Connections picker, Help a row under Settings. Sensible, and not the same menu: someone who
/// knows the console knows where *Allowlist* is, and on the phone that knowledge was worth
/// nothing.
///
/// So the rail comes over whole. It opens from every screen, it lists all ten entries in the
/// console's order with the console's names, the two sub-entries are indented under their
/// parent, and the checked one carries the same ringed dot. Web 0.7.15 adds an eleventh,
/// **Blocked Sites**, which the console shows only once a filtering resolver is configured —
/// so this rail does too. Underneath sits the rail's status
/// block: what the monitor is doing, whether the firewall can be written, and the one toggle
/// that decides whether detections turn into kernel rules.
///
/// The tab bar stays. It is the fast path to the five screens a phone actually lives in, and
/// this is the map — the same relationship the desktop has between its toolbar and its rail.
enum RailEntry: String, CaseIterable, Identifiable {
    case dashboard
    case connections
    case hosts
    case threats
    case ports
    case firewall
    case firewallConfig
    case allowlist
    /// Web 0.7.15. Not always in the menu — see `NavigationRailView.entries`.
    case dnsBlocked
    case settings
    case help

    var id: String { rawValue }

    /// The console's own label, not a shortened one. The tab bar abbreviates because a tab
    /// bar must; a rail row has the width to say what the console says.
    var title: String {
        switch self {
        case .dashboard: return "Dashboard"
        case .connections: return "Live Connections"
        case .hosts: return "Remote Computers"
        case .threats: return "Break-in Attempts"
        case .ports: return "Open Ports"
        case .firewall: return "Firewall & Block"
        case .firewallConfig: return "Firewall Config"
        case .allowlist: return "Allowlist"
        case .dnsBlocked: return "Blocked Sites"
        case .settings: return "Settings"
        case .help: return "Help"
        }
    }

    /// `nav button.sub` — indented under its parent, and a shade quieter, so the rail reads
    /// as a hierarchy rather than a longer flat list.
    var isSub: Bool {
        switch self {
        case .firewallConfig, .allowlist, .help: return true
        default: return false
        }
    }

    /// The console puts these on the two entries whose names do not say what they hold.
    var hint: String? {
        switch self {
        case .firewallConfig: return "Add, edit and delete inbound and outbound rules"
        case .allowlist: return "Domains and IPs that are never blocked"
        case .dnsBlocked: return "Names the filtering resolver refused"
        default: return nil
        }
    }
}

struct NavigationRailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    /// Which entry the app is currently showing, so the rail can check it.
    let current: RailEntry
    let onSelect: (RailEntry) -> Void

    private var settings: SettingsInfo? { model.state?.settings }

    /// The menu, for this server. Nine entries are always in it; **Blocked Sites** appears
    /// only once a filtering resolver is configured, which is what the console does with its
    /// own nav item — a list of refused names with no resolver behind it has nothing to say,
    /// and every other entry in this rail leads somewhere on every server.
    private var entries: [RailEntry] {
        RailEntry.allCases.filter { $0 != .dnsBlocked || model.hasDnsFilter }
    }
    private var monitoring: Bool {
        !model.isAsleep && (settings?.isMonitoring ?? model.state?.stats?.isMonitoring ?? false)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            brand
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Text("Navigation")
                        .font(.system(size: 10.5, weight: .bold))
                        .textCase(.uppercase)
                        .tracking(1.4)
                        .foregroundStyle(NSTheme.dim)
                        .padding(.leading, 8)
                        .padding(.bottom, 8)

                    ForEach(entries) { entry in
                        railButton(entry)
                    }
                }
                .padding(.horizontal, 2)
            }
            statusBox
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background { AmbientField() }
    }

    // MARK: - Brand

    private var brand: some View {
        HStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(NSTheme.ink)
                .frame(width: 42, height: 42)
                .background(NSTheme.accentGradient, in: .rect(cornerRadius: 10))

            VStack(alignment: .leading, spacing: 2) {
                Text("Network Sentinel")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(NSTheme.text)
                Text(model.server?.name ?? "No server")
                    .font(.system(size: 11))
                    .foregroundStyle(NSTheme.signal)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(NSTheme.dim)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 4)
        .padding(.bottom, 18)
    }

    // MARK: - Rail rows

    private func railButton(_ entry: RailEntry) -> some View {
        let active = entry == current
        return Button {
            onSelect(entry)
            dismiss()
        } label: {
            HStack(spacing: 12) {
                // The ring, and the dot the checked one carries — drawn the way the console
                // draws it, as a ring with a filled centre rather than a filled circle, so
                // the unchecked rows still read as a column of choices.
                Circle()
                    .stroke(active ? NSTheme.signal : NSTheme.dim, lineWidth: 2)
                    .frame(width: 15, height: 15)
                    .overlay {
                        if active {
                            Circle().fill(NSTheme.signal).frame(width: 7, height: 7)
                        }
                    }

                VStack(alignment: .leading, spacing: 1) {
                    Text(entry.title)
                        .font(.system(size: entry.isSub ? 14 : 15, weight: entry.isSub ? .regular : .semibold))
                        .foregroundStyle(active ? NSTheme.text : NSTheme.text2)
                    if let hint = entry.hint {
                        Text(hint)
                            .font(.system(size: 11))
                            .foregroundStyle(NSTheme.dim)
                            .lineLimit(1)
                    }
                }
                Spacer(minLength: 0)
                if let badge = badge(for: entry) {
                    Text(badge)
                        .font(.system(size: 11, weight: .semibold).monospacedDigit())
                        .foregroundStyle(NSTheme.dim)
                }
            }
            .padding(.leading, entry.isSub ? 30 : 14)
            .padding(.trailing, 14)
            .padding(.vertical, entry.isSub ? 8 : 11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                active ? NSTheme.accent.opacity(0.15) : .clear,
                in: .rect(cornerRadius: 10)
            )
        }
        .buttonStyle(.plain)
        .padding(.bottom, entry.isSub ? 3 : 0)
    }

    /// What the console shows in each table, counted. A rail that says the firewall has
    /// thirty rules is a rail worth opening.
    private func badge(for entry: RailEntry) -> String? {
        let state = model.state
        let count: Int?
        switch entry {
        case .connections: count = state?.connections?.count
        case .hosts: count = state?.hosts?.count
        case .threats: count = state?.threats?.count
        case .ports: count = state?.ports?.count
        case .firewall: count = (state?.firewallRules ?? []).groupedByBlock().count
        case .firewallConfig: count = model.configRules.isEmpty ? nil : model.configRules.count
        case .allowlist: count = state?.allowlist?.count
        // What the last read found. Nil until the screen has been opened once — the list is
        // never fetched on the poll, so a zero here would mean "not read yet", not "none".
        case .dnsBlocked: count = model.dnsBlocked.isEmpty ? nil : model.dnsBlocked.count
        default: count = nil
        }
        guard let count, count > 0 else { return nil }
        return "\(count)"
    }

    // MARK: - Status block
    //
    // Pinned to the foot of the rail, as on the desktop and in the console: what the monitor
    // is doing, whether the firewall can be written, and the one toggle that decides whether
    // detections turn into kernel rules.

    private var statusBox: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Status")
                .font(.system(size: 10.5, weight: .bold))
                .textCase(.uppercase)
                .tracking(1.4)
                .foregroundStyle(NSTheme.dim)

            Text(statusText)
                .font(.system(size: 12.5))
                .foregroundStyle(NSTheme.text2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)

            HStack(spacing: 8) {
                ConsoleDot(on: monitoring)
                Text(model.isAsleep ? "Asleep" : (monitoring ? "Monitoring" : "Paused"))
                    .font(.system(size: 12.5))
                    .foregroundStyle(NSTheme.text2)
            }
            .padding(.top, 10)

            if let firewallLine {
                Text(firewallLine)
                    .font(.system(size: 12.5))
                    .foregroundStyle(NSTheme.text2)
                    .lineLimit(2)
                    .padding(.top, 8)
            }

            if let autoBlock = settings?.autoBlockEnabled {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Auto-block")
                        .font(.system(size: 10.5, weight: .bold))
                        .textCase(.uppercase)
                        .tracking(1.4)
                        .foregroundStyle(NSTheme.dim)

                    HStack(spacing: 10) {
                        ConsoleSwitch(isOn: Binding(
                            get: { autoBlock },
                            set: { v in Task { await model.setAutoBlockEnabled(v) } }
                        ))
                        Text("Enable auto-block")
                            .font(.system(size: 13))
                            .foregroundStyle(NSTheme.text2)
                    }

                    Text(settings?.autoBlockSummary ?? (autoBlock
                        ? "Threats at or above \(settings?.autoBlockMinLevel ?? "High") become firewall rules."
                        : "Manual blocks only — nothing is written automatically."))
                        .font(.system(size: 11.5))
                        .foregroundStyle(NSTheme.dim)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.white.opacity(0.05), in: .rect(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(NSTheme.border, lineWidth: 1))
                .padding(.top, 12)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white.opacity(0.05), in: .rect(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(NSTheme.border, lineWidth: 1))
        .padding(.top, 16)
    }

    private var statusText: String {
        if let err = model.lastError, !err.isEmpty { return err }
        if let msg = model.state?.statusMessage, !msg.isEmpty { return msg }
        return model.state == nil ? "Connecting…" : "Connected."
    }

    /// Whether the firewall can be written, which is the rail's second line in the console.
    /// On web 0.7.10+ the server says so outright; before that the closest reading is the
    /// privilege note the scan carries.
    private var firewallLine: String? {
        if let host = model.hostFirewall {
            if host.isReadOnly { return "Firewall: read-only — rules cannot be changed" }
            if let backend = host.backend, !backend.isEmpty {
                return "Firewall: \(backend)\(host.isEnabled ? " · active" : " · inactive")"
            }
        }
        let priv = model.state?.firewall?.privilegeText ?? ""
        return priv.isEmpty ? nil : priv
    }
}
