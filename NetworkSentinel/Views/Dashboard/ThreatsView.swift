import SwiftUI

struct ThreatsView: View {
    @Environment(AppModel.self) private var model
    @State private var filter = ThreatFilter.all
    @State private var query = ""

    enum ThreatFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case high = "High+"
        case critical = "Critical"
        var id: String { rawValue }
    }

    private var threats: [ThreatInfo] {
        var list = model.state?.threats ?? []
        switch filter {
        case .all: break
        case .high:
            list = list.filter { ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .high }
        case .critical:
            list = list.filter { ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .critical }
        }
        if !query.isEmpty {
            let q = query.lowercased()
            list = list.filter {
                $0.title.lowercased().contains(q)
                    || $0.sourceIp.lowercased().contains(q)
                    || ($0.detail?.lowercased().contains(q) ?? false)
                    || ($0.type?.lowercased().contains(q) ?? false)
            }
        }
        return list
    }

    var body: some View {
        NavigationStack {
            Group {
                if threats.isEmpty {
                    EmptyStateView(
                        icon: "checkmark.shield",
                        title: query.isEmpty ? "All clear" : "No matches",
                        message: query.isEmpty
                            ? "No threat alerts on this server right now."
                            : "Try a different search or filter."
                    )
                } else {
                    List {
                        ForEach(threats.uniquedRows()) { row in
                            let t = row.value
                            ThreatRow(
                                threat: t,
                                onBlock: { Task { await model.requestBlock(ip: t.sourceIp) } },
                                onUnblock: { Task { await model.unblock(ip: t.sourceIp) } }
                            )
                            .listRowBackground(NSTheme.row)
                            .listRowSeparatorTint(NSTheme.border)
                        }
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .nsAsleepDimmed(model.isAsleep)
            .background { AmbientField() }
            .navigationTitle("Threats")
            .searchable(text: $query, prompt: "IP, title, type")
            // Segmented filter must not live in the nav toolbar — on a phone it
            // collapses into an unreadable circle (All/High+/Critical → "A t C").
            // The sleep banner shares the inset so it stays above the list rather than
            // landing between the filter and the rows it is warning about.
            .safeAreaInset(edge: .top, spacing: 0) {
                VStack(spacing: 8) {
                    if model.isAsleep {
                        SleepBanner { Task { await model.wakeConsole() } }
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                    Picker("Filter", selection: $filter) {
                        ForEach(ThreatFilter.allCases) { f in
                            Text(f.rawValue).tag(f)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(NSTheme.bg)
                .animation(.easeInOut(duration: 0.25), value: model.isAsleep)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await model.clearThreats() }
                    } label: {
                        Label("Clear", systemImage: "trash")
                            .labelStyle(.titleAndIcon)
                    }
                    .disabled((model.state?.threats ?? []).isEmpty)
                    .accessibilityLabel("Clear threats")
                }
            }
            .refreshable { await model.refresh(silent: false) }
        }
    }
}

struct ThreatRow: View {
    let threat: ThreatInfo
    var onBlock: () -> Void
    var onUnblock: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                SeverityBadge(level: threat.level, levelNum: threat.levelNum)
                if let type = threat.type {
                    // The 0.4 suite reports seven new types; without an icon per kind a
                    // scrolled list reads as one undifferentiated wall of alerts.
                    Label(type, systemImage: threat.icon)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(NSTheme.muted)
                        .lineLimit(1)
                }
                Spacer()
                Text(threat.time)
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.muted)
            }

            Text(threat.title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(NSTheme.text)

            if let detail = threat.detail, !detail.isEmpty {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(3)
            }

            // Web 0.6.3+: whether this address is actually being blocked. The badge says
            // what, the server's own sentence says why — the gate that stopped it, or the
            // rule already in force. Without it the row names an address and leaves the
            // reader to go and find out whether anything was done about it.
            if let verdict = threat.blockVerdict {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    BlockBadge(verdict: verdict)
                    if let status = threat.blockStatus, !status.isEmpty {
                        Text(status)
                            .font(.caption2)
                            .foregroundStyle(NSTheme.muted)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                }
            }

            HStack {
                if threat.isBlockable {
                    Label(threat.sourceIp, systemImage: "globe")
                        .font(.caption.monospaced())
                        .foregroundStyle(NSTheme.cyan)
                }
                if let origin = threat.origin, !origin.isEmpty {
                    Text(threat.isBlockable ? "· \(origin)" : origin)
                        .font(.caption)
                        .foregroundStyle(NSTheme.muted)
                        .lineLimit(1)
                }
                Spacer()
                // Host-local detections (new listener, launch item) have no peer to
                // firewall — the server rejects loopback, so the button is only an error.
                if threat.isBlockable {
                    // An address already being dropped offers the release instead, as the
                    // Hosts tab does: re-blocking it would only rewrite a rule in force.
                    if threat.blockVerdict?.isBlocked == true {
                        Button("Unblock", action: onUnblock)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(NSTheme.success)
                    } else {
                        Button("Block", action: onBlock)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(NSTheme.danger)
                    }
                }
            }
        }
        .padding(.vertical, 6)
    }
}
