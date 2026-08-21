import SwiftUI

struct ConnectionsView: View {
    @Environment(AppModel.self) private var model
    /// Set when this list is one half of the Traffic tab; nil when it stands alone.
    var mode: Binding<TrafficMode>?
    @State private var query = ""

    private var connections: [ConnectionInfo] {
        var list = model.state?.connections ?? []
        if !query.isEmpty {
            let q = query.lowercased()
            list = list.filter {
                $0.local.lowercased().contains(q)
                    || $0.remote.lowercased().contains(q)
                    || ($0.process?.lowercased().contains(q) ?? false)
                    || ($0.state?.lowercased().contains(q) ?? false)
                    || ($0.geo?.lowercased().contains(q) ?? false)
                    || $0.protocolName.lowercased().contains(q)
            }
        }
        return list
    }

    var body: some View {
        NavigationStack {
            Group {
                if connections.isEmpty {
                    EmptyStateView(
                        icon: "arrow.left.arrow.right",
                        title: "No connections",
                        message: "Active TCP/UDP sessions will show up here."
                    )
                } else {
                    List {
                        ForEach(connections.uniquedRows()) { row in
                            let c = row.value
                            ConnectionRow(connection: c) {
                                if let ip = c.remoteAddress, !ip.isEmpty {
                                    Task { await model.requestBlock(ip: ip) }
                                }
                            }
                            .listRowBackground(NSTheme.row)
                            .listRowSeparatorTint(NSTheme.border)
                        }
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .nsSleepAware(model.isAsleep) { Task { await model.wakeConsole() } }
            .background { AmbientField() }
            .navigationTitle("Live Connections")
            .consoleRailToolbar()
            .navigationBarTitleDisplayMode(mode == nil ? .automatic : .inline)
            .searchable(text: $query, prompt: "Process, IP, state")
            .toolbar {
                if let mode {
                    ToolbarItem(placement: .principal) {
                        TrafficModePicker(mode: mode)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Text("\(connections.count)")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(NSTheme.muted)
                }
            }
            .refreshable { await model.refresh(silent: false) }
        }
    }
}

struct ConnectionRow: View {
    let connection: ConnectionInfo
    var onBlock: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(connection.protocolName.uppercased())
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(NSTheme.accent)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(NSTheme.accentSoft, in: RoundedRectangle(cornerRadius: 4))

                Text(connection.process ?? "unknown")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)

                if let pid = connection.pid {
                    Text("pid \(pid)")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                }

                Spacer()

                if let state = connection.state {
                    Text(state)
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(stateColor(state))
                }
            }

            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Local")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                    Text(connection.local)
                        .font(.caption.monospaced())
                        .foregroundStyle(NSTheme.text)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                }
                Spacer(minLength: 8)
                Image(systemName: "arrow.right")
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
                    .padding(.top, 14)
                Spacer(minLength: 8)
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Remote")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                    Text(connection.remote)
                        .font(.caption.monospaced())
                        .foregroundStyle(NSTheme.cyan)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                }
            }

            HStack {
                if let geo = connection.geo, !geo.isEmpty {
                    Text(geo)
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                        .lineLimit(1)
                }
                Spacer()
                if let last = connection.lastSeen {
                    Text(last)
                        .font(.caption2.monospaced())
                        .foregroundStyle(NSTheme.muted)
                }
                if let ip = connection.remoteAddress, IPScope.of(ip).isBlockable {
                    Button("Block", action: onBlock)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(NSTheme.danger)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func stateColor(_ state: String) -> Color {
        switch state.uppercased() {
        case "ESTABLISHED": return NSTheme.success
        case "LISTEN": return NSTheme.accent
        case "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2": return NSTheme.warning
        default: return NSTheme.muted
        }
    }
}
