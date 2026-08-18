import SwiftUI
import UIKit

struct HostsView: View {
    @Environment(AppModel.self) private var model
    /// Set when this list is one half of the Traffic tab; nil when it stands alone.
    var mode: Binding<TrafficMode>?
    @State private var query = ""
    @State private var showBlockedOnly = false
    @State private var confirmBlock: HostInfo?
    @State private var confirmUnblock: HostInfo?

    private var hosts: [HostInfo] {
        var list = model.state?.hosts ?? []
        if showBlockedOnly {
            list = list.filter { $0.blocked == true }
        }
        if !query.isEmpty {
            let q = query.lowercased()
            list = list.filter {
                $0.ip.lowercased().contains(q)
                    || ($0.name?.lowercased().contains(q) ?? false)
                    || ($0.hostName?.lowercased().contains(q) ?? false)
                    || ($0.geo?.lowercased().contains(q) ?? false)
                    || ($0.threat?.lowercased().contains(q) ?? false)
            }
        }
        return list.sorted { ($0.active ?? 0) > ($1.active ?? 0) }
    }

    var body: some View {
        NavigationStack {
            Group {
                if hosts.isEmpty {
                    EmptyStateView(
                        icon: "network.slash",
                        title: "No hosts",
                        message: "Remote peers will appear here as traffic is observed."
                    )
                } else {
                    List {
                        ForEach(hosts) { h in
                            HostRow(host: h)
                                .listRowBackground(NSTheme.row)
                                .listRowSeparatorTint(NSTheme.border)
                                .swipeActions(edge: .trailing) {
                                    if h.blocked == true {
                                        Button {
                                            confirmUnblock = h
                                        } label: {
                                            Label("Unblock", systemImage: "lock.open")
                                        }
                                        .tint(NSTheme.success)
                                    } else {
                                        Button(role: .destructive) {
                                            confirmBlock = h
                                        } label: {
                                            Label("Block", systemImage: "hand.raised.fill")
                                        }
                                    }
                                }
                                .contextMenu {
                                    if h.blocked == true {
                                        Button("Unblock \(h.ip)") {
                                            Task { await model.unblock(ip: h.ip) }
                                        }
                                    } else {
                                        Button("Block \(h.ip)", role: .destructive) {
                                            Task { await model.requestBlock(ip: h.ip) }
                                        }
                                    }
                                    Button("Copy IP") {
                                        UIPasteboard.general.string = h.ip
                                    }
                                }
                        }
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .nsSleepAware(model.isAsleep) { Task { await model.wakeConsole() } }
            .background { AmbientField() }
            .navigationTitle("Remote Computers")
            .navigationBarTitleDisplayMode(mode == nil ? .automatic : .inline)
            .searchable(text: $query, prompt: "IP, name, geo")
            .toolbar {
                if let mode {
                    ToolbarItem(placement: .principal) {
                        TrafficModePicker(mode: mode)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Toggle(isOn: $showBlockedOnly) {
                        Image(systemName: showBlockedOnly ? "hand.raised.fill" : "hand.raised")
                    }
                    .toggleStyle(.button)
                    .tint(showBlockedOnly ? NSTheme.danger : NSTheme.muted)
                }
            }
            .refreshable { await model.refresh(silent: false) }
            .confirmationDialog("Block this IP?", isPresented: Binding(
                get: { confirmBlock != nil },
                set: { if !$0 { confirmBlock = nil } }
            ), titleVisibility: .visible) {
                if let h = confirmBlock {
                    Button("Block \(h.ip)", role: .destructive) {
                        Task { await model.requestBlock(ip: h.ip) }
                        confirmBlock = nil
                    }
                    Button("Cancel", role: .cancel) { confirmBlock = nil }
                }
            } message: {
                Text("Creates a Network Sentinel firewall rule on the remote host.")
            }
            .confirmationDialog("Unblock this IP?", isPresented: Binding(
                get: { confirmUnblock != nil },
                set: { if !$0 { confirmUnblock = nil } }
            ), titleVisibility: .visible) {
                if let h = confirmUnblock {
                    Button("Unblock \(h.ip)") {
                        Task { await model.unblock(ip: h.ip) }
                        confirmUnblock = nil
                    }
                    Button("Cancel", role: .cancel) { confirmUnblock = nil }
                }
            }
        }
    }
}

struct HostRow: View {
    let host: HostInfo

    private var severity: ThreatSeverity {
        ThreatSeverity.from(level: host.threat, levelNum: host.threatLevel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(host.name ?? host.ip)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)
                Spacer()
                if host.blocked == true {
                    Text("BLOCKED")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(NSTheme.danger)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(NSTheme.danger.opacity(0.15), in: Capsule())
                }
            }

            HStack(spacing: 8) {
                Text(host.ip)
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.cyan)
                if let geo = host.geo, !geo.isEmpty {
                    Text("· \(geo)")
                        .font(.caption)
                        .foregroundStyle(NSTheme.muted)
                        .lineLimit(1)
                }
            }

            HStack(spacing: 14) {
                metric(icon: "bolt.fill", text: "\(host.active ?? 0) active")
                metric(icon: "sum", text: "\(host.total ?? 0) total")
                metric(icon: "door.left.hand.open", text: "\(host.ports ?? 0) ports")
                Spacer()
                if let threat = host.threat, !threat.isEmpty, severity > .none {
                    Text(threat)
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(severity.color)
                }
            }

            if let last = host.lastSeen {
                Text("Last seen \(last)")
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
            }
        }
        .padding(.vertical, 6)
    }

    private func metric(icon: String, text: String) -> some View {
        Label(text, systemImage: icon)
            .font(.caption2)
            .foregroundStyle(NSTheme.muted)
            .labelStyle(.titleAndIcon)
    }
}
