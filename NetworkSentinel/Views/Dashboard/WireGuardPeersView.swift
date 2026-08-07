import SwiftUI

/// The WireGuard peer table the server publishes on web 0.6+.
///
/// Read-only, deliberately. Revoking a peer is `wg set <iface> peer <key> remove` — a
/// WireGuard configuration change, not something a monitoring console should do behind your
/// back — so this screen shows what the tunnel is doing and stops there.
///
/// Only public keys ever arrive here: the interface private key and each peer's preshared
/// key are dropped where the server parses `wg show ... dump`, so they are never stored,
/// logged, sent to a webhook, or transmitted to any client.
struct WireGuardPeersView: View {
    let peers: [WireGuardPeerInfo]
    let status: String?

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if peers.isEmpty {
                    EmptyStateView(
                        icon: "point.3.filled.connected.trianglepath.dotted",
                        title: "No peers",
                        message: status
                            ?? "This server reports no WireGuard peers. Reading device state needs root."
                    )
                } else {
                    List {
                        Section {
                            ForEach(peers) { peer in
                                peerRow(peer)
                                    .listRowBackground(NSTheme.row)
                                    .listRowSeparatorTint(NSTheme.border)
                            }
                        } footer: {
                            if let status, !status.isEmpty {
                                Text(status)
                            }
                        }
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .background { AmbientField() }
            .navigationTitle("WireGuard peers")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func peerRow(_ peer: WireGuardPeerInfo) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(peer.shortKey ?? peer.publicKey ?? "unknown key")
                    .font(.subheadline.monospaced().weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 8)
                if let iface = peer.iface, !iface.isEmpty {
                    Text(iface)
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(NSTheme.signal)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(NSTheme.signal.opacity(0.15), in: Capsule())
                }
            }

            // The endpoint is where the tunnel's packets come from, and the one field on
            // this screen the prevention engine reads: while monitoring is on it refuses to
            // auto-block any current peer's endpoint, so a detector tripping on peer
            // traffic cannot cut a client's tunnel dead.
            if let endpoint = peer.endpoint, !endpoint.isEmpty {
                Label(endpoint, systemImage: "arrow.left.arrow.right")
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.cyan)
                    .lineLimit(1)
            }

            if let allowed = peer.allowedIps, !allowed.isEmpty {
                Label(allowed, systemImage: "checkmark.shield")
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(2)
            }

            HStack(spacing: 12) {
                if let handshake = peer.handshake, !handshake.isEmpty {
                    Label(handshake, systemImage: "clock")
                        .font(.caption)
                        .foregroundStyle(NSTheme.muted)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                Text("↓ \(peer.rxMb ?? 0) MB  ↑ \(peer.txMb ?? 0) MB")
                    .font(.readout(12))
                    .foregroundStyle(NSTheme.muted)
            }
        }
        .padding(.vertical, 6)
    }
}
