import SwiftUI

/// **Help** — the console's own Help page, which its rail keeps indented under Settings.
///
/// Ported rather than rewritten: an operator who has read the console's Help should not have
/// to learn a second vocabulary on the phone. The two paragraphs that are only true of the
/// server — how to start it, which port it picks — are dropped, since nothing on a phone can
/// act on them; what stays is what each section is, what Sleep does, and the two facts that
/// look like bugs the first time you meet them (elevation, and the master password).
struct HelpView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List {
            Section {
                Text("Network Sentinel watches a machine's connections, listening ports and intrusion signals, and blocks what it decides is hostile. This app is a front-end for the same server the browser console talks to — the same monitoring and firewall stack as the desktop and TUI apps.")
                    .listRowBackground(NSTheme.row)
            }

            Section {
                helpRow("Dashboard", "Live counters, the activity and data-flow charts, and what needs attention now")
                helpRow("Live Connections", "Live traffic, with Block on the row")
                helpRow("Remote Computers", "Remote peers; block and unblock by address")
                helpRow("Break-in Attempts", "What the detectors found, newest first, each saying whether the address is blocked")
                helpRow("Open Ports", "Local listeners; block a port in one tap")
                helpRow("Firewall & Block", "Managed rules, manual IP and port blocking, remove rules")
                helpRow("Firewall Config", "Every rule the firewall evaluates — UFW's, Docker's and this app's — with add, edit and delete")
                helpRow("Allowlist", "Domains and IPs that are never blocked")
                helpRow("Settings", "Which server this is, how it alerts this device, the server's webhook and remote access")
            } header: {
                Text("Sections")
            }

            Section {
                Text("The first control on Dashboard stops every watcher on the server — connections, listening ports, auth log, port-scan probes, ARP, startup items, exfiltration, honeypot — and parks the console. Press it again to wake and start monitoring from live data.")
                    .listRowBackground(NSTheme.row)
                Text("Firewall blocks stay in force while asleep: sleeping stops watching, it does not unblock anything. Sleep applies to the web service; a desktop or TUI instance is a separate process and keeps running.")
                    .listRowBackground(NSTheme.row)
            } header: {
                Text("Sleep / Wake")
            }

            Section {
                Text("Firewall actions need root or an elevation helper (pkexec or sudo) on the server. Prefer running the web service as root once rather than elevating per action — under systemd pkexec cannot work at all, since it needs a graphical session the unit does not have.")
                    .listRowBackground(NSTheme.row)
                if let privilege = model.state?.firewall?.privilegeText, !privilege.isEmpty {
                    Text(privilege)
                        .foregroundStyle(NSTheme.warning)
                        .listRowBackground(NSTheme.row)
                }
            } header: {
                Text("Elevation")
            }

            Section {
                Text("Access is gated by a master password, set on first visit and changeable under Settings. The server stores it only as a salted one-way hash. Signing out requires it again; this app can keep it in the Keychain so background polling can sign in on its own.")
                    .listRowBackground(NSTheme.row)
            } header: {
                Text("Master password")
            }
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Help")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func helpRow(_ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(NSTheme.text)
            Text(detail)
                .font(.caption)
                .foregroundStyle(NSTheme.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .listRowBackground(NSTheme.row)
    }
}
