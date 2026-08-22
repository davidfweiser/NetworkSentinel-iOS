import SwiftUI

/// **Blocked Sites** — the names the filtering resolver refused. Web 0.7.15's console page.
///
/// Every other list in this app is drawn from the state poll. This one is not, and the
/// server is explicit about why: the query log is the heaviest document AdGuard serves, and
/// the resolver behind it is what every tunnel client resolves names through. A phone
/// re-reading it every 2.5 seconds would be a load on the one service whose failure takes
/// the whole tunnel offline. So it is read when the screen opens, when the count changes,
/// and when the list is pulled — which is exactly when the web console reads it.
///
/// The list is a *name*-based block, and the note says so on the screen rather than in the
/// documentation. A client that dials a hard-coded address never asks a resolver anything,
/// so it is never refused and never appears here; reading an empty list as "nothing was
/// blocked, so nothing was attempted" is the one wrong conclusion this page invites.
///
/// The server's own sentence is the status line. "Nothing blocked yet — the log is empty, or
/// the query log is switched off in AdGuard" is a diagnosis the phone cannot make for
/// itself, and paraphrasing it would lose the half that matters.
struct DnsBlockedView: View {
    @Environment(AppModel.self) private var model

    private var entries: [DnsBlockedEntry] { model.dnsBlocked }

    var body: some View {
        List {
            controlsSection
            stateSection
            entriesSection
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Blocked Sites")
        .navigationBarTitleDisplayMode(.inline)
        .consoleRailToolbar()
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await model.loadDnsBlocked() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .accessibilityLabel("Refresh")
                .disabled(model.dnsBlockedLoading)
            }
        }
        // Read on arrival, as the console does when the view is opened. Not on every
        // appearance of a cached screen either — `task` runs when the view is created, and
        // the toolbar's Refresh is there for asking again.
        .task { await model.loadDnsBlocked() }
        .refreshable { await model.loadDnsBlocked() }
    }

    // MARK: - How many

    private var controlsSection: some View {
        Section {
            HStack {
                Text("Show")
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.text)
                Spacer(minLength: 12)
                ConsoleSelect(
                    options: AppModel.dnsBlockedLimits,
                    selection: Binding(
                        get: { model.dnsBlockedLimit },
                        set: { v in Task { await model.setDnsBlockedLimit(v) } }
                    ),
                    label: { "Last \($0)" }
                )
            }
            .listRowBackground(NSTheme.row)
        } footer: {
            Text("Names your filtering resolver refused, newest first. This is a name-based block: a client that dials a hard-coded address never asks, so it never appears here.")
        }
    }

    // MARK: - What the read did

    @ViewBuilder
    private var stateSection: some View {
        if model.dnsBlockedUnsupported {
            Section {
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("No Blocked Sites on this server")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(NSTheme.text)
                        Text("It has no \(Text("/api/dns-blocked").font(.caption.monospaced())) route, so it predates DNS filtering. The page comes from web 0.7.15 or newer, with a filtering resolver set up on that node.")
                            .font(.caption)
                            .foregroundStyle(NSTheme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } icon: {
                    Image(systemName: "questionmark.circle")
                        .foregroundStyle(NSTheme.warning)
                }
                .listRowBackground(NSTheme.row)
            }
        } else if model.dnsBlockedLoading && entries.isEmpty {
            Section {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Reading the resolver…")
                        .foregroundStyle(NSTheme.muted)
                }
                .listRowBackground(NSTheme.row)
            }
        } else if let message = model.dnsBlockedMessage, !message.isEmpty {
            Section {
                // The server's words, not a paraphrase — an unreachable resolver, refused
                // credentials and a query log switched off in AdGuard are three different
                // problems with three different fixes, and only this sentence tells them apart.
                Label(message, systemImage: model.dnsBlockedOk ? "info.circle" : "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(model.dnsBlockedOk ? NSTheme.muted : NSTheme.warning)
                    .listRowBackground(NSTheme.row)

                if !model.dnsBlockedOk {
                    Button {
                        Task { await model.loadDnsBlocked() }
                    } label: {
                        Label("Try again", systemImage: "arrow.clockwise")
                    }
                    .tint(NSTheme.accent)
                    .listRowBackground(NSTheme.row)
                }
            }
        }
    }

    // MARK: - The refusals

    @ViewBuilder
    private var entriesSection: some View {
        if !entries.isEmpty {
            Section {
                // The same name refused twice a second apart is two rows, and the resolver's
                // log carries no id to tell them apart — so identity is the whole shape,
                // disambiguated by position the way the connection list is.
                ForEach(entries.uniquedRows()) { row in
                    entryRow(row.value)
                        .listRowBackground(NSTheme.row)
                }
            } header: {
                Text("Refused")
            }
        }
    }

    private func entryRow(_ entry: DnsBlockedEntry) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(entry.domain ?? "")
                    .font(.subheadline.monospaced())
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(2)
                    .truncationMode(.middle)
                Spacer(minLength: 8)
                Text(entry.time ?? "")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(NSTheme.dim)
            }

            HStack(spacing: 8) {
                if let reason = entry.reason, !reason.isEmpty {
                    Text(reason)
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(NSTheme.warning)
                }
                // Which client asked. On a VPN gateway this is the only thing that says
                // whose traffic was refused — the forwarded flow itself has no local socket
                // and never appears anywhere else in this app.
                if let client = entry.client, !client.isEmpty {
                    Text(client)
                        .font(.caption2.monospaced())
                        .foregroundStyle(NSTheme.cyan)
                        .lineLimit(1)
                }
            }

            if let rule = entry.rule, !rule.isEmpty {
                Text(rule)
                    .font(.caption2.monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.vertical, 2)
    }
}
