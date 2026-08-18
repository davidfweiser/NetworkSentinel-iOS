import SwiftUI

/// **Firewall & Block** — the console's own section, with the same pages under it.
///
/// The web console's navigation rail carries *Firewall & Block* with *Firewall Config* and
/// *Allowlist* indented beneath it and *Open Ports* immediately above; the desktop's menu is
/// the same shape. On the phone those four were scattered, three of them inside More next to
/// the webhook URL and this app's own notification settings — which is where a setting goes,
/// not where the firewall goes.
///
/// This screen is that group. It carries what the console's Firewall & Block page carries —
/// the blocks this app and the prevention engine minted, one row per block, manual IP
/// blocking, the elevation prompt, Remove all — and holds the three pages that sit under it.
///
/// It is deliberately not the same list as Firewall Config. That one is every rule the kernel
/// evaluates, whoever wrote it; this one is the set you act on during an incident. Folding
/// them together is what would hide a permissive rule sitting above a block.
struct FirewallBlockView: View {
    @Environment(AppModel.self) private var model

    @State private var showBlockIP = false
    @State private var blockIPText = ""
    @State private var pendingRuleRemoval: FirewallRuleGroup?
    @State private var confirmRemoveAll = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink {
                        FirewallConfigView()
                    } label: {
                        navRow("Firewall Config", "shield.lefthalf.filled",
                               count: model.state?.configRules?.count)
                    }
                    .listRowBackground(NSTheme.row)
                    .disabled(model.state?.configRules == nil)

                    NavigationLink {
                        OpenPortsView()
                    } label: {
                        navRow("Open Ports", "point.3.filled.connected.trianglepath.dotted",
                               count: model.state?.ports?.count)
                    }
                    .listRowBackground(NSTheme.row)

                    NavigationLink {
                        AllowlistView()
                    } label: {
                        navRow("Allowlist", "checkmark.shield",
                               count: model.state?.allowlist?.count)
                    }
                    .listRowBackground(NSTheme.row)
                } footer: {
                    Text("Firewall Config is every rule the firewall evaluates, in evaluation order, with the listening sockets under it — on web 0.7+ servers only. Open Ports is what this machine is listening on, one tap from a block. The allowlist is never auto-blocked.")
                }

                firewallRulesSection
            }
            .scrollContentBackground(.hidden)
            .background { AmbientField() }
            .navigationTitle("Firewall & Block")
            .alert("Block an IP", isPresented: $showBlockIP) {
                TextField("IP address", text: $blockIPText)
                    .keyboardType(.numbersAndPunctuation)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Block", role: .destructive) {
                    let ip = blockIPText.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !ip.isEmpty else { return }
                    Task {
                        await model.requestBlock(ip: ip)
                        blockIPText = ""
                    }
                }
                Button("Cancel", role: .cancel) { blockIPText = "" }
            } message: {
                Text("Writes an inbound and outbound block rule on the server, the same as the web console’s Block IP.")
            }
            .confirmationDialog(
                "Remove all Network Sentinel firewall rules?",
                isPresented: $confirmRemoveAll,
                titleVisibility: .visible
            ) {
                Button("Remove all", role: .destructive) {
                    Task { await model.removeAllRules() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Deletes managed IP/port rules. The web console’s protected allow rule is left alone when possible.")
            }
            .confirmationDialog(
                "Remove this firewall rule?",
                isPresented: Binding(
                    get: { pendingRuleRemoval != nil },
                    set: { if !$0 { pendingRuleRemoval = nil } }
                ),
                titleVisibility: .visible
            ) {
                if let group = pendingRuleRemoval {
                    Button("Remove \(group.primary.displayAddress)", role: .destructive) {
                        Task { await model.removeRule(named: group.primary.name) }
                        pendingRuleRemoval = nil
                    }
                    Button("Cancel", role: .cancel) { pendingRuleRemoval = nil }
                }
            } message: {
                Text("Lifts the block: the server deletes the inbound and outbound rules together and holds auto-block off this target for 24 hours.")
            }
            .refreshable { await model.refresh(silent: false) }
        }
    }

    /// One row of the group, with what it holds — the count is the reading that says whether
    /// opening it is worth the tap.
    private func navRow(_ title: String, _ symbol: String, count: Int?) -> some View {
        HStack {
            Label(title, systemImage: symbol)
            Spacer(minLength: 8)
            if let count {
                Text("\(count)")
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.muted)
            }
        }
    }

    @ViewBuilder
    private var firewallRulesSection: some View {
        Section {
            // Blocks are written as an -In/-Out pair, so the raw list shows each one twice
            // and removing either half clears both. Group them the way the web console does.
            let groups = (model.state?.firewallRules ?? []).groupedByBlock()
            if groups.isEmpty {
                Text("No managed firewall rules")
                    .foregroundStyle(NSTheme.muted)
                    .listRowBackground(NSTheme.row)
            } else {
                ForEach(groups) { group in
                    firewallRuleRow(group)
                }
            }

            Button {
                blockIPText = ""
                showBlockIP = true
            } label: {
                Label("Block IP…", systemImage: "plus.circle")
            }
            .listRowBackground(NSTheme.row)

            Button {
                Task { await model.authorizeFirewall() }
            } label: {
                Label("Authorize firewall", systemImage: "lock.open")
            }
            .listRowBackground(NSTheme.row)

            Button(role: .destructive) {
                confirmRemoveAll = true
            } label: {
                Label("Remove all managed rules", systemImage: "trash")
            }
            .listRowBackground(NSTheme.row)
        } header: {
            Text("Firewall rules")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("Each row is one block. Remove deletes its inbound and outbound rules together and keeps auto-block from putting the same target back for 24 hours.")
                if let priv = model.state?.firewall?.privilegeText {
                    Text(priv)
                }
            }
        }
    }

    @ViewBuilder
    private func firewallRuleRow(_ group: FirewallRuleGroup) -> some View {
        let rule = group.primary
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(rule.displayAddress)
                    .font(.subheadline.monospaced().weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)
                Spacer(minLength: 8)
                if group.isProtected {
                    ruleChip("PROTECTED", color: NSTheme.warning)
                }
                Text(rule.action ?? "Block")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(NSTheme.danger)
            }

            if rule.target != rule.displayAddress {
                Text(rule.target)
                    .font(.caption2.monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
            }

            // Directions come from the pair, so a block missing its outbound half is
            // visible here instead of silently reading as fully blocked.
            HStack(spacing: 6) {
                ForEach(Array(group.directions.enumerated()), id: \.offset) { _, direction in
                    ruleChip(direction, color: NSTheme.accent)
                }
                ruleChip(group.isEnabled ? "On" : "Off",
                         color: group.isEnabled ? NSTheme.success : NSTheme.muted)
                Text(
                    [rule.kind, rule.protocolName, rule.ports]
                        .compactMap { $0 }
                        .filter { !$0.isEmpty && $0 != "Any" }
                        .joined(separator: " · ")
                )
                .font(.caption)
                .foregroundStyle(NSTheme.muted)
                .lineLimit(1)
            }

            if let detail = rule.description, !detail.isEmpty {
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(2)
            }

            HStack {
                Text(group.id)
                    .font(.system(size: 10).monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(1)
                Spacer(minLength: 8)
                if group.isProtected {
                    // Removing this one from here would cut the app off from the console.
                    Text("this console")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                } else {
                    Button("Remove") { pendingRuleRemoval = group }
                        .font(.caption.weight(.bold))
                        .foregroundStyle(NSTheme.success)
                        .buttonStyle(.borderless)
                }
            }
        }
        .listRowBackground(NSTheme.row)
        .swipeActions(edge: .trailing, allowsFullSwipe: !group.isProtected) {
            if !group.isProtected {
                Button(role: .destructive) {
                    pendingRuleRemoval = group
                } label: {
                    Label("Remove", systemImage: "trash")
                }
            }
        }
    }

    private func ruleChip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
    }
}

/// **Open Ports** — the console page of that name: what this machine is listening on, with a
/// block one tap away. It was More's "Ports" section; the console keeps it in the firewall
/// group, because a listening port is something you decide about rather than a setting.
struct OpenPortsView: View {
    @Environment(AppModel.self) private var model

    @State private var showBlockPort = false
    @State private var blockPortText = ""

    var body: some View {
        List {
                Section {
                    if let ports = model.state?.ports, !ports.isEmpty {
                        let blockedPorts = (model.state?.firewallRules ?? []).blockedPortKeys()
                        ForEach(ports.uniquedRows()) { row in
                            let p = row.value
                            let proto = p.protocolName.uppercased()
                            let isBlocked = blockedPorts.contains("\(proto)/\(p.port)")
                            HStack {
                                Text(proto)
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(NSTheme.accent)
                                    .frame(width: 36, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(p.endpoint ?? ":\(p.port)")
                                        .font(.subheadline.monospaced())
                                        .foregroundStyle(NSTheme.text)
                                    Text([p.process, p.hint].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · "))
                                        .font(.caption)
                                        .foregroundStyle(NSTheme.muted)
                                        .lineLimit(1)
                                }
                                Spacer(minLength: 8)
                                // A port already carrying a managed rule needs the opposite
                                // button: Block there did nothing but re-write the same rule.
                                if isBlocked {
                                    Text("BLOCKED")
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundStyle(NSTheme.danger)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(NSTheme.danger.opacity(0.15), in: Capsule())
                                    Button("Unblock") {
                                        Task { await model.unblockPort(p.port, protocol: proto) }
                                    }
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(NSTheme.success)
                                } else {
                                    Button("Block") {
                                        Task {
                                            await model.blockPort(
                                                p.port,
                                                protocol: proto,
                                                direction: "Inbound"
                                            )
                                        }
                                    }
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(NSTheme.danger)
                                }
                            }
                            .listRowBackground(NSTheme.row)
                            .swipeActions {
                                if isBlocked {
                                    Button {
                                        Task { await model.unblockPort(p.port, protocol: proto) }
                                    } label: {
                                        Label("Unblock port", systemImage: "lock.open")
                                    }
                                    .tint(NSTheme.success)
                                } else {
                                    Button {
                                        Task {
                                            await model.blockPort(
                                                p.port,
                                                protocol: proto,
                                                direction: "Inbound"
                                            )
                                        }
                                    } label: {
                                        Label("Block port", systemImage: "hand.raised.fill")
                                    }
                                    .tint(NSTheme.danger)
                                }
                            }
                        }
                    } else {
                        Text("No listeners")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.row)
                    }

                    Button {
                        blockPortText = ""
                        showBlockPort = true
                    } label: {
                        Label("Block port…", systemImage: "plus.circle")
                    }
                    .listRowBackground(NSTheme.row)
                } footer: {
                    Text("Block port uses the web 0.3+ API. Do not block the console’s own listen port. A blocked port that has stopped listening drops off this list — lift it under Firewall rules.")
                }
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Open Ports")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Block port", isPresented: $showBlockPort) {
            TextField("Port number", text: $blockPortText)
                .keyboardType(.numberPad)
            Button("Block TCP inbound") {
                submitBlockPort(proto: "TCP", direction: "Inbound")
            }
            Button("Block UDP inbound") {
                submitBlockPort(proto: "UDP", direction: "Inbound")
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enter a port 1–65535. Do not block the web console port.")
        }
        .refreshable { await model.refresh(silent: false) }
    }

    private func submitBlockPort(proto: String, direction: String) {
        let trimmed = blockPortText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(trimmed), (1...65535).contains(port) else {
            model.lastError = "Enter a valid port (1–65535)."
            return
        }
        Task { await model.blockPort(port, protocol: proto, direction: direction) }
    }
}

/// **Allowlist** — domains and IPs the engine never blocks, as its own page under Firewall &
/// Block, which is where the console's rail puts it.
struct AllowlistView: View {
    @Environment(AppModel.self) private var model

    @State private var allowlistValue = ""
    @State private var showAddAllowlist = false

    var body: some View {
        List {
                Section {
                    if let entries = model.state?.allowlist, !entries.isEmpty {
                        ForEach(entries.uniquedRows()) { row in
                            let e = row.value
                            HStack {
                                Text(e.kind)
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(NSTheme.success)
                                    .frame(width: 56, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(e.value)
                                        .font(.subheadline.monospaced())
                                        .foregroundStyle(NSTheme.text)
                                    if let d = e.detail, !d.isEmpty {
                                        Text(d)
                                            .font(.caption2)
                                            .foregroundStyle(NSTheme.muted)
                                            .lineLimit(1)
                                    }
                                }
                            }
                            .listRowBackground(NSTheme.row)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    Task { await model.removeAllowlist(e.value, kind: e.kind) }
                                } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                            }
                        }
                    } else {
                        Text("Allowlist empty")
                            .foregroundStyle(NSTheme.muted)
                            .listRowBackground(NSTheme.row)
                    }

                    Button {
                        showAddAllowlist = true
                    } label: {
                        Label("Add domain or IP", systemImage: "plus.circle")
                    }
                    .listRowBackground(NSTheme.row)

                    Button {
                        Task { await model.refreshAllowlist() }
                    } label: {
                        Label("Refresh allowlist", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .listRowBackground(NSTheme.row)

                    Button {
                        Task { await model.restoreAllowlisted() }
                    } label: {
                        Label("Restore good sites", systemImage: "arrow.uturn.backward.circle")
                    }
                    .listRowBackground(NSTheme.row)
                } header: {
                    Text("Allowlist")
                } footer: {
                    if let s = model.state?.allowlistStatus {
                        Text(s)
                    }
                }
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Allowlist")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Add to allowlist", isPresented: $showAddAllowlist) {
            TextField("domain or IP", text: $allowlistValue)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Add") {
                let v = allowlistValue.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !v.isEmpty else { return }
                Task {
                    await model.addAllowlist(v)
                    allowlistValue = ""
                }
            }
            Button("Cancel", role: .cancel) { allowlistValue = "" }
        } message: {
            Text("Trusted domains/IPs are never auto-blocked.")
        }
        .refreshable { await model.refresh(silent: false) }
    }
}
