import SwiftUI

/// The host firewall — web 0.7's Firewall Config tab, as 0.7.4 rewrote it.
///
/// This is not the same list as More's *Firewall rules*, and the difference is the point.
/// That one is the blocks this app and the prevention engine minted, which is the set you act
/// on during an incident. This one is *the firewall*: on web 0.7.4 the server reads
/// `ufw status verbose`, `nft -j list ruleset`, `iptables -S` and `ss -tulpnH` and folds UFW's
/// rules, WireGuard's, Docker's and this app's into a single list. One machine has one
/// firewall, and before 0.7.4 both front-ends showed a fraction of it and called it the whole.
///
/// Order within a direction is never re-sorted — not by name, not by action, not to put the
/// editable rules together. The server sends evaluation order and evaluation order is the
/// reading: a permissive rule sitting above a block is the misconfiguration this screen exists
/// to make visible. Inbound and Outbound are separated because they are separate chains, which
/// is how the server sends them and how the web console has always shown them.
///
/// The listeners at the bottom are the other half of the same question. A rule list says what
/// the firewall would do; a listener list says what is actually accepting connections. Neither
/// alone tells you whether a port is reachable.
struct FirewallConfigView: View {
    @Environment(AppModel.self) private var model

    @State private var editing: EditorTarget?
    @State private var pendingRemoval: ConfigRuleInfo?
    @State private var rescanning = false
    /// Set when a listening row has nothing to prefill. Both other front-ends answer the same
    /// tap with a sentence rather than an editor full of an unparseable port.
    @State private var prefillRefusal: String?

    /// What the editor sheet was opened for. `rule` is nil when adding.
    struct EditorTarget: Identifiable {
        let rule: ConfigRuleInfo?
        /// Values the sheet opens on instead of a rule's — a rule seeded from a listening
        /// socket, which has no rule behind it to edit.
        var prefill: FirewallRuleDraft?
        /// Why those values are already in the fields, said on the sheet that has them.
        var seedNote: String?
        /// The rule's own identity, which on 0.7.4 is its shape rather than its name — two
        /// UFW rules can share a name, and opening the editor on the wrong one of them would
        /// silently rewrite the other. A seeded add is identified by what seeded it, so
        /// tapping a second listener re-opens the sheet on that socket rather than the first.
        var id: String {
            rule?.id ?? "new|\(prefill?.direction.rawValue ?? "")|\(prefill?.protocolName ?? "")|\(prefill?.ports ?? "")"
        }
    }

    // Whichever place this server keeps the scan: in the poll, or on `/api/hostfirewall`
    // because reading it costs seconds. The screen does not care which; the model resolves it.
    private var rules: [ConfigRuleInfo] { model.configRules }
    private var inbound: [ConfigRuleInfo] { rules.filter { $0.inbound ?? true } }
    private var outbound: [ConfigRuleInfo] { rules.filter { !($0.inbound ?? true) } }
    private var listeners: [HostListener] { model.hostListeners }
    /// Absent on web 0.7.0–0.7.3, where `configRules` is this app's ledger and there is no
    /// host-wide reading to report.
    private var host: HostFirewallInfo? { model.hostFirewall }

    var body: some View {
        // The Firewall tab opens here — on the firewall itself, not on the ledger of blocks
        // above it. The console's rail indents this page under Firewall & Block; a phone has
        // one tab for the group, and the whole host firewall is what that tab should open on.
        // The rest of the group is one tap away at the top of the list. The stack belongs to
        // the tab, so neither this screen nor the ones it pushes carries one.
        List {
            groupSection
            scanStateSection
            hostSection
            rulesSection("Inbound", inbound)
            rulesSection("Outbound", outbound)
            listenersSection
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Firewall Config")
        // A server that keeps the scan off /api/state is read here rather than on the poll —
        // netsh takes seconds, which is why that build moved it in the first place.
        .task { await model.ensureHostFirewall() }
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                // Two entry points, not one: the direction is the first thing a rule is, and
                // both other front-ends ask for it before the form opens rather than inside it.
                Menu {
                    Button("Add an Inbound Rule") { addRule(.inbound) }
                    Button("Add an Outbound Rule") { addRule(.outbound) }
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add rule")
            }
        }
        .sheet(item: $editing) { target in
            FirewallRuleEditor(rule: target.rule, prefill: target.prefill, seedNote: target.seedNote)
                .preferredColorScheme(.dark)
        }
        .confirmationDialog(
            // The label is itself optional, so coalescing it against the name directly
            // would flatten a present-but-nil label into the fallback and drop the name.
            "Remove \(pendingRemoval.map { $0.label ?? $0.name } ?? "rule")?",
            isPresented: Binding(
                get: { pendingRemoval != nil },
                set: { if !$0 { pendingRemoval = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let rule = pendingRemoval {
                    Task { await remove(rule) }
                }
                pendingRemoval = nil
            }
            Button("Cancel", role: .cancel) { pendingRemoval = nil }
        } message: {
            Text(pendingRemoval.map(removalWarning) ?? "")
        }
        .alert(
            "Nothing to prefill",
            isPresented: Binding(
                get: { prefillRefusal != nil },
                set: { if !$0 { prefillRefusal = nil } }
            )
        ) {
            Button("OK", role: .cancel) { prefillRefusal = nil }
        } message: {
            Text(prefillRefusal ?? "")
        }
        .refreshable {
            await model.refresh(silent: false)
            // Where the scan has its own endpoint the poll does not carry it, so a pull that
            // only re-read /api/state would leave this screen showing the same list forever.
            // Without the rescan flag the server answers from its cache — Rescan is the one
            // that makes it shell out to netsh again.
            if model.hostScan != nil { await model.loadHostFirewall() }
        }
    }

    /// What the scan is doing, when it is not simply there.
    ///
    /// Three states worth saying out loud: still reading (a Windows host with thousands of
    /// rules genuinely takes seconds), could not be read, and this server has no such page at
    /// all. The last one used to be silent — the tab quietly showed a different screen, which
    /// reads as the app having lost a feature rather than the server not having it.
    @ViewBuilder
    private var scanStateSection: some View {
        if model.hostScanLoading && rules.isEmpty {
            Section {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Reading the host firewall…")
                        .foregroundStyle(NSTheme.muted)
                }
                .listRowBackground(NSTheme.row)
            } footer: {
                Text("This server reads its firewall on request rather than on every poll, because the read takes seconds on a host carrying a few thousand rules.")
            }
        } else if let error = model.hostScanError, rules.isEmpty {
            Section {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(NSTheme.warning)
                    .listRowBackground(NSTheme.row)
                Button {
                    Task { await model.loadHostFirewall() }
                } label: {
                    Label("Try again", systemImage: "arrow.clockwise")
                }
                .tint(NSTheme.accent)
                .listRowBackground(NSTheme.row)
            }
        } else if !model.hasFirewallConfig && !model.hostScanLoading {
            Section {
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("No Firewall Config on this server")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(NSTheme.text)
                        Text("It sends no rule list in \(model.state?.version.map { "version \($0)" } ?? "its state") and has no separate scan endpoint. The page comes from Linux and macOS servers on web 0.7 or newer, and from a Windows server on 0.7.4 or newer. Firewall & Block above still works.")
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
        }
    }

    /// The rest of the console's firewall group. Rows rather than a toolbar menu, because
    /// every other way into a screen in this app is a row, and at the top rather than the
    /// bottom because a list with thirty rules and thirty sockets under them has no reachable
    /// bottom.
    private var groupSection: some View {
        Section {
            NavigationLink {
                FirewallBlockView()
            } label: {
                groupRow("Firewall & Block", "hand.raised.fill",
                         count: (model.state?.firewallRules ?? []).groupedByBlock().count)
            }
            .listRowBackground(NSTheme.row)

            NavigationLink {
                OpenPortsView()
            } label: {
                groupRow("Open Ports", "point.3.filled.connected.trianglepath.dotted",
                         count: model.state?.ports?.count)
            }
            .listRowBackground(NSTheme.row)

            NavigationLink {
                AllowlistView()
            } label: {
                groupRow("Allowlist", "checkmark.shield",
                         count: model.state?.allowlist?.count)
            }
            .listRowBackground(NSTheme.row)
        } footer: {
            Text("Firewall & Block is the blocks this app and the engine minted — the set you act on during an incident — with manual blocking and Remove all. This page is every rule the firewall evaluates, whoever wrote it.")
        }
    }

    private func groupRow(_ title: String, _ symbol: String, count: Int?) -> some View {
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

    // MARK: - The firewall itself

    /// What the scan found the machine to be. Read this before the rules: an Allow rule means
    /// something different under a default of Drop than under a default of Accept, and a short
    /// list on an unprivileged server is a privilege problem rather than an empty firewall.
    @ViewBuilder
    private var hostSection: some View {
        if let host {
            Section {
                HStack(spacing: 8) {
                    Circle()
                        .fill(host.isEnabled ? NSTheme.success : NSTheme.warning)
                        .frame(width: 8, height: 8)
                    Text(host.headline)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(NSTheme.text)
                    Spacer(minLength: 0)
                }
                .listRowBackground(NSTheme.row)

                // "(12 from Network Sentinel, 30 from the rest of the host)" — the sentence
                // the console and the desktop both carry, and the one that says at a glance
                // how much of this firewall this app is responsible for.
                Text(ownershipSummary)
                    .font(.caption)
                    .foregroundStyle(NSTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                    .listRowBackground(NSTheme.row)

                LabeledContent {
                    Text(host.defaultInbound ?? "?")
                        .font(.caption.monospaced())
                        .foregroundStyle(host.dropsInboundByDefault ? NSTheme.success : NSTheme.warning)
                } label: {
                    Text("Default inbound").foregroundStyle(NSTheme.text)
                }
                .listRowBackground(NSTheme.row)

                LabeledContent {
                    Text(host.defaultOutbound ?? "?")
                        .font(.caption.monospaced())
                        .foregroundStyle(NSTheme.muted)
                } label: {
                    Text("Default outbound").foregroundStyle(NSTheme.text)
                }
                .listRowBackground(NSTheme.row)

                Button {
                    Task { await rescan() }
                } label: {
                    HStack {
                        Label(rescanning ? "Rescanning…" : "Rescan firewall",
                              systemImage: "arrow.clockwise")
                        Spacer(minLength: 0)
                        if let at = host.scannedAt, !at.isEmpty, !rescanning {
                            Text(at)
                                .font(.caption.monospaced())
                                .foregroundStyle(NSTheme.muted)
                        }
                    }
                }
                .disabled(rescanning)
                .tint(NSTheme.accent)
                .listRowBackground(NSTheme.row)
            } header: {
                Text("Host firewall")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    // What the scan actually read, in the server's words — the sentence the
                    // payload has always carried and this screen used to drop on the floor.
                    if let description = host.description, !description.isEmpty {
                        Text(description)
                    }
                    Text(defaultPolicySentence(host))
                    // The scan is cached on the server so the 2.5s poll does not shell out to
                    // ufw and nft four times a second. Pulling to refresh re-reads state, not
                    // the kernel — Rescan is the one that does.
                    Text("Pull to refresh re-reads the server's cached scan. Rescan re-reads the kernel.")
                    if let note = host.privilegeNote, !note.isEmpty {
                        Text(note).foregroundStyle(NSTheme.warning)
                    }
                    if let errors = host.errors, !errors.isEmpty {
                        ForEach(errors, id: \.self) { Text($0).foregroundStyle(NSTheme.danger) }
                    }
                    if let seen = host.backendsSeen, seen.count > 1 {
                        // Rules under a backend that is not the active one still exist; they
                        // are just not what decides the traffic.
                        Text("Also present: \(seen.joined(separator: ", ")).")
                    }
                }
            }
        }
    }

    /// The one sentence that changes how every Allow row below should be read.
    private func defaultPolicySentence(_ host: HostFirewallInfo) -> String {
        let policy = "Default policy: \(host.defaultInbound ?? "?") inbound, \(host.defaultOutbound ?? "?") outbound. "
        let meaning = host.dropsInboundByDefault
            ? "Inbound traffic no rule matches is dropped, so a service is reachable only if a rule admits it. "
            : "Inbound traffic no rule matches is accepted, so an Allow rule opens a path through the rules above it rather than granting access on its own. "
        return policy + meaning + "Rules match in order, first match wins."
    }

    // MARK: - Rules

    @ViewBuilder
    private func rulesSection(_ title: String, _ list: [ConfigRuleInfo]) -> some View {
        Section {
            if list.isEmpty {
                Text("No \(title.lowercased()) rules")
                    .foregroundStyle(NSTheme.muted)
                    .listRowBackground(NSTheme.row)
            } else {
                // A rule's key is its shape, and the Windows Firewall holds the same shape
                // once per profile — so several rows can carry one key. Identity for the list
                // has to survive that; the key itself still goes to the server untouched,
                // where an ambiguous one is the server's to refuse.
                ForEach(list.uniquedRows()) { row($0.value) }
            }

            Button {
                addRule(title == "Outbound" ? .outbound : .inbound)
            } label: {
                Label("Add an \(title) Rule", systemImage: "plus.circle")
            }
            .tint(NSTheme.accent)
            .listRowBackground(NSTheme.row)
        } header: {
            HStack {
                Text(title)
                Spacer()
                Text("\(list.count)")
            }
        } footer: {
            // Said once, under the second list rather than under each.
            if title == "Outbound" {
                VStack(alignment: .leading, spacing: 4) {
                    Text(host == nil
                         ? "Blocks the engine wrote come first, then rules configured here. Addresses are sources on an inbound rule, destinations on an outbound one."
                         : "Every rule on the host, whoever wrote it. Addresses are sources on an inbound rule, destinations on an outbound one.")
                    if let priv = model.state?.firewall?.privilegeText, !priv.isEmpty {
                        Text(priv)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func row(_ rule: ConfigRuleInfo) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                // Allow and Block are the same shape of row and opposite in effect, so the
                // verb carries the colour rather than sitting in grey beside the name.
                Text(rule.action ?? "Block")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(rule.isAllow ? NSTheme.success : NSTheme.danger)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        (rule.isAllow ? NSTheme.success : NSTheme.danger).opacity(0.15),
                        in: Capsule()
                    )

                Text(rule.label ?? rule.name)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 6)

                if let copies = rule.copiesText {
                    Text(copies)
                        .font(.caption2.monospaced())
                        .foregroundStyle(NSTheme.muted)
                }

                if rule.isProtectedRule {
                    Text("THIS CONSOLE")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(NSTheme.warning)
                }
            }

            // Protocol · Port range, then the address list under its own heading. Both are
            // printed in the server's own words — `All ports`, `All IPv4, All IPv6` — because
            // an empty cell reads as "nothing here" where the rule means "everything".
            HStack(spacing: 8) {
                Text("\(rule.protocolText) · \(rule.portsText)")
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.accent)
                Spacer(minLength: 0)
                Label(
                    rule.direction ?? ((rule.inbound ?? true) ? "Inbound" : "Outbound"),
                    systemImage: (rule.inbound ?? true) ? "arrow.down.right" : "arrow.up.right"
                )
                .font(.caption2)
                .foregroundStyle(NSTheme.muted)
            }

            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(rule.addressHeading)
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
                // Never truncated: a UFW rule's source list is the half of the row that
                // decides who the rule is about, and the grid on the other two shows it whole.
                Text(rule.addressesText)
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.text)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }

            HStack(spacing: 8) {
                // Who wrote it. On 0.7.4 this is the column that separates our own rules
                // from UFW's and Docker's, so it is worth more than grey on a foreign row.
                Text("Created by \(rule.originText)")
                    .font(.caption2)
                    .foregroundStyle(rule.isForeignRule ? NSTheme.signal : NSTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)

                if let expiry = rule.expiry, !expiry.isEmpty, expiry != "Permanent" {
                    Label(expiry, systemImage: "clock")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.warning)
                        .lineLimit(1)
                }

                Spacer(minLength: 0)

                // The web page and the desktop grid both put Edit and Delete on the row
                // itself. A swipe is the iOS idiom, but it is also invisible until you try
                // it, and a screen that can be edited should look like one.
                if rule.isProtectedRule {
                    // Says why this row has no buttons, where the buttons would have been —
                    // the console's actions column carries the same word for the same reason.
                    Text("not removable")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                } else {
                    if rule.isEditable {
                        Button("Edit") {
                            editing = EditorTarget(rule: rule, prefill: nil, seedNote: nil)
                        }
                        .font(.caption2.weight(.semibold))
                        .buttonStyle(.borderless)
                        .foregroundStyle(NSTheme.accent)
                    }
                    Button("Delete") { pendingRemoval = rule }
                        .font(.caption2.weight(.semibold))
                        .buttonStyle(.borderless)
                        .foregroundStyle(NSTheme.danger)
                }
            }
        }
        .padding(.vertical, 2)
        .listRowBackground(NSTheme.row)
        .contentShape(.rect)
        .onTapGesture {
            if rule.isEditable { editing = EditorTarget(rule: rule, prefill: nil, seedNote: nil) }
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: !rule.isProtectedRule) {
            if !rule.isProtectedRule {
                Button(role: .destructive) {
                    pendingRemoval = rule
                } label: {
                    Label("Remove", systemImage: "trash")
                }
            }
            if rule.isEditable {
                Button {
                    editing = EditorTarget(rule: rule, prefill: nil, seedNote: nil)
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .tint(NSTheme.accent)
            }
        }
    }

    // MARK: - Listeners

    /// What is accepting connections, and whether the rules above let anyone reach it.
    ///
    /// A listener bound to every interface that the firewall does not admit is fine; the same
    /// listener with nothing covering it is the row this list exists for.
    ///
    /// One row per bind address, not per port — the same set `ss -tuln` prints — so a service
    /// like NetBIOS shows its rows on `0.0.0.0`, the LAN address and the broadcast address
    /// rather than one collapsed entry. Which of them is listening is the question a rule is
    /// written about.
    ///
    /// The list is empty rather than absent on a 0.7.4 server that could not read a firewall
    /// backend at all: the listeners come from `ss`, which needs no privilege, so an
    /// unprivileged run still has an inventory even when it has no rules.
    @ViewBuilder
    private var listenersSection: some View {
        if !listeners.isEmpty || host != nil {
            Section {
                if listeners.isEmpty {
                    Text("No listening sockets reported.")
                        .foregroundStyle(NSTheme.muted)
                        .listRowBackground(NSTheme.row)
                }
                ForEach(listeners.uniquedRows()) { entry in
                    let listener = entry.value
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(listener.process ?? "—")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(NSTheme.text)
                                .lineLimit(1)
                            Spacer(minLength: 6)
                            Text(listener.covered ?? "Unknown")
                                .font(.system(size: 9, weight: .bold))
                                .foregroundStyle(exposureColor(listener.exposure))
                        }
                        HStack(spacing: 8) {
                            Text("\(listener.protocolName ?? "TCP") \(listener.port ?? "")")
                                .font(.caption.monospaced())
                                .foregroundStyle(NSTheme.accent)
                            if let service = listener.service, !service.isEmpty {
                                Text(service)
                                    .font(.caption2)
                                    .foregroundStyle(NSTheme.muted)
                                    .lineLimit(1)
                            }
                            Spacer(minLength: 0)
                            Text(listener.address ?? "")
                                .font(.caption2.monospaced())
                                .foregroundStyle(NSTheme.muted)
                                .lineLimit(1)
                        }
                    }
                    .padding(.vertical, 2)
                    .listRowBackground(NSTheme.row)
                    .contentShape(.rect)
                    .onTapGesture { startRule(for: listener) }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button {
                            startRule(for: listener)
                        } label: {
                            Label("New rule", systemImage: "plus")
                        }
                        .tint(NSTheme.accent)
                    }
                }
            } header: {
                HStack {
                    Text("Listening")
                    Spacer()
                    Text("\(listeners.count)")
                }
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(listenerSummary)
                    Text("What is accepting connections, and what the inbound rules do to traffic arriving at it. Open means reachable from anywhere; Local only means bound to this machine; Not allowed means nothing admits it, however loudly it is listening.")
                    // The point of listing the sockets beside the rules: a rule here is written
                    // against one of them, and reading the port off a terminal to retype it is
                    // how a port goes missing from the rule set.
                    Text("One row per bind address. Tap a row — or swipe it — to start an inbound rule for that socket's protocol and port.")
                }
            }
        }
    }

    /// Opens the editor on a blank rule in one direction. The direction is chosen before the
    /// sheet rather than inside it, which is how both other front-ends ask for it.
    private func addRule(_ direction: FirewallRuleDraft.Direction) {
        var draft = FirewallRuleDraft()
        draft.direction = direction
        editing = EditorTarget(rule: nil, prefill: draft, seedNote: nil)
    }

    /// How much of this firewall this app wrote, and how much of it belongs to everything else.
    private var ownershipSummary: String {
        let mine = rules.filter { !$0.isForeignRule }.count
        let theirs = rules.count - mine
        var text = "\(mine) from Network Sentinel, \(theirs) from the rest of the host."
        // The Windows Firewall stores one rule per profile and protocol, so the scan folds
        // identical rows and says how many it folded — otherwise the count on the page and
        // the count in netsh disagree for no visible reason.
        let folded = rules.reduce(0) { $0 + max(($1.copies ?? 1) - 1, 0) }
        if folded > 0 { text += " \(folded) duplicate rules folded into the rows they repeat." }
        if let disabled = host?.disabledRules, disabled > 0 {
            text += " \(disabled) disabled rules not listed."
        }
        return text
    }

    /// The listener line both other front-ends print above their table: how many sockets, and
    /// how many of them anyone can reach.
    private var listenerSummary: String {
        if listeners.isEmpty { return "No listening sockets were readable." }
        let open = listeners.filter { $0.exposure == .open }.count
        let plural = listeners.count == 1 ? "" : "s"
        return "\(listeners.count) listening socket\(plural) · \(open) reachable from anywhere"
    }

    /// Opens the rule editor on the rule a listening socket argues for.
    ///
    /// A socket whose port is not a plain number has nothing to fill in, so the tap is answered
    /// with the reason rather than a form the server would refuse after the round trip.
    private func startRule(for listener: HostListener) {
        guard let draft = listener.newRuleDraft, let note = listener.newRuleNote else {
            prefillRefusal = listener.newRuleRefusal
            return
        }
        editing = EditorTarget(rule: nil, prefill: draft, seedNote: note)
    }

    private func exposureColor(_ exposure: HostListener.Exposure) -> Color {
        switch exposure {
        // Open is not a fault — a web server is meant to be reachable — but it is the row to
        // read first, so it is the one that carries colour.
        case .open: return NSTheme.warning
        case .restricted: return NSTheme.success
        case .closed: return NSTheme.muted
        case .none: return NSTheme.danger
        case .unknown: return NSTheme.muted
        }
    }

    // MARK: - Actions

    private func rescan() async {
        rescanning = true
        await model.rescanFirewall()
        // The rescan invalidates the server's cache; this is the read that picks up the
        // result, since the action's own reply carries only a summary line.
        await model.refresh(silent: true)
        rescanning = false
    }

    /// Removes through whichever door the rule came in by, which is a question only the
    /// server can answer. A UFW rule has no entry in this app's ledger, so `remove_rule`
    /// would look it up by name and find nothing; `delete_host_rule` takes the shape and
    /// routes it — back through the ledger for one of ours, out through `ufw delete` or
    /// `nft delete rule … handle` for anyone else's.
    private func remove(_ rule: ConfigRuleInfo) async {
        if rule.hasHostKey, let key = rule.key {
            await model.deleteHostRule(key: key)
        } else {
            // Pre-0.7.4: the list is this app's ledger and the name is the handle.
            await model.removeRule(named: rule.name)
        }
    }

    /// What is about to happen, in the terms that matter for this particular rule.
    private func removalWarning(_ rule: ConfigRuleInfo) -> String {
        var text = "The rule stops being evaluated immediately. Traffic it was matching falls through to whatever rule comes next."

        if rule.isForeignRule {
            text += "\n\nThis rule belongs to \(rule.origin ?? "the host"), not to Network Sentinel. Removing it takes it out of the host firewall for good."
        } else if rule.isCustom != true, let origin = rule.origin, !origin.isEmpty {
            text += "\n\nThis rule came from \(origin.lowercased()). Removing it unblocks that traffic until something detects it again."
        }

        // Removing the rule that admits SSH can end the session the machine is administered
        // over, and the app cannot undo that from here.
        if rule.isAllow, rule.matchesSSH {
            text += "\n\nThis is the rule that allows SSH — removing it can end the session you administer this host with."
        }

        return text + "\n\nRequires root or pkexec/sudo on the server."
    }
}

/// Composing one rule. Adding when `rule` is nil, replacing it otherwise.
///
/// The server revalidates everything and is the authority — in particular it is the only side
/// that knows which ports serve this console, so the guard against writing a rule that cuts
/// off the app answering it stays there. What this form does is catch the purely textual
/// mistakes while the keyboard is still up, and refuse to send a shape the server is certain
/// to reject.
struct FirewallRuleEditor: View {
    let rule: ConfigRuleInfo?
    /// Why the fields came filled in, when they did. Nil for a plain add or an edit.
    let seedNote: String?
    /// What the socket filled in. The note names a protocol and a port, so it stops being
    /// true the moment either is edited — the web console leaves its own note standing there
    /// claiming port 22 over a form that now says 443.
    private let seedShape: (protocolName: String, ports: String)?

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var draft: FirewallRuleDraft
    /// The service the protocol and port fields currently spell out, or `Custom`. It follows
    /// the fields rather than owning them: typing over either drops the picker back to Custom,
    /// which is what the desktop's `_suppressPresetHandler` dance amounts to.
    @State private var preset: String = FirewallRuleDraft.presetCustom
    @State private var saving = false
    /// The server's refusal, kept on the sheet. Dismissing on a failed save would look
    /// exactly like a successful one.
    @State private var serverError: String?

    init(rule: ConfigRuleInfo?, prefill: FirewallRuleDraft? = nil, seedNote: String? = nil) {
        self.rule = rule
        self.seedNote = seedNote
        // A prefill only ever accompanies an add — there is no rule whose values it would be
        // overriding — but the order says which wins if that ever stops being true.
        let initial = prefill ?? rule?.draft ?? FirewallRuleDraft()
        seedShape = prefill.map { ($0.protocolName, $0.ports) }
        _draft = State(initialValue: initial)
        _preset = State(initialValue: FirewallRuleDraft.presetMatching(
            protocolName: initial.protocolName, ports: initial.ports))
    }

    /// The console's editor heading is "Add an Inbound Rule"; a phone's inline title bar has
    /// Cancel on one side and Add Rule on the other and clips that to "Add an Inbound R…".
    /// The direction is the half worth keeping — the verb is on the button beside it.
    private var title: String { "\(draft.direction.rawValue) Rule" }

    private var isEditing: Bool { rule != nil }
    private var validationError: String? { draft.validationError }

    /// A block matching everything in its direction takes the machine off the network, this
    /// console with it. The server refuses it outright rather than confirming, because the
    /// request carrying the answer would be cut by the rule it was answering about.
    private var selfBlockRefusal: String? {
        guard draft.action == .block, draft.direction == .inbound, draft.isCatchAll else { return nil }
        return "This would block every inbound connection on every port, including the one this app "
             + "is talking to. The server refuses it — write it from the console on the machine itself."
    }

    private var blocker: String? { validationError ?? selfBlockRefusal }

    /// Editing a rule the host owns is not an edit. UFW has no in-place rewrite, so the server
    /// deletes the original where it lives and writes these values as a new rule — which means
    /// the rule changes position in evaluation order, and a failed write leaves neither.
    private var foreignEditNote: String? {
        guard let rule, rule.isForeignRule else { return nil }
        return "“\(rule.label ?? rule.name)” was created by \(rule.origin ?? "another tool"). "
             + "Saving removes it there and writes these values as a new rule — UFW has no in-place "
             + "edit, so that is what editing one means here."
    }

    var body: some View {
        NavigationStack {
            List {
                if let seedNote, stillSeeded {
                    Section {
                        Label(seedNote, systemImage: "antenna.radiowaves.left.and.right")
                            .font(.system(size: 12))
                            .foregroundStyle(NSTheme.signal)
                            .listRowBackground(NSTheme.row)
                    }
                }

                if let foreignEditNote {
                    Section {
                        Label(foreignEditNote, systemImage: "arrow.triangle.swap")
                            .font(.system(size: 12))
                            .foregroundStyle(NSTheme.signal)
                            .listRowBackground(NSTheme.row)
                    }
                }

                Section {
                    TextField("block-inbound-ssh   (optional)", text: $draft.label)
                        .foregroundStyle(NSTheme.text)
                        .listRowBackground(NSTheme.row)
                } footer: {
                    Text("Optional — the server names the rule from its own fields when this is blank.")
                }

                Section {
                    // Fills protocol and port from a well-known service, exactly as the web
                    // console's Preset select and the desktop's Preset combo do.
                    Picker("Preset", selection: $preset) {
                        Text(FirewallRuleDraft.presetCustom).tag(FirewallRuleDraft.presetCustom)
                        ForEach(FirewallRuleDraft.presets) { Text($0.name).tag($0.name) }
                    }
                    .listRowBackground(NSTheme.row)
                    .onChange(of: preset) { _, name in
                        guard let match = FirewallRuleDraft.presets.first(where: { $0.name == name }) else { return }
                        draft.protocolName = match.protocolName
                        draft.ports = match.ports
                    }

                    Picker("Action", selection: $draft.action) {
                        ForEach(FirewallRuleDraft.Action.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(NSTheme.row)

                    Picker("Direction", selection: $draft.direction) {
                        ForEach(FirewallRuleDraft.Direction.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(NSTheme.row)

                    Picker("Protocol", selection: $draft.protocolName) {
                        ForEach(FirewallRuleDraft.protocols, id: \.self) { Text($0).tag($0) }
                    }
                    .listRowBackground(NSTheme.row)
                    .onChange(of: draft.protocolName) { _, _ in syncPreset() }
                } footer: {
                    Text(draft.direction == .inbound
                         ? "Inbound matches the source address of traffic arriving at this machine."
                         : "Outbound matches the destination address of traffic leaving this machine.")
                }

                Section {
                    TextField("22   or  8000-8001   or  80, 443", text: $draft.ports)
                        .font(.system(size: 15).monospaced())
                        .foregroundStyle(NSTheme.text)
                        .keyboardType(.numbersAndPunctuation)
                        .autocorrectionDisabled()
                        .listRowBackground(NSTheme.row)
                        .onChange(of: draft.ports) { _, _ in syncPreset() }
                } header: {
                    Text("Port range")
                } footer: {
                    // The empty case is the dangerous one, so it is the one spelled out.
                    Text(draft.ports.trimmingCharacters(in: .whitespaces).isEmpty
                         ? "Empty matches every port."
                         : "Single ports and ranges, comma separated.")
                }

                Section {
                    TextField("All IPv4, All IPv6   or  10.0.0.0/8", text: $draft.addresses)
                        .font(.system(size: 15).monospaced())
                        .foregroundStyle(NSTheme.text)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .listRowBackground(NSTheme.row)
                } header: {
                    // "Sources" reads wrong on an outbound rule, where the field is the far
                    // end — both other front-ends swap the word with the direction.
                    Text(draft.direction == .outbound ? "Destinations" : "Sources")
                } footer: {
                    Text(FirewallRuleDraft.isAnyAddress(draft.addresses)
                         ? "Empty matches every address, IPv4 and IPv6."
                         : "Addresses or CIDR blocks, comma separated.")
                }

                if let blocker {
                    Section {
                        Label(blocker, systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(NSTheme.warning)
                            .listRowBackground(NSTheme.row)
                    }
                }

                if let serverError, !serverError.isEmpty {
                    Section {
                        Label(serverError, systemImage: "xmark.octagon.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(NSTheme.danger)
                            .listRowBackground(NSTheme.row)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background { AmbientField() }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(isEditing ? "Save Rule" : "Add Rule") { Task { await save() } }
                        .disabled(blocker != nil || saving)
                        .fontWeight(.semibold)
                }
            }
        }
        .interactiveDismissDisabled(saving)
    }

    /// True while the form still holds what the listening socket put there.
    private var stillSeeded: Bool {
        guard let seedShape else { return false }
        return draft.protocolName == seedShape.protocolName && draft.ports == seedShape.ports
    }

    /// Keeps the preset name honest after the fields it filled in are edited by hand.
    private func syncPreset() {
        let match = FirewallRuleDraft.presetMatching(
            protocolName: draft.protocolName, ports: draft.ports)
        if match != preset { preset = match }
    }

    private func save() async {
        guard blocker == nil else { return }
        saving = true
        serverError = nil
        // Which handle identifies the original decides how the server replaces it. One of ours
        // goes by name through the ledger; one the host owns goes by shape, because its name is
        // not unique and the ledger has never heard of it. Sending both would be a name lookup
        // the server would fail before it ever reached the shape.
        let ok: Bool
        if let rule, rule.isForeignRule, rule.hasHostKey {
            ok = await model.saveConfigRule(draft, ruleKey: rule.key)
        } else {
            ok = await model.saveConfigRule(draft, replacing: rule?.name)
        }
        saving = false
        if ok {
            dismiss()
        } else {
            serverError = model.lastError ?? "The rule was not applied."
        }
    }
}
