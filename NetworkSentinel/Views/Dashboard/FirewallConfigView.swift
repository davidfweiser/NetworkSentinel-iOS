import SwiftUI

/// The firewall ledger — web 0.7's Firewall Config tab.
///
/// This is not the same list as More's *Firewall rules*, and the difference is the point.
/// That one is the blocks this app and the prevention engine minted, which is the set you act
/// on during an incident. This one is *everything the firewall will evaluate*, in the order it
/// evaluates it: engine blocks first, then the operator's own rules. A permissive rule sitting
/// above a block is the misconfiguration this screen exists to make visible, and it is
/// invisible in any list that leaves half the rules out.
///
/// Order is therefore never re-sorted here — not by name, not by action, not to put the
/// editable ones together. The server sends evaluation order and evaluation order is the
/// reading.
struct FirewallConfigView: View {
    @Environment(AppModel.self) private var model

    @State private var editing: EditorTarget?
    @State private var pendingRemoval: ConfigRuleInfo?

    /// What the editor sheet was opened for. `rule` is nil when adding.
    struct EditorTarget: Identifiable {
        let rule: ConfigRuleInfo?
        var id: String { rule?.name ?? "" }
    }

    private var rules: [ConfigRuleInfo] { model.state?.configRules ?? [] }

    var body: some View {
        List {
            Section {
                if rules.isEmpty {
                    Text("No firewall rules configured")
                        .foregroundStyle(NSTheme.muted)
                        .listRowBackground(NSTheme.row)
                } else {
                    ForEach(rules) { rule in
                        row(rule)
                    }
                }
            } header: {
                Text("Evaluation order")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Rules are matched top to bottom. Blocks the engine wrote come first, then rules configured here.")
                    if let priv = model.state?.firewall?.privilegeText, !priv.isEmpty {
                        Text(priv)
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background { AmbientField() }
        .navigationTitle("Firewall Config")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    editing = EditorTarget(rule: nil)
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add rule")
            }
        }
        .sheet(item: $editing) { target in
            FirewallRuleEditor(rule: target.rule)
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
                if let name = pendingRemoval?.name {
                    Task { await model.removeRule(named: name) }
                }
                pendingRemoval = nil
            }
            Button("Cancel", role: .cancel) { pendingRemoval = nil }
        } message: {
            Text("The rule stops being evaluated immediately. Traffic it was matching falls through to whatever rule comes next.")
        }
        .refreshable { await model.refresh(silent: false) }
    }

    // MARK: - Row

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
                    .lineLimit(1)

                Spacer(minLength: 6)

                if rule.isProtectedRule {
                    Text("THIS CONSOLE")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(NSTheme.warning)
                }
            }

            Text(rule.matchSummary)
                .font(.caption.monospaced())
                .foregroundStyle(NSTheme.muted)
                .lineLimit(2)

            HStack(spacing: 8) {
                Label(
                    rule.direction ?? ((rule.inbound ?? true) ? "Inbound" : "Outbound"),
                    systemImage: (rule.inbound ?? true) ? "arrow.down.right" : "arrow.up.right"
                )
                .font(.caption2)
                .foregroundStyle(NSTheme.accent)

                if let origin = rule.origin, !origin.isEmpty {
                    Text(origin)
                        .font(.caption2)
                        .foregroundStyle(NSTheme.muted)
                        .lineLimit(1)
                }

                if let expiry = rule.expiry, !expiry.isEmpty {
                    Label(expiry, systemImage: "clock")
                        .font(.caption2)
                        .foregroundStyle(NSTheme.warning)
                        .lineLimit(1)
                }

                Spacer(minLength: 0)
            }
        }
        .padding(.vertical, 2)
        .listRowBackground(NSTheme.row)
        .contentShape(.rect)
        .onTapGesture {
            // Only a rule the operator wrote can be edited. An engine block is lifted by
            // unblocking its address, not by rewriting the rule underneath it — editing one
            // here would leave the engine believing it still holds a block it no longer has.
            if rule.isEditable { editing = EditorTarget(rule: rule) }
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
                    editing = EditorTarget(rule: rule)
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .tint(NSTheme.accent)
            }
        }
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

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var draft: FirewallRuleDraft
    @State private var saving = false
    /// The server's refusal, kept on the sheet. Dismissing on a failed save would look
    /// exactly like a successful one.
    @State private var serverError: String?

    init(rule: ConfigRuleInfo?) {
        self.rule = rule
        _draft = State(initialValue: rule?.draft ?? FirewallRuleDraft())
    }

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

    var body: some View {
        NavigationStack {
            List {
                Section {
                    TextField("Label", text: $draft.label)
                        .foregroundStyle(NSTheme.text)
                        .listRowBackground(NSTheme.row)
                } footer: {
                    Text("Optional — the server names the rule from its own fields when this is blank.")
                }

                Section {
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
                } footer: {
                    Text(draft.direction == .inbound
                         ? "Inbound matches the source address of traffic arriving at this machine."
                         : "Outbound matches the destination address of traffic leaving this machine.")
                }

                Section {
                    TextField("22, 8000-8001", text: $draft.ports)
                        .font(.system(size: 15).monospaced())
                        .foregroundStyle(NSTheme.text)
                        .keyboardType(.numbersAndPunctuation)
                        .autocorrectionDisabled()
                        .listRowBackground(NSTheme.row)
                } header: {
                    Text("Ports")
                } footer: {
                    // The empty case is the dangerous one, so it is the one spelled out.
                    Text(draft.ports.trimmingCharacters(in: .whitespaces).isEmpty
                         ? "Empty matches every port."
                         : "Single ports and ranges, comma separated.")
                }

                Section {
                    TextField("Any address", text: $draft.addresses)
                        .font(.system(size: 15).monospaced())
                        .foregroundStyle(NSTheme.text)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .listRowBackground(NSTheme.row)
                } header: {
                    Text("Addresses")
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
            .navigationTitle(isEditing ? "Edit rule" : "New rule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(isEditing ? "Save" : "Add") { Task { await save() } }
                        .disabled(blocker != nil || saving)
                        .fontWeight(.semibold)
                }
            }
        }
        .interactiveDismissDisabled(saving)
    }

    private func save() async {
        guard blocker == nil else { return }
        saving = true
        serverError = nil
        // `replace` is the old rule's name: the server removes that one and writes this in
        // its place, which is what keeps an edit from silently becoming a second rule.
        let ok = await model.saveConfigRule(draft, replacing: rule?.name)
        saving = false
        if ok {
            dismiss()
        } else {
            serverError = model.lastError ?? "The rule was not applied."
        }
    }
}
