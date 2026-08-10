import SwiftUI

/// What blocking actually does — reached from the Status screen, beside the controls it
/// governs. Auto-block's on/off is a one-tap control on Status because it is the switch you
/// reach for mid-incident; everything that shapes the rule it writes is here, because
/// changing a threshold is not something anyone does while an alert is live.
struct EnforcementView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    private var settings: SettingsInfo? { model.state?.settings }
    private var autoBlockOn: Bool { settings?.autoBlockEnabled ?? false }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle(isOn: Binding(
                        get: { autoBlockOn },
                        set: { _ in Task { await model.toggleAutoblock() } }
                    )) {
                        Text("Auto-block")
                            .font(.system(size: 15))
                            .foregroundStyle(NSTheme.text)
                    }
                    .tint(NSTheme.danger)
                    .listRowBackground(NSTheme.row)

                    Menu {
                        ForEach(["Medium", "High", "Critical"], id: \.self) { level in
                            Button(level) {
                                Task { await model.setMinLevel(level) }
                            }
                        }
                    } label: {
                        settingLabel(
                            title: "Minimum level",
                            subtitle: "Nothing below this is ever blocked automatically.",
                            value: settings?.autoBlockMinLevel ?? "High"
                        )
                    }
                    .listRowBackground(NSTheme.row)

                    // Web 0.4+ — auto-block rules can expire on their own. Presets rather
                    // than a minutes field: nobody types "10080" on a phone to mean a week.
                    if let expiry = settings?.autoBlockExpiryMinutes {
                        Menu {
                            ForEach(Self.expiryOptions, id: \.minutes) { option in
                                Button(option.label) {
                                    Task { await model.setAutoBlockExpiry(minutes: option.minutes) }
                                }
                            }
                        } label: {
                            settingLabel(
                                title: "Rules expire",
                                subtitle: "How long an automatic rule stays in force.",
                                value: Self.expiryLabel(expiry)
                            )
                        }
                        .listRowBackground(NSTheme.row)
                    }
                } header: {
                    Text("Auto-block")
                } footer: {
                    // The engine's own sentence — the only text that gets dry run right.
                    if let summary = settings?.autoBlockSummary, !summary.isEmpty {
                        Text(summary)
                    }
                }

                // Web 0.6+ — the prevention engine can walk every gate and report what it
                // would have dropped without writing a rule.
                if let dryRun = settings?.preventionDryRun {
                    Section {
                        Toggle(isOn: Binding(
                            get: { dryRun },
                            set: { on in Task { await model.setPreventionDryRun(on) } }
                        )) {
                            Text("Dry run")
                                .font(.system(size: 15))
                                .foregroundStyle(NSTheme.text)
                        }
                        .tint(NSTheme.warning)
                        .listRowBackground(NSTheme.row)
                    } footer: {
                        Text(dryRun
                             ? "Auto-block walks every gate and reports what it would drop, writing no firewall rules."
                             : "Auto-block writes firewall rules. Turn dry run on before trusting a new detection source.")
                    }
                }

                Section {
                    Toggle(isOn: Binding(
                        get: { settings?.blockInbound ?? true },
                        set: { on in Task { await model.setBlockInbound(on) } }
                    )) {
                        Text("Block inbound")
                            .font(.system(size: 15))
                            .foregroundStyle(NSTheme.text)
                    }
                    .tint(NSTheme.accent)
                    .listRowBackground(NSTheme.row)

                    Toggle(isOn: Binding(
                        get: { settings?.blockOutbound ?? false },
                        set: { on in Task { await model.setBlockOutbound(on) } }
                    )) {
                        Text("Block outbound")
                            .font(.system(size: 15))
                            .foregroundStyle(NSTheme.text)
                    }
                    .tint(NSTheme.accent)
                    .listRowBackground(NSTheme.row)
                } header: {
                    Text("Direction")
                } footer: {
                    Text("Which way a block rule is written. Outbound also stops this machine from reaching the address.")
                }

                Section {
                    Button {
                        Task { await model.authorizeFirewall() }
                    } label: {
                        Label("Authorize firewall", systemImage: "lock.open")
                    }
                    .listRowBackground(NSTheme.row)
                } footer: {
                    if let priv = model.state?.firewall?.privilegeText, !priv.isEmpty {
                        Text(priv)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background { AmbientField() }
            .navigationTitle("Enforcement")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func settingLabel(title: String, subtitle: String, value: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 15))
                    .foregroundStyle(NSTheme.text)
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Text(value)
                .font(.system(size: 12).monospaced())
                .foregroundStyle(NSTheme.cyan)
            Image(systemName: "chevron.up.chevron.down")
                .font(.caption2)
                .foregroundStyle(NSTheme.muted)
        }
        .padding(.vertical, 4)
    }

    private static let expiryOptions: [(minutes: Int, label: String)] = [
        (0, "Never"),
        (60, "1 hour"),
        (360, "6 hours"),
        (1440, "24 hours"),
        (10080, "7 days")
    ]

    private static func expiryLabel(_ minutes: Int) -> String {
        if let known = expiryOptions.first(where: { $0.minutes == minutes }) { return known.label }
        if minutes % 1440 == 0 { return "\(minutes / 1440)d" }
        if minutes % 60 == 0 { return "\(minutes / 60)h" }
        return "\(minutes)m"
    }
}
