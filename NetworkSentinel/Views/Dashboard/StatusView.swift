import SwiftUI

/// The Status screen — design 2a, "tightened".
///
/// The old Dashboard stacked eleven cards: the two you came for sat above six panels of
/// server settings. This screen is the two you came for. A verdict you can read from across
/// the room, one decision card carrying the action that settles it, and the instruments
/// behind them. Everything a detector *setting* rather than a network *reading* moved to
/// Detection; everything that changes what blocking does moved to Enforcement. Both are one
/// row from here, which is where they belong — near, not on, the screen you check.
///
/// The queue behind the decision card is chips rather than a list, so working through three
/// threats never means leaving this screen to find out what they are.
struct StatusView: View {
    @Environment(AppModel.self) private var model
    @Binding var showServers: Bool
    /// Handing over to the Threats tab. Chips name the threats waiting behind this one, and
    /// tapping one has to land where it can be acted on rather than opening a modal that
    /// duplicates the tab.
    var onOpenThreats: () -> Void

    @Namespace private var glassNamespace
    @State private var showEnforcement = false

    // MARK: Hold to block
    //
    // No confirmation dialog. A dialog on a phone is two taps in the same place, which is
    // how you block the wrong address — the second tap is muscle memory by the time you have
    // done it twice. A hold is one continuous, interruptible gesture: the fill is the
    // confirmation, and letting go early is the cancel.

    @State private var holdTask: Task<Void, Never>?
    @State private var holdProgress: CGFloat = 0
    @State private var holdingIP: String?

    private static let holdDuration: TimeInterval = 1.3

    private var stats: StatsInfo? { model.state?.stats }
    private var settings: SettingsInfo? { model.state?.settings }
    private var monitoring: Bool { settings?.isMonitoring ?? stats?.isMonitoring ?? false }
    private var asleep: Bool { model.isAsleep }

    /// Everything at High or above — the set this screen is a verdict on.
    private var pending: [ThreatInfo] {
        (model.state?.threats ?? []).filter {
            ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) >= .high
        }
    }

    private var topSeverity: ThreatSeverity {
        pending.reduce(.none) {
            Swift.max($0, ThreatSeverity.from(level: $1.level, levelNum: $1.levelNum))
        }
    }

    private var chromeTint: Color {
        model.liveSeverity >= .high ? model.liveSeverity.color : NSTheme.accent
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    serverBar
                    if asleep {
                        SleepBanner { Task { await model.wakeConsole() } }
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                    // Readings dim while asleep; the controls under them stay at full
                    // strength, because they hold the way back to Wake.
                    verdictBlock.nsAsleepDimmed(asleep)
                    decisionCard.nsAsleepDimmed(asleep)
                    queueChips.nsAsleepDimmed(asleep)
                    instrumentPanel.nsAsleepDimmed(asleep)
                    controlRow
                    destinationRows
                    footnote
                }
                .animation(.easeInOut(duration: 0.25), value: asleep)
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 28)
            }
            .background {
                AmbientField(severity: model.liveSeverity, load: model.activityLoad)
            }
            .scrollEdgeEffectStyle(.soft, for: .top)
            // The server bar is the header. A navigation bar on top of it would be a second
            // row of chrome saying the same thing.
            .toolbar(.hidden, for: .navigationBar)
            .refreshable { await model.refresh(silent: false) }
            .navigationDestination(for: StatusDestination.self) { destination in
                switch destination {
                case .detection: DetectionView()
                }
            }
            .sheet(isPresented: $showEnforcement) {
                EnforcementView()
                    .preferredColorScheme(.dark)
            }
        }
    }

    // MARK: - Server bar

    private var serverBar: some View {
        HStack(spacing: 10) {
            Button {
                showServers = true
            } label: {
                HStack(spacing: 7) {
                    Circle()
                        .fill(asleep ? NSTheme.warning : (monitoring ? NSTheme.success : NSTheme.warning))
                        .frame(width: 7, height: 7)
                    Text(model.server?.name ?? "No server")
                        .font(.system(size: 13, weight: .medium).monospaced())
                        .foregroundStyle(NSTheme.text)
                        .lineLimit(1)
                    Image(systemName: "chevron.down")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(NSTheme.muted)
                }
            }
            .accessibilityLabel("Server: \(model.server?.name ?? "none"). Switch server.")

            Spacer(minLength: 8)

            if let clock = model.state?.clock {
                Text(clock)
                    .font(.system(size: 12).monospaced())
                    .foregroundStyle(NSTheme.muted)
                    .contentTransition(.numericText())
            }

            Button {
                Task { await model.refresh(silent: false) }
            } label: {
                if model.isLoading || model.isRefreshing {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(chromeTint)
                }
            }
            .accessibilityLabel("Refresh")
        }
        .frame(height: 38)
    }

    // MARK: - Verdict
    //
    // The number and the word, at a size that survives a glance from arm's length, over one
    // line saying whether anything is currently stopping it. Those are two different
    // questions — how bad, and is it handled — and answering only the first is what sends
    // people to the console to find out whether the app did anything.

    private var verdictBlock: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(headline)
                .font(.readout(52, weight: .bold))
                .foregroundStyle(pending.isEmpty ? NSTheme.signal : topSeverity.color)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
                .contentTransition(.numericText())

            Text(verdictLine)
                .font(.system(size: 13, weight: .semibold))
                .textCase(.uppercase)
                .tracking(1.2)
                .foregroundStyle(verdictTint)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .animation(.snappy(duration: 0.35), value: pending.count)
    }

    /// The count is of the worst level present, not of everything above High: "3 high" over a
    /// live Critical would be a headline that leaves out the reason you picked up the phone.
    private var headline: String {
        guard !pending.isEmpty else { return asleep ? "Asleep" : "All clear" }
        let top = topSeverity
        let n = pending.count { ThreatSeverity.from(level: $0.level, levelNum: $0.levelNum) == top }
        return "\(n) \(top.label.lowercased())"
    }

    private var verdictLine: String {
        guard let t = model.attentionThreat else {
            if asleep { return "Monitoring stopped · blocks still in force" }
            return monitoring ? "Nothing needs a decision" : "Monitoring paused"
        }
        // The server's own sentence when it has one — it knows about dry run and about a
        // block the firewall refused, neither of which is visible from here.
        if let short = t.blockShort, !short.isEmpty {
            return t.blockVerdict?.isBlocked == true ? "Blocked · rule in force" : short
        }
        if !t.isBlockable { return "On this host · nothing to firewall" }
        return "Not blocked · nothing stopping it"
    }

    private var verdictTint: Color {
        guard let t = model.attentionThreat else { return pending.isEmpty ? NSTheme.signal : NSTheme.muted }
        if t.blockVerdict?.isBlocked == true { return NSTheme.success }
        if t.blockVerdict == .dryRun || t.blockVerdict == .failed { return NSTheme.warning }
        return topSeverity.color
    }

    // MARK: - Decision

    @ViewBuilder
    private var decisionCard: some View {
        if let t = model.attentionThreat {
            let severity = ThreatSeverity.from(level: t.level, levelNum: t.levelNum)
            VStack(alignment: .leading, spacing: 11) {
                HStack(spacing: 8) {
                    Image(systemName: t.icon)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(severity.color)
                    Text(t.type ?? severity.label)
                        .font(.system(size: 11, weight: .semibold))
                        .textCase(.uppercase)
                        .tracking(0.8)
                        .foregroundStyle(severity.color)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    Text(t.time)
                        .font(.system(size: 11).monospaced())
                        .foregroundStyle(NSTheme.mutedOnTint)
                }

                Text(t.title)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(NSTheme.text)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 8) {
                    Text(t.isBlockable ? t.sourceIp : "This computer")
                        .font(.system(size: 14, weight: .medium).monospaced())
                        .foregroundStyle(NSTheme.cyan)
                        .lineLimit(1)
                    if let origin = t.origin, !origin.isEmpty {
                        Text(origin)
                            .font(.system(size: 12))
                            .foregroundStyle(NSTheme.mutedOnTint)
                            .lineLimit(1)
                    }
                }

                if let status = t.blockStatus, !status.isEmpty {
                    Text(status)
                        .font(.system(size: 12))
                        .foregroundStyle(verdictTint)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let detail = t.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.system(size: 12))
                        .foregroundStyle(NSTheme.mutedOnTint)
                        .lineLimit(2)
                }

                decisionAction(for: t, severity: severity)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .nsCard(tint: severity.color)
            .transition(.asymmetric(
                insertion: .scale(scale: 0.96).combined(with: .opacity),
                removal: .opacity
            ))
            .animation(.spring(response: 0.4, dampingFraction: 0.8), value: t.id)
        }
    }

    @ViewBuilder
    private func decisionAction(for t: ThreatInfo, severity: ThreatSeverity) -> some View {
        if !t.isBlockable {
            // Host-local detections report loopback; the server refuses to firewall it, so a
            // block control here would be a hold that ends in an error toast.
            Label("On this host — there is no peer to firewall", systemImage: "desktopcomputer")
                .font(.system(size: 12))
                .foregroundStyle(NSTheme.mutedOnTint)
        } else if t.blockVerdict?.isBlocked == true {
            // Deliberately a state, not a release. This is the most prominent control on the
            // screen; "undo the protection" does not belong one stray tap away. The Threats
            // tab offers Unblock, on the row it belongs to.
            HStack(spacing: 8) {
                BlockBadge(verdict: .blocked)
                Spacer(minLength: 0)
                Button("Threats", action: onOpenThreats)
                    .font(.caption.weight(.semibold))
                    .buttonStyle(.glass)
            }
        } else {
            holdToBlock(t, tint: severity.color)
        }
    }

    private func holdToBlock(_ t: ThreatInfo, tint: Color) -> some View {
        let active = holdingIP == t.sourceIp
        return ZStack {
            Capsule().fill(Color.white.opacity(0.10))
            GeometryReader { geo in
                Capsule()
                    .fill(LinearGradient(
                        colors: [tint, tint.opacity(0.72)],
                        startPoint: .leading,
                        endPoint: .trailing
                    ))
                    .frame(width: geo.size.width * (active ? holdProgress : 0))
            }
            HStack(spacing: 8) {
                Image(systemName: "hand.raised.fill")
                    .font(.system(size: 14, weight: .semibold))
                Text(active ? "Hold…" : "Hold to block \(t.sourceIp)")
                    .font(.system(size: 15, weight: .semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 16)
        }
        .frame(height: 52)
        .clipShape(.capsule)
        .overlay(Capsule().stroke(Color.white.opacity(0.18), lineWidth: 0.5))
        .contentShape(.capsule)
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in beginHold(t.sourceIp) }
                .onEnded { _ in cancelHold() }
        )
        // A press-and-hold is unusable with VoiceOver, so the same action is offered
        // outright — the gesture exists to slow a sighted stray tap, not to gate the action.
        .accessibilityElement()
        .accessibilityLabel("Block \(t.sourceIp)")
        .accessibilityHint("Press and hold to write a firewall rule")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction {
            Task { await model.requestBlock(ip: t.sourceIp) }
        }
    }

    private func beginHold(_ ip: String) {
        guard holdTask == nil else { return }
        holdingIP = ip
        withAnimation(.linear(duration: Self.holdDuration)) { holdProgress = 1 }
        holdTask = Task {
            try? await Task.sleep(for: .seconds(Self.holdDuration))
            guard !Task.isCancelled else { return }
            UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
            await model.requestBlock(ip: ip)
            cancelHold()
        }
    }

    private func cancelHold() {
        holdTask?.cancel()
        holdTask = nil
        holdingIP = nil
        withAnimation(.easeOut(duration: 0.18)) { holdProgress = 0 }
    }

    // MARK: - The queue behind the decision

    @ViewBuilder
    private var queueChips: some View {
        // Everything High+ except the one already on the card above it.
        let rest = Array(pending.dropFirst().prefix(3))
        if !rest.isEmpty {
            HStack(spacing: 8) {
                ForEach(rest.uniquedRows()) { row in
                    let t = row.value
                    let severity = ThreatSeverity.from(level: t.level, levelNum: t.levelNum)
                    Button(action: onOpenThreats) {
                        HStack(spacing: 7) {
                            Circle()
                                .fill(severity.color)
                                .frame(width: 6, height: 6)
                            Text(t.title)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(NSTheme.mutedOnTint)
                                .lineLimit(1)
                                .truncationMode(.tail)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 11)
                        .padding(.vertical, 9)
                        .background(NSTheme.row, in: .rect(cornerRadius: 14))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14)
                                .stroke(NSTheme.border, lineWidth: 0.5)
                        )
                    }
                    .accessibilityLabel("\(severity.label): \(t.title). Open in Threats.")
                }
            }
        }
    }

    // MARK: - Instruments

    private var instrumentPanel: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top, spacing: 0) {
                instrument("\(stats?.activeConnections ?? 0)", "Conns", tint: NSTheme.text)
                instrument("\(stats?.remoteHosts ?? 0)", "Hosts", tint: NSTheme.text)
                instrument(
                    "\(stats?.threatsToday ?? 0)",
                    "Threats",
                    tint: (stats?.highThreats ?? 0) > 0 ? NSTheme.danger : NSTheme.text
                )
                instrument("\(stats?.listeningPorts ?? 0)", "Ports", tint: NSTheme.text)
            }

            if let activity = model.state?.activity, !activity.isEmpty {
                ActivityChart(points: activity, style: .compact)
            } else {
                Text("Waiting for samples…")
                    .font(.system(size: 12))
                    .foregroundStyle(NSTheme.muted)
                    .frame(height: 46, alignment: .center)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 13)
        .background(NSTheme.row, in: .rect(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 0.5)
        )
    }

    private func instrument(_ value: String, _ label: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value)
                .font(.readout(24, weight: .bold))
                .foregroundStyle(tint)
                .contentTransition(.numericText())
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .textCase(.uppercase)
                .tracking(0.9)
                .foregroundStyle(NSTheme.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    // MARK: - Controls

    private var controlRow: some View {
        GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
                controlButton(
                    title: asleep ? "Wake" : "Sleep",
                    icon: asleep ? "sun.max.fill" : "moon.zzz.fill",
                    tint: asleep ? NSTheme.warning : NSTheme.accent
                ) {
                    await model.toggleSleep()
                }
                .glassEffectID("sleep", in: glassNamespace)

                // Asleep, Wake is already the way back — a second control offering to
                // un-stop the same monitor would be two names for one thing.
                if !asleep {
                    controlButton(
                        title: monitoring ? "Pause" : "Resume",
                        icon: monitoring ? "pause.fill" : "play.fill",
                        tint: monitoring ? NSTheme.warning : NSTheme.success
                    ) {
                        await model.toggleMonitor()
                    }
                    .glassEffectID("monitor", in: glassNamespace)
                }

                controlButton(
                    title: autoBlockShort,
                    icon: "hand.raised.fill",
                    tint: autoBlockTint
                ) {
                    await model.toggleAutoblock()
                }
                .glassEffectID("autoblock", in: glassNamespace)
                // The engine's own wording, for anyone who cannot see the tint.
                .accessibilityValue(settings?.autoBlockSummary ?? autoBlockShort)
            }
        }
    }

    // Auto-block has three states, not two: 0.6's dry run walks every gate and writes
    // nothing. The button is one word wide, so the third state has to be the word itself —
    // "Auto-block" over an engine deliberately writing no rules is the one lie worth
    // avoiding here. The full sentence is in Enforcement, one row down.
    private var autoBlockOn: Bool { settings?.autoBlockEnabled ?? false }
    private var autoBlockDryRun: Bool { settings?.preventionDryRun ?? false }

    private var autoBlockShort: String {
        guard autoBlockOn else { return "Manual" }
        return autoBlockDryRun ? "Dry run" : "Auto-block"
    }

    private var autoBlockTint: Color {
        guard autoBlockOn else { return NSTheme.muted }
        return autoBlockDryRun ? NSTheme.warning : NSTheme.danger
    }

    private func controlButton(
        title: String,
        icon: String,
        tint: Color,
        action: @escaping () async -> Void
    ) -> some View {
        Button {
            Task { await action() }
        } label: {
            HStack(spacing: 7) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(tint)
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .contentTransition(.interpolate)
        }
        .buttonStyle(.glass)
    }

    // MARK: - Where the rest of it went

    @ViewBuilder
    private var destinationRows: some View {
        Button {
            showEnforcement = true
        } label: {
            destinationRow(
                icon: "hand.raised.fill",
                tint: autoBlockTint,
                title: "Enforcement",
                value: enforcementSummary
            )
        }

        NavigationLink(value: StatusDestination.detection) {
            destinationRow(
                icon: "dot.radiowaves.left.and.right",
                tint: NSTheme.signal,
                title: "Detection",
                value: detectionSummary
            )
        }
    }

    private func destinationRow(icon: String, tint: Color, title: String, value: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 18)
            Text(title)
                .font(.system(size: 15))
                .foregroundStyle(NSTheme.text)
            Spacer(minLength: 8)
            Text(value)
                .font(.system(size: 12))
                .foregroundStyle(NSTheme.muted)
                .lineLimit(1)
            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(NSTheme.muted)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 13)
        .background(NSTheme.row, in: .rect(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 0.5)
        )
    }

    /// The server's own summary when it publishes one (0.6.3+), because it is the only text
    /// that gets dry run right; the level otherwise.
    private var enforcementSummary: String {
        if let summary = settings?.autoBlockSummary, !summary.isEmpty { return summary }
        guard autoBlockOn else { return "Manual blocks only" }
        return "≥ \(settings?.autoBlockMinLevel ?? "High")"
    }

    private var detectionSummary: String {
        let detectors = Detector.all(settings: settings, model: model)
        guard !detectors.isEmpty else { return "—" }
        var parts = ["\(detectors.count(where: \.isOn)) on"]
        let stalled = detectors.count(where: \.isStalled)
        if stalled > 0 { parts.append("\(stalled) needs root") }
        return parts.joined(separator: " · ")
    }

    // MARK: - Footnote

    /// The server's status line and the last error. The old screen gave these a card of their
    /// own at the top; they are the least urgent text here, so they sit at the bottom where
    /// they can be read rather than scanned past.
    @ViewBuilder
    private var footnote: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let err = model.lastError, !err.isEmpty {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(NSTheme.danger)
                    .transition(.opacity)
            } else if let msg = model.state?.statusMessage, !msg.isEmpty {
                Text(msg)
                    .font(.system(size: 12))
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(3)
                    .contentTransition(.opacity)
            }

            if let priv = model.state?.firewall?.privilegeText, !priv.isEmpty {
                Text(priv)
                    .font(.system(size: 11))
                    .foregroundStyle(NSTheme.muted)
                    .lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 2)
        .animation(.easeInOut(duration: 0.2), value: model.lastError)
    }
}

/// Push targets from Status. An enum rather than a closure so the stack keeps working when
/// more screens move off this one.
enum StatusDestination: Hashable {
    case detection
}
