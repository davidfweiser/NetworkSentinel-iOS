import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.store.servers.isEmpty {
                OnboardingView()
            } else {
                switch model.authPhase {
                case .checking:
                    AuthLoadingView(message: "Connecting to server…")
                case .setup, .login:
                    AuthView()
                case .authenticated:
                    MainTabView()
                case .unreachable(let message):
                    UnreachableView(message: message)
                }
            }
        }
        .background { AmbientField() }
        .task {
            model.onAppear()
        }
        .onDisappear {
            model.onDisappear()
        }
        .animation(.easeInOut(duration: 0.25), value: model.store.servers.count)
        .animation(.easeInOut(duration: 0.2), value: model.authPhase)
        .animation(.easeInOut(duration: 0.2), value: model.isAuthenticated)
        // A Critical arriving in the foreground used to open a modal alert, which covered
        // the Dashboard card offering the same Block button. A banner says the same thing
        // without taking the screen hostage, and the card stays there after it goes.
        // Every floating notice shares one stack. Blocking an IP raises both at once — the
        // action's confirmation, and the next Critical the poll turns up — and as separate
        // top overlays the confirmation landed squarely on the banner's Block and dismiss
        // buttons. Stacked, they queue instead of covering each other.
        .overlay(alignment: .top) {
            VStack(spacing: 8) {
                if let alert = model.pendingCriticalAlert {
                    CriticalBanner(
                        payload: alert,
                        onBlock: {
                            let ip = alert.threat.sourceIp
                            model.dismissCriticalAlert()
                            Task { await model.requestBlock(ip: ip) }
                        },
                        onDismiss: { model.dismissCriticalAlert() }
                    )
                    .transition(.move(edge: .top).combined(with: .opacity))
                }

                if let banner = model.statusBanner {
                    StatusToast(message: banner) { model.statusBanner = nil }
                        .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)
        }
        .animation(.spring(response: 0.42, dampingFraction: 0.85), value: model.pendingCriticalAlert)
        .animation(.spring(response: 0.35), value: model.statusBanner)
        // Web 0.6's prevention engine keeps auto-block off CGNAT (100.64/10) entirely,
        // because that range carries Tailscale and most WireGuard tunnels. A manual block
        // still reaches it — a hostile tunnel peer is a real case — so it asks first, once,
        // here rather than in each of the views offering a Block button.
        .confirmationDialog(
            "Block a tunnel address?",
            isPresented: Binding(
                get: { model.pendingTunnelBlockIP != nil },
                set: { if !$0 { model.cancelPendingTunnelBlock() } }
            ),
            titleVisibility: .visible,
            presenting: model.pendingTunnelBlockIP
        ) { ip in
            Button("Block \(ip)", role: .destructive) {
                Task { await model.confirmTunnelBlock(ip) }
            }
            Button("Cancel", role: .cancel) { model.cancelPendingTunnelBlock() }
        } message: { ip in
            Text("\(ip) is in the carrier-grade NAT range used by VPN tunnels. Blocking it cuts that peer off — which may be how you reach this server.")
        }
    }
}

/// Transient confirmation for an action you just took ("Blocked 1.2.3.4"). Steps aside on
/// its own; tapping clears it early rather than waiting it out.
struct StatusToast: View {
    let message: String
    var onDismiss: () -> Void

    var body: some View {
        Text(message)
            .font(.footnote.weight(.medium))
            .foregroundStyle(NSTheme.text)
            .multilineTextAlignment(.center)
            // A block reports every firewall rule it wrote, by name. Three lines is enough
            // to see what happened without the toast growing into a wall over the UI.
            .lineLimit(3)
            .padding(.horizontal, 16)
            .padding(.vertical, 11)
            .glassEffect(.regular, in: .capsule)
            .contentShape(.capsule)
            .onTapGesture(perform: onDismiss)
            // Keyed on the message: a second one arriving while the first is still up
            // restarts the timer. `.onAppear` did not fire again for the reused Text, so
            // the replacement message inherited no timer and stayed up for good.
            .task(id: message) {
                try? await Task.sleep(for: .seconds(2.5))
                guard !Task.isCancelled else { return }
                onDismiss()
            }
    }
}

/// Foreground warning for a new Critical threat. Non-blocking: it floats over whichever
/// tab you are on, offers the one action worth taking, and steps aside on its own.
struct CriticalBanner: View {
    let payload: CriticalAlertPayload
    var onBlock: () -> Void
    var onDismiss: () -> Void

    private var severity: ThreatSeverity {
        ThreatSeverity.from(level: payload.threat.level, levelNum: payload.threat.levelNum)
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Circle()
                .fill(severity.color)
                .frame(width: 8, height: 8)
                .padding(.top, 6)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text("Critical").nsEyebrow()
                    Text(payload.serverName)
                        .font(.system(size: 11))
                        .foregroundStyle(NSTheme.muted)
                    if payload.extraCount > 0 {
                        Text("+\(payload.extraCount)")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(severity.color)
                    }
                }
                Text(payload.threat.title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(2)
                Text(payload.threat.isBlockable
                     ? payload.threat.sourceIp
                     : (payload.threat.type ?? "On this host"))
                    .font(.system(size: 11).monospaced())
                    .foregroundStyle(NSTheme.cyan)
                    .lineLimit(1)
                // Web 0.6.3+: an alarm that names an address should say whether that
                // address is being blocked — the whole point of the banner is that you
                // do not have to open the console to find out what is happening.
                if let verdict = payload.threat.blockVerdict,
                   let status = payload.threat.blockStatus, !status.isEmpty {
                    Text(status)
                        .font(.system(size: 10))
                        .foregroundStyle(
                            verdict == .dryRun || verdict == .failed
                                ? NSTheme.warning
                                : NSTheme.mutedOnTint
                        )
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Spacer(minLength: 4)

            VStack(spacing: 6) {
                // A 0.4+ host-local Critical has no peer to block; only the dismiss
                // control is meaningful there. Nor is there anything to offer once the
                // server has already blocked it — and a banner that dismisses itself
                // after eight seconds is the worst place to put "release this address".
                if payload.threat.isBlockable, payload.threat.blockVerdict?.isBlocked != true {
                    Button("Block", action: onBlock)
                        .font(.caption.weight(.bold))
                        .buttonStyle(.glassProminent)
                        .tint(severity.color)
                }
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(NSTheme.muted)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(14)
        .glassEffect(Glass.regular.tint(severity.color.opacity(0.22)), in: .rect(cornerRadius: 20))
        .task(id: payload.id) {
            // Long enough to read and act on, short enough not to sit over the UI.
            try? await Task.sleep(for: .seconds(8))
            onDismiss()
        }
    }
}

struct AuthLoadingView: View {
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            ProgressView()
                .tint(NSTheme.accent)
                .scaleEffect(1.2)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(NSTheme.muted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background { AmbientField() }
    }
}

struct UnreachableView: View {
    @Environment(AppModel.self) private var model
    let message: String
    @State private var showServers = false
    @State private var showEditServer = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "wifi.exclamationmark")
                    .font(.system(size: 44))
                    .foregroundStyle(NSTheme.warning)

                Text("Can't reach server")
                    .font(.title2.bold())
                    .foregroundStyle(NSTheme.text)

                if let s = model.server {
                    Text(s.name)
                        .font(.headline)
                        .foregroundStyle(NSTheme.text)
                    Text(s.displayHost)
                        .font(.caption.monospaced())
                        .foregroundStyle(NSTheme.muted)
                }

                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(NSTheme.muted)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)

                Button {
                    Task { await model.refresh(silent: false) }
                } label: {
                    Text("Retry")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .buttonStyle(.borderedProminent)
                .tint(NSTheme.accent)
                .padding(.horizontal, 32)

                HStack(spacing: 20) {
                    Button {
                        showEditServer = true
                    } label: {
                        Label("Edit server", systemImage: "pencil")
                            .font(.subheadline.weight(.medium))
                    }
                    .foregroundStyle(NSTheme.accent)

                    Button("Switch server") { showServers = true }
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(NSTheme.accent)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background { AmbientField() }
            .sheet(isPresented: $showServers) {
                NavigationStack {
                    ServersListView()
                        .toolbar {
                            ToolbarItem(placement: .topBarTrailing) {
                                Button("Done") { showServers = false }
                            }
                        }
                }
                .preferredColorScheme(.dark)
            }
            .sheet(isPresented: $showEditServer) {
                if let server = model.server {
                    ServerEditorView(mode: .edit(server))
                        .preferredColorScheme(.dark)
                }
            }
        }
    }
}

struct MainTabView: View {
    @Environment(AppModel.self) private var model
    @State private var tab = 0
    @State private var showServers = false
    @State private var showRail = false
    @State private var showHelp = false
    /// Which of the console's two "who is this machine talking to" lists is showing. Held
    /// here rather than inside the screen so the rail can open either one directly, the way
    /// its two entries do in the console.
    @State private var trafficMode: TrafficMode = .hosts
    /// The Firewall tab's stack, as a path — Open Ports, Firewall & Block and Allowlist are
    /// rail entries in the console, so the rail has to be able to push straight to one.
    @State private var firewallPath: [FirewallRoute] = []

    /// Chrome follows the network: interactive blue when things are calm, the severity
    /// colour once a High or Critical threat is live.
    private var chromeTint: Color {
        model.liveSeverity >= .high ? model.liveSeverity.color : NSTheme.accent
    }

    var body: some View {
        // Five of the console's ten rail entries are tabs, because a tab bar holds five and
        // these are the five a phone lives in. The other five are not hidden: the rail —
        // reachable from every screen through the button in each navigation bar — carries the
        // whole menu, in the console's order, under the console's names.
        //
        // Tab labels are shortened where the bar would truncate them; every screen carries the
        // console's own name in its title.
        TabView(selection: $tab) {
            Tab("Dashboard", systemImage: "gauge.with.dots.needle.67percent", value: 0) {
                StatusView(
                    showServers: $showServers,
                    onOpenThreats: { tab = 1 },
                    onOpenSettings: { tab = 4 }
                )
            }

            Tab("Break-ins", systemImage: "exclamationmark.shield.fill", value: 1) {
                ThreatsView()
            }
            .badge(model.attentionThreat == nil ? 0 : model.attentionBacklog + 1)

            Tab("Connections", systemImage: "arrow.left.arrow.right", value: 2) {
                TrafficView(mode: $trafficMode)
            }

            Tab("Firewall", systemImage: "shield.lefthalf.filled", value: 3) {
                NavigationStack(path: $firewallPath) {
                    // Always the whole host firewall. Which endpoint it arrives on is the
                    // model's problem, and a server that has no such page says so on the
                    // screen rather than being silently swapped for a different one.
                    FirewallConfigView()
                        .navigationDestination(for: FirewallRoute.self) { route in
                            switch route {
                            case .block: FirewallBlockView()
                            case .ports: OpenPortsView()
                            case .allowlist: AllowlistView()
                            case .dnsBlocked: DnsBlockedView()
                            }
                        }
                }
            }

            Tab("Settings", systemImage: "gearshape", value: 4) {
                SettingsView()
            }
        }
        // Reading a dense table on a phone is worth more than a permanent tab bar.
        .tabBarMinimizeBehavior(.onScrollDown)
        .tint(chromeTint)
        .animation(.easeInOut(duration: 0.5), value: chromeTint)
        .environment(\.consoleRail, ConsoleRailAction { showRail = true })
        .sheet(isPresented: $showRail) {
            NavigationRailView(current: currentRailEntry, onSelect: open)
                .presentationDetents([.large])
                .presentationBackground(.clear)
                .preferredColorScheme(.dark)
        }
        .sheet(isPresented: $showHelp) {
            NavigationStack {
                HelpView()
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Done") { showHelp = false }
                        }
                    }
            }
            .preferredColorScheme(.dark)
        }
        .sheet(isPresented: $showServers) {
            NavigationStack {
                ServersListView()
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Done") { showServers = false }
                        }
                    }
            }
            .presentationDetents([.medium, .large])
            .preferredColorScheme(.dark)
        }
    }

    // MARK: - The rail

    /// Which rail entry the app is currently showing, so the rail can check it. Two tabs hold
    /// more than one entry — Connections holds both traffic lists, Firewall holds its whole
    /// group — so this reads the state inside the tab, not just the tab.
    private var currentRailEntry: RailEntry {
        switch tab {
        case 1: return .threats
        case 2: return trafficMode == .hosts ? .hosts : .connections
        case 3:
            switch firewallPath.last {
            case .block: return .firewall
            case .ports: return .ports
            case .allowlist: return .allowlist
            case .dnsBlocked: return .dnsBlocked
            case nil: return .firewallConfig
            }
        case 4: return .settings
        default: return .dashboard
        }
    }

    private func open(_ entry: RailEntry) {
        switch entry {
        case .dashboard:
            tab = 0
        case .threats:
            tab = 1
        case .hosts:
            trafficMode = .hosts
            tab = 2
        case .connections:
            trafficMode = .connections
            tab = 2
        case .firewallConfig:
            firewallPath = []
            tab = 3
        case .firewall:
            firewallPath = [.block]
            tab = 3
        case .ports:
            firewallPath = [.ports]
            tab = 3
        case .allowlist:
            firewallPath = [.allowlist]
            tab = 3
        case .dnsBlocked:
            // A top-level entry in the console's rail, and a push on the Firewall tab here.
            // Not a sheet like Help: this is a list you read, pull to re-read, and go back
            // from — and the tab it sits under is already the one that answers "what is
            // being blocked", which is the same question in a different layer.
            firewallPath = [.dnsBlocked]
            tab = 3
        case .settings:
            tab = 4
        case .help:
            // Help is a page under Settings in the console, and a sheet here: pushing it into
            // the Settings stack would leave the tab parked on Help the next time it is
            // opened, which is not where anyone left it.
            showHelp = true
        }
    }
}

/// The Firewall tab's group, as values rather than views, so the rail can push one directly.
enum FirewallRoute: Hashable {
    case block
    case ports
    case allowlist
    /// Web 0.7.15. Reached from the rail rather than from a row on Firewall Config: it is a
    /// top-level entry in the console's own menu, not part of its firewall group.
    case dnsBlocked
}

// MARK: - Opening the rail from anywhere

/// Every screen's navigation bar carries the rail button, and no screen should have to be
/// handed a closure through four initialisers to draw it. The action goes in the environment
/// once, at the tab view, and `.consoleRailToolbar()` picks it up wherever it is applied.
struct ConsoleRailAction {
    let open: () -> Void
    init(_ open: @escaping () -> Void = {}) { self.open = open }
}

private struct ConsoleRailKey: EnvironmentKey {
    static let defaultValue = ConsoleRailAction()
}

extension EnvironmentValues {
    var consoleRail: ConsoleRailAction {
        get { self[ConsoleRailKey.self] }
        set { self[ConsoleRailKey.self] = newValue }
    }
}

/// The rail button, in the leading slot of a navigation bar — where the console keeps its
/// rail, and where a phone's thumb expects a menu.
struct ConsoleRailButton: View {
    @Environment(\.consoleRail) private var rail

    var body: some View {
        Button(action: rail.open) {
            Image(systemName: "sidebar.leading")
                .font(.system(size: 15, weight: .semibold))
        }
        .accessibilityLabel("Console menu")
    }
}

extension View {
    /// Adds the rail button to this screen's navigation bar.
    func consoleRailToolbar() -> some View {
        toolbar {
            ToolbarItem(placement: .topBarLeading) {
                ConsoleRailButton()
            }
        }
    }
}
