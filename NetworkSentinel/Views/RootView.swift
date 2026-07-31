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
                            Task { await model.block(ip: ip) }
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
            }

            Spacer(minLength: 4)

            VStack(spacing: 6) {
                // A 0.4+ host-local Critical has no peer to block; only the dismiss
                // control is meaningful there.
                if payload.threat.isBlockable {
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

    /// Chrome follows the network: interactive blue when things are calm, the severity
    /// colour once a High or Critical threat is live.
    private var chromeTint: Color {
        model.liveSeverity >= .high ? model.liveSeverity.color : NSTheme.accent
    }

    var body: some View {
        TabView(selection: $tab) {
            Tab("Dashboard", systemImage: "gauge.with.dots.needle.67percent", value: 0) {
                DashboardView(showServers: $showServers)
            }

            Tab("Threats", systemImage: "exclamationmark.shield.fill", value: 1) {
                ThreatsView()
            }
            .badge(model.attentionThreat == nil ? 0 : model.attentionBacklog + 1)

            Tab("Hosts", systemImage: "network", value: 2) {
                HostsView()
            }

            Tab("Connections", systemImage: "arrow.left.arrow.right", value: 3) {
                ConnectionsView()
            }

            Tab("More", systemImage: "ellipsis.circle", value: 4) {
                MoreView()
            }
        }
        // Reading a dense table on a phone is worth more than a permanent tab bar.
        .tabBarMinimizeBehavior(.onScrollDown)
        .tint(chromeTint)
        .animation(.easeInOut(duration: 0.5), value: chromeTint)
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
}
