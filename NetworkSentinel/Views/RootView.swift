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
        .background(NSTheme.bg.ignoresSafeArea())
        .task {
            model.onAppear()
        }
        .onDisappear {
            model.onDisappear()
        }
        .animation(.easeInOut(duration: 0.25), value: model.store.servers.count)
        .animation(.easeInOut(duration: 0.2), value: model.authPhase)
        .animation(.easeInOut(duration: 0.2), value: model.isAuthenticated)
        .alert(
            "Critical threat",
            isPresented: Binding(
                get: { model.pendingCriticalAlert != nil },
                set: { if !$0 { model.dismissCriticalAlert() } }
            )
        ) {
            if let alert = model.pendingCriticalAlert {
                Button("Block \(alert.threat.sourceIp)", role: .destructive) {
                    let ip = alert.threat.sourceIp
                    model.dismissCriticalAlert()
                    Task { await model.block(ip: ip) }
                }
                Button("Dismiss", role: .cancel) {
                    model.dismissCriticalAlert()
                }
            } else {
                Button("OK", role: .cancel) {
                    model.dismissCriticalAlert()
                }
            }
        } message: {
            if let alert = model.pendingCriticalAlert {
                let extra = alert.extraCount > 0 ? "\n(+\(alert.extraCount) more)" : ""
                Text("\(alert.serverName)\n\(alert.threat.title)\n\(alert.threat.sourceIp)\(extra)")
            }
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
        .background(NSTheme.gradient.ignoresSafeArea())
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
            .background(NSTheme.gradient.ignoresSafeArea())
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

    var body: some View {
        TabView(selection: $tab) {
            DashboardView(showServers: $showServers)
                .tabItem { Label("Dashboard", systemImage: "gauge.with.dots.needle.67percent") }
                .tag(0)

            ThreatsView()
                .tabItem { Label("Threats", systemImage: "exclamationmark.shield.fill") }
                .tag(1)

            HostsView()
                .tabItem { Label("Hosts", systemImage: "network") }
                .tag(2)

            ConnectionsView()
                .tabItem { Label("Connections", systemImage: "arrow.left.arrow.right") }
                .tag(3)

            MoreView()
                .tabItem { Label("More", systemImage: "ellipsis.circle") }
                .tag(4)
        }
        .tint(NSTheme.accent)
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
        .overlay(alignment: .top) {
            if let banner = model.statusBanner {
                Text(banner)
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(NSTheme.text)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(.ultraThinMaterial, in: Capsule())
                    .padding(.top, 8)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .onAppear {
                        Task {
                            try? await Task.sleep(nanoseconds: 2_500_000_000)
                            if model.statusBanner == banner {
                                model.statusBanner = nil
                            }
                        }
                    }
            }
        }
        .animation(.spring(response: 0.35), value: model.statusBanner)
    }
}
