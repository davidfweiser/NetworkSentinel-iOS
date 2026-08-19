import SwiftUI

struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @State private var name = ""
    @State private var url = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 28) {
                    VStack(spacing: 12) {
                        ZStack {
                            Circle()
                                .fill(NSTheme.accentSoft)
                                .frame(width: 88, height: 88)
                            Image(systemName: "shield.lefthalf.filled")
                                .font(.system(size: 40, weight: .semibold))
                                .foregroundStyle(NSTheme.accent)
                                .symbolRenderingMode(.hierarchical)
                        }
                        .padding(.top, 32)

                        Text("Network Sentinel")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .foregroundStyle(NSTheme.text)

                        Text("Monitor Linux & Windows Network Sentinel web servers from your iPhone. Add a server URL to get started.")
                            .font(.subheadline)
                            .foregroundStyle(NSTheme.muted)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 8)
                    }

                    VStack(alignment: .leading, spacing: 16) {
                        field(title: "Display name", placeholder: "Home lab", text: $name)
                        field(title: "Server URL", placeholder: "http://192.168.1.10:18765", text: $url)
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()

                        if let error {
                            Text(error)
                                .font(.footnote)
                                .foregroundStyle(NSTheme.danger)
                        }

                        Button {
                            add()
                        } label: {
                            Text("Add server")
                                .font(.headline)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(NSTheme.accent)
                        .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                        Text("Run Network Sentinel with `-w` or `--web` on the host, then enter the URL shown in the console (e.g. http://192.168.1.10:18765).")
                            .font(.caption)
                            .foregroundStyle(NSTheme.muted)
                    }
                    .nsCard()
                    .padding(.horizontal)

                    featureList
                        .padding(.horizontal)
                        .padding(.bottom, 32)
                }
            }
            .background { AmbientField() }
            .navigationBarHidden(true)
        }
    }

    private var featureList: some View {
        VStack(alignment: .leading, spacing: 12) {
            feature(icon: "server.rack", title: "Multi-server", text: "Switch between home, office, and cloud hosts.")
            feature(icon: "exclamationmark.triangle.fill", title: "Critical alerts", text: "Threats, high-severity events, and blocked peers.")
            feature(icon: "hand.raised.fill", title: "Take action", text: "Block/unblock IPs, toggle auto-block, manage allowlist.")
        }
    }

    private func feature(icon: String, title: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .foregroundStyle(NSTheme.accent)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(NSTheme.text)
                Text(text).font(.caption).foregroundStyle(NSTheme.muted)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .nsCard(padding: 14)
    }

    private func field(title: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(NSTheme.muted)
            TextField(placeholder, text: text)
                .padding(12)
                .background(NSTheme.cardElevated, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .foregroundStyle(NSTheme.text)
        }
    }

    private func add() {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            error = "Enter a server URL."
            return
        }
        let normalized = ServerProfile.normalizeURL(trimmed)
        guard let parsed = URL(string: normalized), parsed.host != nil else {
            error = "Enter a valid URL, e.g. http://192.168.1.10:18765"
            return
        }
        error = nil
        model.store.add(name: name.isEmpty ? "Server" : name, baseURL: normalized)
        model.evaluateAuthAfterServerChange()
        model.restartPolling()
    }
}
