import SwiftUI

struct AuthView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var confirm = ""
    @State private var remember = true
    @State private var isWorking = false
    @State private var error: String?
    @State private var showServers = false
    @State private var showEditServer = false
    @FocusState private var focusedField: Field?

    private enum Field {
        case password, confirm
    }

    private var isSetup: Bool {
        model.needsSetup || model.authPhase == .setup
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    serverHeader

                    VStack(alignment: .leading, spacing: 16) {
                        Text(isSetup ? "Create master password" : "Master password required")
                            .font(.title2.bold())
                            .foregroundStyle(NSTheme.text)

                        Text(isSetup
                             ? "This server has no master password yet. Create one (min 8 characters) to secure the API."
                             : "Your Network Sentinel server requires the master password before any data can be loaded.")
                            .font(.subheadline)
                            .foregroundStyle(NSTheme.muted)

                        SecureField(isSetup ? "New password" : "Master password", text: $password)
                            .textContentType(isSetup ? .newPassword : .password)
                            .submitLabel(isSetup ? .next : .go)
                            .focused($focusedField, equals: .password)
                            .padding(14)
                            .background(NSTheme.cardElevated, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                            .onSubmit {
                                if isSetup {
                                    focusedField = .confirm
                                } else {
                                    Task { await submit() }
                                }
                            }

                        if isSetup {
                            SecureField("Confirm password", text: $confirm)
                                .textContentType(.newPassword)
                                .submitLabel(.go)
                                .focused($focusedField, equals: .confirm)
                                .padding(14)
                                .background(NSTheme.cardElevated, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                                .onSubmit {
                                    Task { await submit() }
                                }
                        }

                        Toggle(isOn: $remember) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Remember on this device")
                                    .font(.subheadline)
                                Text("Stored in Keychain. You can sign out anytime.")
                                    .font(.caption2)
                                    .foregroundStyle(NSTheme.muted)
                            }
                        }
                        .tint(NSTheme.accent)

                        if let error {
                            Text(error)
                                .font(.footnote)
                                .foregroundStyle(NSTheme.danger)
                        }

                        Button {
                            Task { await submit() }
                        } label: {
                            Group {
                                if isWorking {
                                    ProgressView().tint(.white)
                                } else {
                                    Text(isSetup ? "Create & sign in" : "Sign in")
                                        .font(.headline)
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(NSTheme.accent)
                        .disabled(isWorking || !canSubmit)

                        HStack(spacing: 16) {
                            Button {
                                showEditServer = true
                            } label: {
                                Label("Edit server", systemImage: "pencil")
                                    .font(.subheadline.weight(.medium))
                            }
                            .foregroundStyle(NSTheme.accent)

                            Spacer()

                            Button("Switch server") {
                                showServers = true
                            }
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(NSTheme.accent)
                        }
                    }
                    .nsCard()
                    .padding(.horizontal)

                    if let err = model.lastError, !isSetup, error == nil {
                        Text(err)
                            .font(.caption)
                            .foregroundStyle(NSTheme.muted)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                }
                .padding(.vertical, 24)
            }
            .background(NSTheme.gradient.ignoresSafeArea())
            .navigationTitle("Network Sentinel")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                focusedField = .password
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

    private var canSubmit: Bool {
        if password.count < 8 { return false }
        if isSetup { return password == confirm }
        return true
    }

    private var serverHeader: some View {
        VStack(spacing: 8) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 44))
                .foregroundStyle(NSTheme.accent)
                .symbolRenderingMode(.hierarchical)
            if let s = model.server {
                Text(s.name)
                    .font(.headline)
                    .foregroundStyle(NSTheme.text)
                Text(s.displayHost)
                    .font(.caption.monospaced())
                    .foregroundStyle(NSTheme.muted)
            }
            Text("Protected server")
                .font(.caption.weight(.semibold))
                .foregroundStyle(NSTheme.warning)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(NSTheme.warning.opacity(0.12), in: Capsule())
        }
        .padding(.top, 12)
    }

    private func submit() async {
        error = nil
        guard canSubmit else {
            error = isSetup && password != confirm
                ? "Passwords do not match."
                : "Password must be at least 8 characters."
            return
        }
        isWorking = true
        defer { isWorking = false }
        do {
            if isSetup {
                try await model.performSetup(password: password, confirm: confirm)
            } else {
                try await model.performLogin(password: password, remember: remember)
            }
            password = ""
            confirm = ""
        } catch {
            self.error = error.localizedDescription
        }
    }
}
