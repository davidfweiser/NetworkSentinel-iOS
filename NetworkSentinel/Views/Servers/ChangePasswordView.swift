import SwiftUI

/// Change the server's master password (Network Sentinel web ≥ 0.3.3).
/// The server keeps this session alive and signs every other client out.
struct ChangePasswordView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var current = ""
    @State private var newPassword = ""
    @State private var confirm = ""
    @State private var isWorking = false
    @State private var error: String?

    private enum Field { case current, new, confirm }
    @FocusState private var focusedField: Field?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    header

                    VStack(spacing: 14) {
                        secureField("Current master password", text: $current, field: .current)
                        secureField("New master password", text: $newPassword, field: .new)
                        secureField("Confirm new password", text: $confirm, field: .confirm)

                        if let error {
                            Text(error)
                                .font(.caption)
                                .foregroundStyle(NSTheme.danger)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }

                        Button {
                            Task { await submit() }
                        } label: {
                            HStack {
                                if isWorking { ProgressView().tint(.white) }
                                Text(isWorking ? "Updating…" : "Update password")
                                    .font(.headline)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(NSTheme.accent)
                        .disabled(isWorking || !canSubmit)
                    }
                    .nsCard()
                    .padding(.horizontal)

                    Text("Other signed-in browsers and devices are signed out. This device stays signed in, and a remembered password is updated in the Keychain.")
                        .font(.caption)
                        .foregroundStyle(NSTheme.muted)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 28)
                }
                .padding(.vertical, 24)
            }
            .background(NSTheme.gradient.ignoresSafeArea())
            .navigationTitle("Master password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onAppear { focusedField = .current }
        }
    }

    private var header: some View {
        VStack(spacing: 8) {
            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 40))
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
        }
        .padding(.top, 8)
    }

    private func secureField(_ title: String, text: Binding<String>, field: Field) -> some View {
        SecureField(title, text: text)
            .textContentType(field == .current ? .password : .newPassword)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .focused($focusedField, equals: field)
            .submitLabel(field == .confirm ? .go : .next)
            .onSubmit {
                switch field {
                case .current: focusedField = .new
                case .new: focusedField = .confirm
                case .confirm: Task { await submit() }
                }
            }
            .padding(12)
            .background(NSTheme.cardElevated, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .foregroundStyle(NSTheme.text)
    }

    /// Mirrors the server's own checks so obvious mistakes never cost a round trip.
    private var canSubmit: Bool {
        !current.isEmpty
            && newPassword.count >= 8
            && newPassword == confirm
            && newPassword != current
    }

    private func submit() async {
        error = nil
        guard canSubmit else {
            if newPassword.count < 8 {
                error = "New password must be at least 8 characters."
            } else if newPassword != confirm {
                error = "New passwords do not match."
            } else if newPassword == current {
                error = "New password must be different from the current password."
            } else {
                error = "Enter your current master password."
            }
            return
        }

        isWorking = true
        defer { isWorking = false }
        do {
            try await model.changeMasterPassword(
                current: current,
                new: newPassword,
                confirm: confirm
            )
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
