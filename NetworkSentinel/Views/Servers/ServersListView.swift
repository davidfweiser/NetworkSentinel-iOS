import SwiftUI

struct ServersListView: View {
    @Environment(AppModel.self) private var model
    @State private var showAdd = false
    @State private var editProfile: ServerProfile?

    var body: some View {
        List {
            Section {
                ForEach(model.store.servers) { server in
                    HStack(spacing: 12) {
                        Button {
                            model.selectServer(server.id)
                        } label: {
                            HStack(spacing: 14) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                                        .fill(NSTheme.accentSoft)
                                        .frame(width: 40, height: 40)
                                    Image(systemName: "server.rack")
                                        .foregroundStyle(NSTheme.accent)
                                }

                                VStack(alignment: .leading, spacing: 3) {
                                    Text(server.name)
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(NSTheme.text)
                                    Text(server.displayHost)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(NSTheme.muted)
                                }

                                Spacer(minLength: 0)

                                if model.store.selectedServerId == server.id {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(NSTheme.success)
                                }
                            }
                        }
                        .buttonStyle(.plain)

                        Button {
                            editProfile = server
                        } label: {
                            Image(systemName: "pencil.circle.fill")
                                .font(.title2)
                                .foregroundStyle(NSTheme.accent)
                                .symbolRenderingMode(.hierarchical)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Edit \(server.name)")
                    }
                    .listRowBackground(NSTheme.row)
                    .contextMenu {
                        Button {
                            editProfile = server
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        Button {
                            model.selectServer(server.id)
                        } label: {
                            Label("Select", systemImage: "checkmark.circle")
                        }
                        Divider()
                        Button(role: .destructive) {
                            delete(server)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            delete(server)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                        Button {
                            editProfile = server
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        .tint(NSTheme.accent)
                    }
                }
            } header: {
                Text("Servers")
            } footer: {
                Text("Tap a server to select it. Use the pencil to edit name or URL. Swipe for more actions.")
            }

            Section {
                Button {
                    showAdd = true
                } label: {
                    Label("Add server", systemImage: "plus.circle.fill")
                }
                .listRowBackground(NSTheme.row)
            }
        }
        .scrollContentBackground(.hidden)
        .background(NSTheme.bg)
        .navigationTitle("Servers")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showAdd = true
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add server")
            }
        }
        .sheet(isPresented: $showAdd) {
            ServerEditorView(mode: .add)
                .preferredColorScheme(.dark)
        }
        .sheet(item: $editProfile) { profile in
            ServerEditorView(mode: .edit(profile))
                .preferredColorScheme(.dark)
        }
    }

    private func delete(_ server: ServerProfile) {
        model.store.delete(server.id)
        if model.store.servers.isEmpty {
            model.state = nil
            model.isAuthenticated = false
            model.authPhase = .checking
        } else {
            model.evaluateAuthAfterServerChange()
            model.restartPolling()
        }
    }
}

struct ServerEditorView: View {
    enum Mode {
        case add
        case edit(ServerProfile)
    }

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let mode: Mode
    @State private var name = ""
    @State private var url = ""
    @State private var error: String?
    @FocusState private var focusURL: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Display name", text: $name)
                        .textInputAutocapitalization(.words)

                    TextField("Server URL", text: $url)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .focused($focusURL)
                        .textContentType(.URL)
                } header: {
                    Text("Connection")
                } footer: {
                    Text("Include the port from the Network Sentinel web console.\nExample: http://192.168.1.10:18765")
                }

                if case .edit = mode {
                    Section {
                        Label("Changing the URL signs you out of this server so you can re-enter the master password.", systemImage: "info.circle")
                            .font(.footnote)
                            .foregroundStyle(NSTheme.muted)
                    }
                    .listRowBackground(Color.clear)
                }

                if let error {
                    Section {
                        Text(error).foregroundStyle(NSTheme.danger)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(NSTheme.bg)
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .fontWeight(.semibold)
                }
            }
            .onAppear {
                switch mode {
                case .add:
                    focusURL = true
                case .edit(let p):
                    name = p.name
                    url = p.baseURL
                    focusURL = true
                }
            }
        }
    }

    private var title: String {
        switch mode {
        case .add: return "Add server"
        case .edit: return "Edit server"
        }
    }

    private func save() {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !u.isEmpty else {
            error = "URL is required."
            return
        }

        let normalized = ServerProfile.normalizeURL(u)
        // Basic sanity check
        guard let parsed = URL(string: normalized), parsed.host != nil else {
            error = "Enter a valid URL, e.g. http://192.168.1.10:18765"
            return
        }

        switch mode {
        case .add:
            model.store.add(name: n.isEmpty ? "Server" : n, baseURL: normalized)
            model.evaluateAuthAfterServerChange()
            model.restartPolling()
        case .edit(var p):
            let urlChanged = ServerProfile.normalizeURL(p.baseURL) != normalized
            p.name = n.isEmpty ? p.name : n
            p.baseURL = normalized
            model.store.update(p)
            if urlChanged {
                // URL changed — drop session so master password is required again.
                model.store.setSessionToken(nil, for: p.id)
                model.store.setRememberedPassword(nil, for: p.id)
            }
            if model.store.selectedServerId == p.id {
                model.evaluateAuthAfterServerChange()
                model.restartPolling()
            }
        }
        dismiss()
    }
}
