import SwiftUI
import UIKit

/// A free-text server setting: what to call it, how to type it, and where it goes.
///
/// Web 0.4 added two of these (decoy ports, webhook URL) and 0.6 added five more —
/// approved resolvers, the Suricata EVE path and muted sids, the TLS paths, the DuckDNS
/// domain and token. They all edit identically: one row, one alert, one `set_setting`.
/// Carrying a `@State` flag and a draft string per field is how that turns into a hundred
/// lines of near-identical view code, so they share one editor instead.
struct TextSettingEdit: Identifiable {
    let id: String
    let title: String
    let placeholder: String
    /// Why the field exists and what an empty value means — the server rejects several of
    /// these with a specific message, and saying so first is cheaper than a failed round trip.
    let message: String
    var keyboard: UIKeyboardType = .default
    let apply: (String) async -> Void
}

extension View {
    /// Presents whichever `TextSettingEdit` is pending, editing `draft`.
    ///
    /// Set `draft` to the server's current value at the same moment you set the edit —
    /// these fields are absolute paths and port lists, not things anyone retypes.
    func nsTextSettingAlert(
        _ edit: Binding<TextSettingEdit?>,
        draft: Binding<String>
    ) -> some View {
        alert(
            edit.wrappedValue?.title ?? "",
            isPresented: Binding(
                get: { edit.wrappedValue != nil },
                set: { if !$0 { edit.wrappedValue = nil } }
            ),
            presenting: edit.wrappedValue
        ) { pending in
            TextField(pending.placeholder, text: draft)
                .keyboardType(pending.keyboard)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Save") {
                // Read the draft now: dismissing the alert is free to reset it.
                let value = draft.wrappedValue
                Task { await pending.apply(value) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text(pending.message)
        }
    }
}
