import SwiftUI

/// Hosts and connections under one tab.
///
/// They were two tabs answering one question — who is this machine talking to — and the
/// answer needs both readings: a host is the actor, a connection is what it is doing right
/// now. Two tabs meant the tab bar spent 40% of itself on that distinction, which is what
/// left no room for Status, Threats and More to be reachable in one reach.
///
/// The switch is a picker in the navigation bar rather than a segmented header, so it costs
/// no vertical space in a dense table and the search field stays where each list had it.
struct TrafficView: View {
    @State private var mode: TrafficMode = .hosts

    var body: some View {
        switch mode {
        case .hosts:
            HostsView(mode: $mode)
        case .connections:
            ConnectionsView(mode: $mode)
        }
    }
}

enum TrafficMode: String, CaseIterable, Identifiable {
    case hosts = "Hosts"
    case connections = "Connections"

    var id: String { rawValue }
}

/// Shown by whichever list is on screen, in its own navigation bar.
struct TrafficModePicker: View {
    @Binding var mode: TrafficMode

    var body: some View {
        Picker("Traffic view", selection: $mode) {
            ForEach(TrafficMode.allCases) { option in
                Text(option.rawValue).tag(option)
            }
        }
        .pickerStyle(.segmented)
        .frame(width: 210)
    }
}
