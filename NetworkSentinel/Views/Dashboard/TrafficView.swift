import SwiftUI

/// The console's **Live Connections** and **Remote Computers** under one tab.
///
/// They are two rail entries there and one tab here, answering one question — who is this
/// machine talking to — from two sides: a host is the actor, a connection is what it is doing
/// right now. Two tab slots for that distinction is what would leave the firewall without one.
/// The picker in the navigation bar is the rail entry; each side carries the console's own
/// name as its title.
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
    /// The console calls these *Remote Computers* and *Live Connections*. Both names carry in
    /// the screen titles; the segmented control gets the half of each that fits in 210 points.
    case hosts = "Computers"
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
