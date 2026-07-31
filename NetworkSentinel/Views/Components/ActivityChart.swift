import Charts
import SwiftUI

/// Connection volume over the sample window, with a marker on every sample that carried a
/// threat — the same reading as the web console's SVG chart and the desktop GUI's sparkline,
/// but scrubbable: drag to pin any sample and read its exact values.
struct ActivityChart: View {
    let points: [ActivityPoint]

    @State private var selectedIndex: Int?

    private struct Sample: Identifiable {
        let id: Int
        let connections: Int
        let threats: Int
        let hosts: Int
        let time: String
    }

    private var samples: [Sample] {
        points.enumerated().map { i, p in
            Sample(
                id: i,
                connections: p.connections ?? 0,
                threats: p.threats ?? 0,
                hosts: p.hosts ?? 0,
                time: p.time
            )
        }
    }

    /// Zero-baseline, like the web chart — a flat line near the top would otherwise imply
    /// a busier network than there is.
    private var upperBound: Int {
        max(samples.map(\.connections).max() ?? 1, 1)
    }

    private var selected: Sample? {
        guard let selectedIndex else { return nil }
        return samples.first { $0.id == selectedIndex }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header

            Chart(samples) { s in
                AreaMark(
                    x: .value("Sample", s.id),
                    y: .value("Connections", s.connections)
                )
                .interpolationMethod(.catmullRom)
                .foregroundStyle(
                    LinearGradient(
                        colors: [NSTheme.accent.opacity(0.34), NSTheme.accent.opacity(0.02)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )

                if s.threats > 0 {
                    RuleMark(x: .value("Sample", s.id))
                        .foregroundStyle(NSTheme.threatMarker.opacity(0.32))
                        .lineStyle(StrokeStyle(lineWidth: 3))
                }

                LineMark(
                    x: .value("Sample", s.id),
                    y: .value("Connections", s.connections)
                )
                .interpolationMethod(.catmullRom)
                .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                .foregroundStyle(
                    LinearGradient(
                        colors: [NSTheme.accent, NSTheme.cyan],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )

                if let selected, selected.id == s.id {
                    PointMark(
                        x: .value("Sample", s.id),
                        y: .value("Connections", s.connections)
                    )
                    .symbolSize(90)
                    .foregroundStyle(NSTheme.cyan)
                } else if selectedIndex == nil, s.id == samples.count - 1 {
                    // Idle state pins the newest sample so "now" is always marked.
                    PointMark(
                        x: .value("Sample", s.id),
                        y: .value("Connections", s.connections)
                    )
                    .symbolSize(60)
                    .foregroundStyle(NSTheme.cyan)
                }
            }
            .chartYScale(domain: 0...upperBound)
            .chartXAxis(.hidden)
            .chartYAxis {
                AxisMarks(position: .trailing, values: [0, upperBound]) {
                    AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                    AxisValueLabel()
                        .font(.system(size: 9))
                        .foregroundStyle(NSTheme.muted)
                }
            }
            .chartXSelection(value: $selectedIndex)
            .frame(height: 108)
            .animation(.easeInOut(duration: 0.4), value: samples.count)

            footer
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Activity").nsEyebrow()
            Spacer()
            if let selected {
                // Scrubbing: the readout becomes the pinned sample.
                HStack(spacing: 10) {
                    readout("\(selected.connections)", label: "conn", tint: NSTheme.cyan)
                    readout("\(selected.hosts)", label: "hosts", tint: NSTheme.signal)
                    if selected.threats > 0 {
                        readout("\(selected.threats)", label: "threats", tint: NSTheme.threatMarker)
                    }
                    Text(selected.time)
                        .font(.system(size: 11).monospaced())
                        .foregroundStyle(NSTheme.muted)
                }
                .transition(.opacity)
            } else {
                HStack(spacing: 10) {
                    readout("\(samples.last?.connections ?? 0)", label: "now", tint: NSTheme.cyan)
                    readout("\(upperBound)", label: "peak", tint: NSTheme.muted)
                }
            }
        }
        .animation(.snappy(duration: 0.2), value: selectedIndex)
    }

    private func readout(_ value: String, label: String, tint: Color) -> some View {
        HStack(spacing: 3) {
            Text(value)
                .font(.readout(15, weight: .bold))
                .foregroundStyle(tint)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(NSTheme.muted)
        }
    }

    private var footer: some View {
        let threatTotal = samples.reduce(0) { $0 + $1.threats }
        return HStack(spacing: 12) {
            HStack(spacing: 5) {
                RoundedRectangle(cornerRadius: 1.5)
                    .fill(NSTheme.threatMarker.opacity(0.5))
                    .frame(width: 3, height: 10)
                Text(threatTotal > 0 ? "\(threatTotal) in window" : "none in window")
                    .font(.system(size: 10))
                    .foregroundStyle(NSTheme.muted)
            }
            Spacer()
            Text(samples.first?.time ?? "")
                .font(.system(size: 10).monospaced())
                .foregroundStyle(NSTheme.muted)
            Text("→")
                .font(.system(size: 10))
                .foregroundStyle(NSTheme.muted.opacity(0.6))
            Text(samples.last?.time ?? "")
                .font(.system(size: 10).monospaced())
                .foregroundStyle(NSTheme.muted)
        }
    }
}
